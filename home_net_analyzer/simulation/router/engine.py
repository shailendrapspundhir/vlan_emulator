"""Router engine for Layer 3 packet forwarding."""

from __future__ import annotations

from typing import Literal

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.simulation.router.models import (
    ARPTable,
    RouteEntry,
    RouteType,
    RouterInterface,
    RoutingTable,
    SVI,
)


class RouterStats:
    """Statistics for router operations."""

    def __init__(self):
        self.packets_received: int = 0
        self.packets_forwarded: int = 0
        self.packets_dropped: int = 0
        self.packets_to_self: int = 0  # Packets destined for router itself
        self.routing_failures: int = 0
        self.arp_failures: int = 0
        self.interface_errors: int = 0

    def to_dict(self) -> dict:
        """Convert stats to dictionary."""
        return {
            "packets_received": self.packets_received,
            "packets_forwarded": self.packets_forwarded,
            "packets_dropped": self.packets_dropped,
            "packets_to_self": self.packets_to_self,
            "routing_failures": self.routing_failures,
            "arp_failures": self.arp_failures,
            "interface_errors": self.interface_errors,
        }


class ForwardingDecision:
    """A forwarding decision for a packet.

    Represents the action to take for forwarding a packet.
    """

    def __init__(
        self,
        action: Literal["forward", "drop", "deliver_local"],
        next_hop_ip: str | None = None,
        next_hop_mac: str | None = None,
        outgoing_interface: str | None = None,
        reason: str = ""
    ):
        self.action = action
        self.next_hop_ip = next_hop_ip
        self.next_hop_mac = next_hop_mac
        self.outgoing_interface = outgoing_interface
        self.reason = reason

    def __str__(self) -> str:
        if self.action == "forward":
            return f"Forward via {self.outgoing_interface} to {self.next_hop_ip} ({self.next_hop_mac})"
        elif self.action == "deliver_local":
            return "Deliver to local router"
        else:
            return f"Drop: {self.reason}"


class RouterEngine:
    """Layer 3 router engine with SVI support.

    This engine processes packets through a virtual router, handling:
    - Routing table lookups (longest prefix match)
    - ARP resolution
    - SVI (VLAN interface) routing
    - Inter-VLAN routing

    Example:
        router = RouterEngine(name="core-router")

        # Add SVIs for VLAN routing
        router.add_svi(SVI(vlan_id=10, ip_address="192.168.10.1", ...))
        router.add_svi(SVI(vlan_id=20, ip_address="192.168.20.1", ...))

        # Add static route
        router.add_route(RouteEntry(destination="0.0.0.0/0", next_hop="10.0.0.1", ...))

        decision = router.process_packet(packet, ingress_interface="eth0")
    """

    def __init__(
        self,
        name: str,
        *,
        log_level: Literal["debug", "info", "warning", "error"] = "info"
    ):
        """Initialize router engine.

        Args:
            name: Router name
            log_level: Logging verbosity
        """
        self.name = name
        self.log_level = log_level
        self.routing_table = RoutingTable()
        self.arp_table = ARPTable()
        self.svis: dict[int, SVI] = {}  # vlan_id -> SVI
        self.physical_interfaces: dict[str, RouterInterface] = {}  # name -> interface
        self.stats = RouterStats()
        self._logs: list[dict] = []

    def add_svi(self, svi: SVI) -> None:
        """Add an SVI (Switched Virtual Interface).

        Automatically adds a connected route for the SVI's network.

        Args:
            svi: SVI configuration
        """
        self.svis[svi.vlan_id] = svi

        # Add connected route
        route = svi.to_route_entry()
        self.routing_table.add_route(route)

        self._log("info", f"Added SVI Vlan{svi.vlan_id}: {svi.ip_address}/{svi.get_network()}")

    def add_physical_interface(self, interface: RouterInterface) -> None:
        """Add a physical interface.

        Automatically adds a connected route if interface has IP.

        Args:
            interface: Physical interface configuration
        """
        self.physical_interfaces[interface.name] = interface

        # Add connected route if interface has IP
        if interface.ip_address and interface.subnet_mask:
            network = interface.get_network()
            if network:
                route = RouteEntry(
                    destination=network,
                    next_hop=None,
                    interface=interface.name,
                    route_type=RouteType.CONNECTED,
                    metric=0
                )
                self.routing_table.add_route(route)
                self._log("info", f"Added interface {interface.name}: {interface.ip_address}/{network}")

    def add_route(self, route: RouteEntry) -> None:
        """Add a route to the routing table.

        Args:
            route: Route entry to add
        """
        self.routing_table.add_route(route)
        self._log("info", f"Added route: {route.destination} via {route.next_hop or 'connected'}")

    def remove_route(self, destination: str, interface: str | None = None) -> bool:
        """Remove a route from the routing table.

        Args:
            destination: Destination network
            interface: Optional interface filter

        Returns:
            True if route was removed
        """
        return self.routing_table.remove_route(destination, interface)

    def process_packet(
        self,
        packet: CapturedPacket,
        ingress_interface: str
    ) -> ForwardingDecision:
        """Process a packet through the router.

        Main entry point for router forwarding. Steps:
        1. Check if packet is for router itself
        2. Validate ingress interface
        3. Look up destination in routing table
        4. Resolve next-hop MAC address via ARP
        5. Return forwarding decision

        Args:
            packet: The packet to process
            ingress_interface: Interface packet arrived on

        Returns:
            ForwardingDecision with action to take
        """
        self.stats.packets_received += 1
        self._log("debug", f"Processing packet on {ingress_interface}: {packet.src_ip} -> {packet.dst_ip}")

        # Check if packet is for router itself
        if self._is_for_router(packet.dst_ip):
            self.stats.packets_to_self += 1
            self._log("info", f"Packet for router itself: {packet.dst_ip}")
            return ForwardingDecision(
                action="deliver_local",
                reason="Destination is router interface"
            )

        # Validate ingress interface exists
        if ingress_interface not in self.physical_interfaces:
            # Check if it's an SVI name (Vlan10)
            if not ingress_interface.startswith("Vlan"):
                self.stats.interface_errors += 1
                self._log("warning", f"Unknown ingress interface: {ingress_interface}")

        # Route lookup
        route = self.routing_table.lookup(packet.dst_ip)
        if not route:
            self.stats.routing_failures += 1
            self._log("warning", f"No route to {packet.dst_ip}")
            return ForwardingDecision(
                action="drop",
                reason=f"No route to destination {packet.dst_ip}"
            )

        self._log("debug", f"Route found: {route.destination} via {route.interface}")

        # Determine next hop
        if route.next_hop:
            next_hop_ip = route.next_hop
        else:
            # Connected route - destination is directly reachable
            next_hop_ip = packet.dst_ip

        # ARP resolution
        next_hop_mac = self.arp_table.resolve(next_hop_ip, route.interface)
        if not next_hop_mac:
            # In real router, would send ARP request and queue packet
            # For simulation, we simulate ARP learning
            self.stats.arp_failures += 1
            self._log("warning", f"ARP resolution failed for {next_hop_ip}")
            return ForwardingDecision(
                action="drop",
                reason=f"ARP resolution failed for {next_hop_ip}"
            )

        self.stats.packets_forwarded += 1
        return ForwardingDecision(
            action="forward",
            next_hop_ip=next_hop_ip,
            next_hop_mac=next_hop_mac,
            outgoing_interface=route.interface,
            reason=f"Routed via {route.destination}"
        )

    def _is_for_router(self, ip: str) -> bool:
        """Check if IP address belongs to router itself."""
        # Check SVIs
        for svi in self.svis.values():
            if svi.ip_address == ip:
                return True

        # Check physical interfaces
        for iface in self.physical_interfaces.values():
            if iface.ip_address == ip:
                return True

        return False

    def learn_arp(
        self,
        ip: str,
        mac: str,
        interface: str,
        entry_type: Literal["dynamic", "static"] = "dynamic"
    ) -> None:
        """Learn an ARP entry.

        Args:
            ip: IP address
            mac: MAC address
            interface: Interface name
            entry_type: Type of ARP entry
        """
        self.arp_table.learn(ip, mac, interface, entry_type)
        self._log("debug", f"Learned ARP: {ip} -> {mac} on {interface}")

    def get_svi(self, vlan_id: int) -> SVI | None:
        """Get SVI by VLAN ID."""
        return self.svis.get(vlan_id)

    def get_svi_for_network(self, ip: str) -> SVI | None:
        """Find SVI that contains the given IP in its network."""
        for svi in self.svis.values():
            if svi.is_in_network(ip):
                return svi
        return None

    def get_interface(self, name: str) -> RouterInterface | SVI | None:
        """Get interface by name (physical or SVI)."""
        if name in self.physical_interfaces:
            return self.physical_interfaces[name]

        # Check if it's an SVI (Vlan10)
        if name.startswith("Vlan"):
            try:
                vlan_id = int(name[4:])
                return self.svis.get(vlan_id)
            except ValueError:
                pass

        return None

    def get_routes(self) -> list[RouteEntry]:
        """Get all routes in routing table."""
        return self.routing_table.get_routes()

    def get_arp_entries(self) -> list[dict]:
        """Get ARP entries formatted for display."""
        return [
            {
                "ip": entry.ip_address,
                "mac": entry.mac_address,
                "interface": entry.interface,
                "type": entry.entry_type,
                "age": int(
                    (datetime.now(timezone.utc) - entry.last_seen).total_seconds()
                ),
            }
            for entry in self.arp_table.get_entries()
        ]

    def clear_arp_table(self) -> int:
        """Clear the ARP table."""
        return self.arp_table.clear()

    def clear_routing_table(self) -> int:
        """Clear all non-connected routes."""
        connected = self.routing_table.get_connected_routes()
        count = self.routing_table.clear()
        # Re-add connected routes
        for route in connected:
            self.routing_table.add_route(route)
        return count - len(connected)

    def get_stats(self) -> dict:
        """Get router statistics."""
        return {
            "router_name": self.name,
            **self.stats.to_dict(),
            "routing_table_stats": self.routing_table.get_stats(),
            "arp_table_stats": self.arp_table.get_stats(),
            "svi_count": len(self.svis),
            "physical_interface_count": len(self.physical_interfaces),
        }

    def get_logs(self, level: str | None = None) -> list[dict]:
        """Get processing logs."""
        if level:
            return [log for log in self._logs if log["level"] == level]
        return self._logs.copy()

    def clear_logs(self) -> None:
        """Clear processing logs."""
        self._logs.clear()

    def _log(self, level: str, message: str) -> None:
        """Add a log entry."""
        from datetime import datetime, timezone

        levels = ["debug", "info", "warning", "error"]
        if levels.index(level) >= levels.index(self.log_level):
            self._logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": level,
                "message": message,
            })


# Import needed for type hints
from datetime import datetime, timezone
