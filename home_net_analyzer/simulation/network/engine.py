"""Network simulation engine for orchestrating multi-device packet flows."""

from __future__ import annotations

import uuid
from typing import Literal

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.simulation.network.models import (
    DeviceType,
    HopLog,
    NetworkDevice,
    NetworkLink,
    NetworkTopology,
    PacketFlow,
    SimulationHost,
)
from home_net_analyzer.simulation.router.engine import RouterEngine
from home_net_analyzer.simulation.switch.engine import SwitchEngine


class NetworkSimulationEngine:
    """Engine for simulating packet flows across multiple network devices.

    This engine orchestrates:
    - Multi-hop packet forwarding through switches and routers
    - Hop-by-hop logging with detailed state at each step
    - VLAN tagging/untagging across trunk links
    - Inter-VLAN routing
    - Protocol simulations (DHCP, DNS, ICMP, etc.)

    Example:
        sim = NetworkSimulationEngine()
        sim.load_topology(my_topology)
        
        # Simulate ping from pc1 to pc2
        flow = sim.simulate_packet(
            source_host="pc1",
            dest_host="pc2",
            protocol="ICMP"
        )
        
        # Print hop-by-hop trace
        for hop in flow.hops:
            print(f"{hop.hop_number}: {hop.device_name} - {hop.action}")
    """

    def __init__(self, name: str = "network-sim"):
        """Initialize simulation engine.

        Args:
            name: Simulation name
        """
        self.name = name
        self.topology: NetworkTopology | None = None
        self.flows: list[PacketFlow] = []
        self._stats = {
            "flows_simulated": 0,
            "flows_successful": 0,
            "flows_dropped": 0,
            "total_hops": 0,
        }

    def load_topology(self, topology: NetworkTopology) -> None:
        """Load a network topology into the engine.

        Args:
            topology: NetworkTopology to load
        """
        self.topology = topology

    def create_topology(self, name: str) -> NetworkTopology:
        """Create a new empty topology.

        Args:
            name: Topology name

        Returns:
            New NetworkTopology
        """
        self.topology = NetworkTopology(name=name)
        return self.topology

    def add_switch(
        self,
        device_id: str,
        name: str,
        switch_engine: SwitchEngine
    ) -> NetworkDevice:
        """Add a switch to the topology.

        Args:
            device_id: Unique device ID
            name: Human-readable name
            switch_engine: Configured SwitchEngine instance

        Returns:
            Created NetworkDevice
        """
        if not self.topology:
            raise RuntimeError("No topology loaded. Call create_topology() first.")

        device = NetworkDevice(
            id=device_id,
            name=name,
            device_type=DeviceType.SWITCH,
            engine_ref=switch_engine
        )
        self.topology.add_device(device)
        return device

    def add_router(
        self,
        device_id: str,
        name: str,
        router_engine: RouterEngine
    ) -> NetworkDevice:
        """Add a router to the topology.

        Args:
            device_id: Unique device ID
            name: Human-readable name
            router_engine: Configured RouterEngine instance

        Returns:
            Created NetworkDevice
        """
        if not self.topology:
            raise RuntimeError("No topology loaded. Call create_topology() first.")

        device = NetworkDevice(
            id=device_id,
            name=name,
            device_type=DeviceType.ROUTER,
            engine_ref=router_engine
        )
        self.topology.add_device(device)
        return device

    def add_host(
        self,
        host_id: str,
        name: str,
        mac: str,
        ip: str,
        connected_switch: str,
        connected_port: int,
        gateway: str | None = None,
        vlan_id: int | None = None,
        subnet_mask: str = "255.255.255.0"
    ) -> SimulationHost:
        """Add a host to the topology.

        Args:
            host_id: Unique host ID
            name: Human-readable name
            mac: MAC address
            ip: IP address
            connected_switch: Connected switch device ID
            connected_port: Connected switch port
            gateway: Default gateway IP
            vlan_id: VLAN ID
            subnet_mask: Subnet mask

        Returns:
            Created SimulationHost
        """
        if not self.topology:
            raise RuntimeError("No topology loaded. Call create_topology() first.")

        host = SimulationHost(
            id=host_id,
            name=name,
            mac=mac,
            ip=ip,
            subnet_mask=subnet_mask,
            gateway=gateway,
            vlan_id=vlan_id,
            connected_switch=connected_switch,
            connected_port=connected_port
        )
        self.topology.add_host(host)
        return host

    def connect_devices(
        self,
        from_device: str,
        to_device: str,
        from_port: str | int,
        to_port: str | int,
        link_type: str = "access",
        vlans: list[int] | None = None
    ) -> NetworkLink:
        """Connect two devices with a link.

        Args:
            from_device: Source device ID
            to_device: Destination device ID
            from_port: Source port
            to_port: Destination port
            link_type: access or trunk
            vlans: Allowed VLANs for trunk links

        Returns:
            Created NetworkLink
        """
        if not self.topology:
            raise RuntimeError("No topology loaded.")

        link = NetworkLink(
            from_device=from_device,
            to_device=to_device,
            from_port=from_port,
            to_port=to_port,
            link_type=link_type,
            vlans=vlans or []
        )
        self.topology.add_link(link)
        return link

    def simulate_packet(
        self,
        source_host: str,
        dest_host: str,
        protocol: str = "IP",
        port: int | None = None,
        payload: dict | None = None
    ) -> PacketFlow:
        """Simulate a packet flow between two hosts.

        This is the main entry point for packet simulation. It traces
        the packet through the network, device by device, logging each hop.

        Args:
            source_host: Source host ID
            dest_host: Destination host ID
            protocol: Protocol name (ICMP, TCP, UDP, DHCP, DNS)
            port: Destination port (for TCP/UDP)
            payload: Additional payload data

        Returns:
            PacketFlow with complete hop-by-hop trace
        """
        if not self.topology:
            raise RuntimeError("No topology loaded.")

        src = self.topology.get_host(source_host)
        dst = self.topology.get_host(dest_host)

        if not src:
            raise ValueError(f"Source host '{source_host}' not found")
        if not dst:
            raise ValueError(f"Destination host '{dest_host}' not found")

        # Create packet flow
        flow = PacketFlow(
            flow_id=str(uuid.uuid4())[:8],
            source_host=source_host,
            dest_host=dest_host,
            source_ip=src.ip,
            dest_ip=dst.ip,
            protocol=protocol,
            port=port
        )

        self._stats["flows_simulated"] += 1

        # Create initial packet
        packet = CapturedPacket(
            src_mac=src.mac,
            dst_mac=dst.mac,
            src_ip=src.ip,
            dst_ip=dst.ip,
            vlan_id=src.vlan_id,
            transport_protocol=protocol if protocol in ["TCP", "UDP", "ICMP"] else None
        )

        # Determine if we need routing
        needs_routing = not src.is_same_network(dst.ip)

        # Start simulation from source host's connected switch
        current_device_id = src.connected_switch
        ingress_port = src.connected_port
        hop_number = 0
        max_hops = 20  # Prevent infinite loops

        while current_device_id and hop_number < max_hops:
            device = self.topology.get_device(current_device_id)
            if not device:
                flow.complete(False, f"Device {current_device_id} not found")
                self._stats["flows_dropped"] += 1
                return flow

            hop_number += 1

            # Process packet through device
            result = self._process_device(
                device=device,
                packet=packet,
                ingress_port=ingress_port,
                flow=flow,
                hop_number=hop_number,
                needs_routing=needs_routing,
                dst_host=dst
            )

            if result["action"] == "delivered":
                flow.complete(True, "Delivered to destination")
                self._stats["flows_successful"] += 1
                return flow
            elif result["action"] == "dropped":
                flow.complete(False, result.get("reason", "Dropped"))
                self._stats["flows_dropped"] += 1
                return flow
            elif result["action"] == "forward":
                # Move to next device
                current_device_id = result.get("next_device")
                ingress_port = result.get("next_ingress_port")

                # Update packet state for next hop
                if "vlan_id" in result:
                    packet.vlan_id = result["vlan_id"]
                if "dst_mac" in result:
                    packet.dst_mac = result["dst_mac"]
            else:
                flow.complete(False, f"Unknown action: {result['action']}")
                self._stats["flows_dropped"] += 1
                return flow

        # Max hops exceeded
        flow.complete(False, "Max hops exceeded (possible loop)")
        self._stats["flows_dropped"] += 1
        return flow

    def _process_device(
        self,
        device: NetworkDevice,
        packet: CapturedPacket,
        ingress_port: str | int,
        flow: PacketFlow,
        hop_number: int,
        needs_routing: bool,
        dst_host: SimulationHost
    ) -> dict:
        """Process packet through a single device.

        Args:
            device: Device to process through
            packet: Current packet state
            ingress_port: Port packet entered on
            flow: Packet flow being built
            hop_number: Current hop number
            needs_routing: Whether routing is needed
            dst_host: Destination host

        Returns:
            Dict with action and next hop info
        """
        if device.device_type == DeviceType.SWITCH:
            return self._process_switch(
                device, packet, ingress_port, flow, hop_number,
                needs_routing, dst_host
            )
        elif device.device_type == DeviceType.ROUTER:
            return self._process_router(
                device, packet, ingress_port, flow, hop_number,
                needs_routing, dst_host
            )
        else:
            return {"action": "dropped", "reason": f"Unknown device type: {device.device_type}"}

    def _process_switch(
        self,
        device: NetworkDevice,
        packet: CapturedPacket,
        ingress_port: str | int,
        flow: PacketFlow,
        hop_number: int,
        needs_routing: bool,
        dst_host: SimulationHost
    ) -> dict:
        """Process packet through a switch."""
        switch_engine: SwitchEngine = device.engine_ref

        # Create switch frame
        from home_net_analyzer.simulation.switch.models import SwitchFrame
        frame = SwitchFrame(
            packet=packet,
            ingress_port=int(ingress_port),
            ingress_switch=device.id,
            native_vlan=packet.vlan_id or 1
        )

        # Process through switch
        decisions = switch_engine.process_frame(frame)

        # Log the hop
        if decisions:
            egress_ports = [d.port_id for d in decisions]
            hop = HopLog(
                hop_number=hop_number,
                device_id=device.id,
                device_name=device.name,
                device_type=DeviceType.SWITCH,
                action="forward",
                ingress_port=ingress_port,
                egress_port=egress_ports[0] if len(egress_ports) == 1 else str(egress_ports),
                packet_state={
                    "vlan_id": packet.vlan_id,
                    "src_mac": packet.src_mac,
                    "dst_mac": packet.dst_mac
                },
                details=f"MAC table lookup: egress ports {egress_ports}"
            )
        else:
            hop = HopLog(
                hop_number=hop_number,
                device_id=device.id,
                device_name=device.name,
                device_type=DeviceType.SWITCH,
                action="drop",
                ingress_port=ingress_port,
                packet_state={"vlan_id": packet.vlan_id},
                details="No forwarding decision (unknown destination or VLAN mismatch)"
            )
            flow.add_hop(hop)
            return {"action": "dropped", "reason": "Switch dropped frame"}

        flow.add_hop(hop)

        # Check if destination host is directly connected
        for decision in decisions:
            # Check if this port connects to destination
            if self._is_destination_port(device.id, decision.port_id, dst_host):
                # Check if VLAN matches
                if packet.vlan_id == dst_host.vlan_id:
                    hop_delivered = HopLog(
                        hop_number=hop_number + 1,
                        device_id="host",
                        device_name=dst_host.name,
                        device_type=DeviceType.HOST,
                        action="delivered",
                        packet_state={"vlan_id": packet.vlan_id},
                        details=f"Packet delivered to {dst_host.ip}"
                    )
                    flow.add_hop(hop_delivered)
                    return {"action": "delivered"}

        # Find next device in path
        for decision in decisions:
            next_device = self._get_connected_device(device.id, decision.port_id)
            if next_device:
                return {
                    "action": "forward",
                    "next_device": next_device,
                    "next_ingress_port": self._get_connected_port(device.id, decision.port_id),
                    "vlan_id": decision.egress_vlan if hasattr(decision, 'egress_vlan') else packet.vlan_id
                }

        # No path found
        return {"action": "dropped", "reason": "No path to destination"}

    def _process_router(
        self,
        device: NetworkDevice,
        packet: CapturedPacket,
        ingress_port: str | int,
        flow: PacketFlow,
        hop_number: int,
        needs_routing: bool,
        dst_host: SimulationHost
    ) -> dict:
        """Process packet through a router."""
        router_engine: RouterEngine = device.engine_ref

        # Determine ingress interface name
        if isinstance(ingress_port, int):
            # Coming from switch - find which SVI/VLAN
            ingress_iface = f"Vlan{packet.vlan_id}" if packet.vlan_id else "unknown"
        else:
            ingress_iface = str(ingress_port)

        # Process through router
        decision = router_engine.process_packet(packet, ingress_iface)

        # Log the hop
        hop = HopLog(
            hop_number=hop_number,
            device_id=device.id,
            device_name=device.name,
            device_type=DeviceType.ROUTER,
            action=decision.action,
            ingress_port=ingress_port,
            egress_port=decision.outgoing_interface,
            packet_state={
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "vlan_id": packet.vlan_id
            },
            details=f"Routing decision: {decision.reason}"
        )
        flow.add_hop(hop)

        if decision.action == "drop":
            return {"action": "dropped", "reason": decision.reason}

        if decision.action == "deliver_local":
            return {"action": "delivered"}

        # Forward action - find next device
        next_device = self._get_connected_device(device.id, decision.outgoing_interface)
        if next_device:
            return {
                "action": "forward",
                "next_device": next_device,
                "next_ingress_port": self._get_connected_port(device.id, decision.outgoing_interface),
                "vlan_id": self._get_vlan_for_interface(device.id, decision.outgoing_interface, dst_host.vlan_id),
                "dst_mac": decision.next_hop_mac
            }

        # Check if we're delivering to destination subnet
        if decision.outgoing_interface and decision.outgoing_interface.startswith("Vlan"):
            vlan_id = int(decision.outgoing_interface[4:])
            if vlan_id == dst_host.vlan_id:
                hop_delivered = HopLog(
                    hop_number=hop_number + 1,
                    device_id="host",
                    device_name=dst_host.name,
                    device_type=DeviceType.HOST,
                    action="delivered",
                    packet_state={"vlan_id": vlan_id},
                    details=f"Packet delivered to {dst_host.ip} via {decision.outgoing_interface}"
                )
                flow.add_hop(hop_delivered)
                return {"action": "delivered"}

        return {"action": "dropped", "reason": "No connected device on egress interface"}

    def _is_destination_port(
        self,
        device_id: str,
        port: int,
        dst_host: SimulationHost
    ) -> bool:
        """Check if a port connects to the destination host."""
        return (
            device_id == dst_host.connected_switch and
            port == dst_host.connected_port
        )

    def _get_connected_device(
        self,
        device_id: str,
        port: str | int
    ) -> str | None:
        """Get device connected to a port."""
        if not self.topology:
            return None

        device = self.topology.get_device(device_id)
        if not device:
            return None

        return device.interfaces.get(str(port))

    def _get_connected_port(
        self,
        device_id: str,
        port: str | int
    ) -> str | int | None:
        """Get the port on the connected device."""
        if not self.topology:
            return None

        for link in self.topology.links:
            if link.from_device == device_id and str(link.from_port) == str(port):
                return link.to_port
            if link.to_device == device_id and str(link.to_port) == str(port):
                return link.from_port

        return None

    def _get_vlan_for_interface(
        self,
        device_id: str,
        interface: str,
        default_vlan: int | None
    ) -> int | None:
        """Get VLAN ID for a router interface."""
        if interface.startswith("Vlan"):
            return int(interface[4:])
        return default_vlan

    def get_flow_summary(self) -> dict:
        """Get summary of all simulated flows."""
        return {
            "total_flows": len(self.flows),
            "successful": sum(1 for f in self.flows if f.success),
            "dropped": sum(1 for f in self.flows if not f.success),
            "stats": self._stats.copy()
        }

    def get_recent_flows(self, limit: int = 10) -> list[PacketFlow]:
        """Get recent flows."""
        return self.flows[-limit:]

    def clear_flows(self) -> None:
        """Clear all recorded flows."""
        self.flows.clear()
        self._stats = {
            "flows_simulated": 0,
            "flows_successful": 0,
            "flows_dropped": 0,
            "total_hops": 0,
        }
