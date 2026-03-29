"""Data models for router simulation: ARP table, routing table, interfaces."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class RouteType(str, Enum):
    """Types of routing table entries."""
    CONNECTED = "connected"    # Directly connected network
    STATIC = "static"          # Static route
    DYNAMIC = "dynamic"        # Dynamic routing protocol (OSPF, BGP, etc.)


class RouteEntry(BaseModel):
    """A single entry in the routing table.

    Supports longest prefix match for route selection.

    Example:
        route = RouteEntry(
            destination="192.168.1.0/24",
            next_hop="10.0.0.1",
            interface="eth0",
            metric=1
        )
    """

    destination: str = Field(..., description="Destination network (CIDR notation)")
    next_hop: str | None = Field(
        default=None,
        description="Next hop IP address (None for connected routes)"
    )
    interface: str = Field(..., description="Outgoing interface name")
    metric: int = Field(default=1, ge=0, description="Route metric (lower is better)")
    route_type: RouteType = Field(default=RouteType.STATIC)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When route was added"
    )

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, v: str) -> str:
        """Validate destination is valid CIDR."""
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid destination network: {v}") from e

    def get_network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """Get the destination as a network object."""
        return ipaddress.ip_network(self.destination, strict=False)

    def matches(self, ip: str) -> bool:
        """Check if an IP address matches this route's destination network."""
        try:
            addr = ipaddress.ip_address(ip)
            network = self.get_network()
            return addr in network
        except ValueError:
            return False

    def prefix_length(self) -> int:
        """Get the prefix length of this route."""
        return self.get_network().prefixlen

    def __hash__(self) -> int:
        """Make hashable for use in sets/dicts."""
        return hash((self.destination, self.interface))

    def __eq__(self, other: object) -> bool:
        """Equality check."""
        if not isinstance(other, RouteEntry):
            return NotImplemented
        return self.destination == other.destination and self.interface == other.interface


class RoutingTable:
    """Routing table with longest prefix match lookup.

    The routing table stores routes and selects the best match
    based on longest prefix (most specific route wins).

    Example:
        table = RoutingTable()
        table.add_route(RouteEntry(destination="192.168.1.0/24", interface="eth0"))
        table.add_route(RouteEntry(destination="0.0.0.0/0", next_hop="10.0.0.1", interface="eth1"))

        route = table.lookup("192.168.1.50")  # Returns /24 route
        route = table.lookup("8.8.8.8")       # Returns default route
    """

    def __init__(self):
        """Initialize empty routing table."""
        self._routes: list[RouteEntry] = []
        self._stats = {
            "lookups": 0,
            "hits": 0,
            "misses": 0,
        }

    def add_route(self, route: RouteEntry) -> None:
        """Add a route to the table.

        Args:
            route: RouteEntry to add
        """
        # Remove existing route with same destination+interface
        self._routes = [
            r for r in self._routes
            if not (r.destination == route.destination and r.interface == route.interface)
        ]
        self._routes.append(route)

    def remove_route(self, destination: str, interface: str | None = None) -> bool:
        """Remove a route from the table.

        Args:
            destination: Destination network to remove
            interface: Optional interface filter

        Returns:
            True if route was removed, False if not found
        """
        initial_count = len(self._routes)
        if interface:
            self._routes = [
                r for r in self._routes
                if not (r.destination == destination and r.interface == interface)
            ]
        else:
            self._routes = [r for r in self._routes if r.destination != destination]
        return len(self._routes) < initial_count

    def lookup(self, ip: str) -> RouteEntry | None:
        """Find the best matching route for an IP address.

        Uses longest prefix match - the route with the most specific
        (longest) prefix that contains the IP address wins.

        Args:
            ip: IP address to look up

        Returns:
            Best matching RouteEntry or None if no match
        """
        self._stats["lookups"] += 1

        # Find all matching routes
        matching = [r for r in self._routes if r.matches(ip)]

        if not matching:
            self._stats["misses"] += 1
            return None

        # Select route with longest prefix (most specific)
        best = max(matching, key=lambda r: r.prefix_length())

        # If multiple routes with same prefix, choose lowest metric
        candidates = [r for r in matching if r.prefix_length() == best.prefix_length()]
        best = min(candidates, key=lambda r: r.metric)

        self._stats["hits"] += 1
        return best

    def get_routes(self) -> list[RouteEntry]:
        """Get all routes in the table."""
        return self._routes.copy()

    def get_connected_routes(self) -> list[RouteEntry]:
        """Get all connected routes."""
        return [r for r in self._routes if r.route_type == RouteType.CONNECTED]

    def clear(self) -> int:
        """Clear all routes from the table.

        Returns:
            Number of routes cleared
        """
        count = len(self._routes)
        self._routes.clear()
        return count

    def get_stats(self) -> dict:
        """Get routing table statistics."""
        return self._stats.copy()


class ARPEntry(BaseModel):
    """A single entry in the ARP table.

    Example:
        entry = ARPEntry(
            ip_address="192.168.1.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            interface="eth0"
        )
    """

    ip_address: str = Field(..., description="IP address")
    mac_address: str = Field(..., description="MAC address")
    interface: str = Field(..., description="Interface name")
    entry_type: Literal["dynamic", "static"] = Field(default="dynamic")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When entry was created"
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Last ARP packet timestamp"
    )
    ttl: int = Field(default=300, ge=0, description="Time-to-live in seconds")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address."""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {v}") from e

    def is_expired(self) -> bool:
        """Check if entry has aged out."""
        if self.entry_type == "static":
            return False
        elapsed = (datetime.now(timezone.utc) - self.last_seen).total_seconds()
        return elapsed > self.ttl

    def touch(self) -> None:
        """Update last_seen timestamp to now."""
        self.last_seen = datetime.now(timezone.utc)

    def __hash__(self) -> int:
        """Make hashable."""
        return hash((self.ip_address, self.interface))

    def __eq__(self, other: object) -> bool:
        """Equality check."""
        if not isinstance(other, ARPEntry):
            return NotImplemented
        return self.ip_address == other.ip_address and self.interface == other.interface


class ARPTable:
    """ARP table for IP-to-MAC resolution.

    Manages dynamic and static ARP entries with aging support.

    Example:
        arp = ARPTable()
        arp.learn("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")
        mac = arp.resolve("192.168.1.1")  # Returns "aa:bb:cc:dd:ee:ff"
    """

    def __init__(self, default_ttl: int = 300):
        """Initialize ARP table.

        Args:
            default_ttl: Default time-to-live for dynamic entries
        """
        self._entries: dict[tuple[str, str], ARPEntry] = {}
        self.default_ttl = default_ttl
        self._stats = {
            "learned": 0,
            "resolved": 0,
            "failed": 0,
            "aged_out": 0,
        }

    def learn(
        self,
        ip: str,
        mac: str,
        interface: str,
        entry_type: Literal["dynamic", "static"] = "dynamic"
    ) -> ARPEntry:
        """Learn or update an ARP entry.

        Args:
            ip: IP address
            mac: MAC address
            interface: Interface name
            entry_type: Type of entry

        Returns:
            The ARP entry
        """
        key = (ip, interface)

        if key in self._entries:
            entry = self._entries[key]
            entry.mac_address = mac.lower()
            entry.touch()
            return entry

        ttl = 0 if entry_type == "static" else self.default_ttl
        entry = ARPEntry(
            ip_address=ip,
            mac_address=mac.lower(),
            interface=interface,
            entry_type=entry_type,
            ttl=ttl
        )
        self._entries[key] = entry
        self._stats["learned"] += 1
        return entry

    def resolve(self, ip: str, interface: str | None = None) -> str | None:
        """Resolve IP address to MAC address.

        Args:
            ip: IP address to resolve
            interface: Optional interface filter

        Returns:
            MAC address if found, None otherwise
        """
        if interface:
            key = (ip, interface)
            entry = self._entries.get(key)
            if entry and not entry.is_expired():
                entry.touch()
                self._stats["resolved"] += 1
                return entry.mac_address
            if entry and entry.is_expired():
                del self._entries[key]
        else:
            # Search all interfaces
            for key, entry in list(self._entries.items()):
                if entry.ip_address == ip:
                    if entry.is_expired():
                        del self._entries[key]
                        continue
                    entry.touch()
                    self._stats["resolved"] += 1
                    return entry.mac_address

        self._stats["failed"] += 1
        return None

    def age_out(self) -> list[ARPEntry]:
        """Remove expired entries and return what was removed."""
        expired = []
        for key, entry in list(self._entries.items()):
            if entry.is_expired():
                expired.append(entry)
                del self._entries[key]
        self._stats["aged_out"] += len(expired)
        return expired

    def add_static(self, ip: str, mac: str, interface: str) -> ARPEntry:
        """Add a static ARP entry."""
        return self.learn(ip, mac, interface, entry_type="static")

    def remove(self, ip: str, interface: str | None = None) -> bool:
        """Remove an ARP entry."""
        if interface:
            key = (ip, interface)
            if key in self._entries:
                del self._entries[key]
                return True
            return False
        else:
            removed = False
            for key in list(self._entries.keys()):
                if key[0] == ip:
                    del self._entries[key]
                    removed = True
            return removed

    def get_entries(self) -> list[ARPEntry]:
        """Get all ARP entries."""
        return list(self._entries.values())

    def get_entry_count(self) -> int:
        """Get number of entries."""
        return len(self._entries)

    def clear(self) -> int:
        """Clear all entries."""
        count = len(self._entries)
        self._entries.clear()
        return count

    def get_stats(self) -> dict:
        """Get ARP statistics."""
        return self._stats.copy()


class RouterInterface(BaseModel):
    """A physical router interface.

    Example:
        iface = RouterInterface(
            name="eth0",
            ip_address="192.168.1.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:dd:ee:ff"
        )
    """

    name: str = Field(..., description="Interface name")
    ip_address: str | None = Field(default=None, description="IP address")
    subnet_mask: str | None = Field(default=None, description="Subnet mask")
    mac_address: str | None = Field(default=None, description="MAC address")
    enabled: bool = Field(default=True)
    description: str = Field(default="")

    def get_network(self) -> str | None:
        """Get the network address in CIDR notation."""
        if not self.ip_address or not self.subnet_mask:
            return None
        try:
            iface_ip = ipaddress.ip_interface(f"{self.ip_address}/{self.subnet_mask}")
            return str(iface_ip.network)
        except ValueError:
            return None

    def is_in_network(self, ip: str) -> bool:
        """Check if an IP is in this interface's network."""
        network = self.get_network()
        if not network:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(network)
            return addr in net
        except ValueError:
            return False


class SVI(BaseModel):
    """Switched Virtual Interface (SVI) for VLAN routing.

    An SVI is a virtual interface that provides Layer 3 routing
    for a VLAN. It's commonly called an "interface VLAN" on switches.

    Example:
        svi = SVI(
            vlan_id=10,
            ip_address="192.168.10.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:dd:ee:ff"
        )
    """

    vlan_id: int = Field(..., ge=1, le=4094, description="VLAN ID")
    ip_address: str = Field(..., description="IP address for the SVI")
    subnet_mask: str = Field(..., description="Subnet mask")
    mac_address: str = Field(..., description="MAC address")
    enabled: bool = Field(default=True)
    description: str = Field(default="")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address."""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {v}") from e

    def get_network(self) -> str:
        """Get the network address in CIDR notation."""
        iface_ip = ipaddress.ip_interface(f"{self.ip_address}/{self.subnet_mask}")
        return str(iface_ip.network)

    def is_in_network(self, ip: str) -> bool:
        """Check if an IP is in this SVI's network."""
        try:
            addr = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(self.get_network())
            return addr in net
        except ValueError:
            return False

    def get_interface_name(self) -> str:
        """Get the interface name (e.g., 'Vlan10')."""
        return f"Vlan{self.vlan_id}"

    def to_route_entry(self) -> RouteEntry:
        """Convert to a connected route entry."""
        return RouteEntry(
            destination=self.get_network(),
            next_hop=None,
            interface=self.get_interface_name(),
            route_type=RouteType.CONNECTED,
            metric=0
        )
