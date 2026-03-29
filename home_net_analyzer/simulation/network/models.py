"""Data models for network simulation engine."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from home_net_analyzer.capture.models import CapturedPacket


class DeviceType(str, Enum):
    """Types of network devices."""
    SWITCH = "switch"
    ROUTER = "router"
    HOST = "host"
    FIREWALL = "firewall"


class NetworkDevice(BaseModel):
    """A device in the network topology.

    Example:
        device = NetworkDevice(
            id="sw1",
            name="Core Switch",
            device_type=DeviceType.SWITCH,
            engine_ref="switch_engine_instance"
        )
    """

    id: str = Field(..., description="Unique device identifier")
    name: str = Field(..., description="Human-readable name")
    device_type: DeviceType = Field(..., description="Type of device")
    engine_ref: Any = Field(default=None, description="Reference to simulation engine")
    config: dict = Field(default_factory=dict, description="Device configuration")
    interfaces: dict[str, str] = Field(
        default_factory=dict,
        description="Interface name -> connected device mapping"
    )

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NetworkDevice):
            return NotImplemented
        return self.id == other.id


class NetworkLink(BaseModel):
    """A link between two network devices.

    Example:
        link = NetworkLink(
            from_device="sw1",
            to_device="router1",
            from_port=24,
            to_port="eth0",
            link_type="trunk",
            vlans=[10, 20]
        )
    """

    from_device: str = Field(..., description="Source device ID")
    to_device: str = Field(..., description="Destination device ID")
    from_port: str | int = Field(..., description="Source port/interface")
    to_port: str | int = Field(..., description="Destination port/interface")
    link_type: str = Field(default="access", description="access/trunk")
    vlans: list[int] = Field(default_factory=list, description="Allowed VLANs for trunk")
    enabled: bool = Field(default=True)

    def __hash__(self) -> int:
        return hash((self.from_device, self.to_device, str(self.from_port)))


class SimulationHost(BaseModel):
    """An end host in the network simulation.

    Example:
        host = SimulationHost(
            id="pc1",
            name="Alice's PC",
            mac="aa:bb:cc:dd:ee:01",
            ip="192.168.10.10",
            subnet_mask="255.255.255.0",
            gateway="192.168.10.1",
            vlan_id=10,
            connected_switch="sw1",
            connected_port=1
        )
    """

    id: str = Field(..., description="Unique host identifier")
    name: str = Field(..., description="Human-readable name")
    mac: str = Field(..., description="MAC address")
    ip: str = Field(..., description="IP address")
    subnet_mask: str = Field(default="255.255.255.0")
    gateway: str | None = Field(default=None, description="Default gateway")
    vlan_id: int | None = Field(default=None)
    connected_switch: str = Field(..., description="Connected switch ID")
    connected_port: int = Field(..., description="Connected switch port")

    def get_network(self) -> str:
        """Get network address from IP and subnet."""
        import ipaddress
        iface = ipaddress.ip_interface(f"{self.ip}/{self.subnet_mask}")
        return str(iface.network)

    def is_same_network(self, ip: str) -> bool:
        """Check if IP is in same network."""
        import ipaddress
        try:
            target = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(self.get_network())
            return target in network
        except ValueError:
            return False


class HopLog(BaseModel):
    """A log entry for a single hop in packet flow.

    Example:
        hop = HopLog(
            hop_number=1,
            device_id="sw1",
            device_name="Core Switch",
            action="forward",
            ingress_port=1,
            egress_port=24,
            details="MAC learning: aa:bb:cc:dd:ee:01 on port 1"
        )
    """

    hop_number: int = Field(..., description="Hop sequence number")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    device_id: str = Field(..., description="Device identifier")
    device_name: str = Field(..., description="Device name")
    device_type: DeviceType = Field(..., description="Type of device")
    action: str = Field(..., description="Action taken (forward, drop, route, etc.)")
    ingress_port: str | int | None = Field(default=None)
    egress_port: str | int | None = Field(default=None)
    packet_state: dict = Field(
        default_factory=dict,
        description="Packet state at this hop (VLAN, MAC, etc.)"
    )
    details: str = Field(default="", description="Detailed log message")


class PacketFlow(BaseModel):
    """Complete packet flow with all hops.

    Example:
        flow = PacketFlow(
            flow_id="flow-001",
            source_host="pc1",
            dest_host="pc2",
            protocol="ICMP",
            hops=[hop1, hop2, hop3]
        )
    """

    flow_id: str = Field(..., description="Unique flow identifier")
    source_host: str = Field(..., description="Source host ID")
    dest_host: str = Field(..., description="Destination host ID")
    source_ip: str = Field(...)
    dest_ip: str = Field(...)
    protocol: str = Field(default="IP")
    port: int | None = Field(default=None)
    start_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    end_time: datetime | None = Field(default=None)
    hops: list[HopLog] = Field(default_factory=list)
    final_action: str = Field(default="pending")
    success: bool = Field(default=False)

    def add_hop(self, hop: HopLog) -> None:
        """Add a hop to the flow."""
        self.hops.append(hop)

    def complete(self, success: bool, action: str) -> None:
        """Mark flow as complete."""
        self.end_time = datetime.now(timezone.utc)
        self.success = success
        self.final_action = action

    def get_duration_ms(self) -> float:
        """Get flow duration in milliseconds."""
        if not self.end_time:
            return 0.0
        return (self.end_time - self.start_time).total_seconds() * 1000

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "flow_id": self.flow_id,
            "source": self.source_host,
            "destination": self.dest_host,
            "protocol": self.protocol,
            "hops": len(self.hops),
            "duration_ms": self.get_duration_ms(),
            "success": self.success,
            "final_action": self.final_action,
        }


class NetworkTopology(BaseModel):
    """Complete network topology definition.

    Contains all devices, links, and hosts in the network.
    """

    name: str = Field(..., description="Topology name")
    devices: dict[str, NetworkDevice] = Field(
        default_factory=dict,
        description="Device ID -> Device mapping"
    )
    links: list[NetworkLink] = Field(default_factory=list)
    hosts: dict[str, SimulationHost] = Field(
        default_factory=dict,
        description="Host ID -> Host mapping"
    )

    def add_device(self, device: NetworkDevice) -> None:
        """Add a device to the topology."""
        self.devices[device.id] = device

    def add_link(self, link: NetworkLink) -> None:
        """Add a link between devices."""
        self.links.append(link)
        # Update device interfaces
        if link.from_device in self.devices:
            self.devices[link.from_device].interfaces[str(link.from_port)] = link.to_device
        if link.to_device in self.devices:
            self.devices[link.to_device].interfaces[str(link.to_port)] = link.from_device

    def add_host(self, host: SimulationHost) -> None:
        """Add a host to the topology."""
        self.hosts[host.id] = host

    def get_device(self, device_id: str) -> NetworkDevice | None:
        """Get device by ID."""
        return self.devices.get(device_id)

    def get_host(self, host_id: str) -> SimulationHost | None:
        """Get host by ID."""
        return self.hosts.get(host_id)

    def get_links_for_device(self, device_id: str) -> list[NetworkLink]:
        """Get all links connected to a device."""
        return [
            link for link in self.links
            if link.from_device == device_id or link.to_device == device_id
        ]

    def find_path(
        self,
        source_device: str,
        dest_device: str,
        visited: set[str] | None = None
    ) -> list[str] | None:
        """Find path between two devices using DFS.

        Returns list of device IDs or None if no path.
        """
        if visited is None:
            visited = set()

        if source_device == dest_device:
            return [source_device]

        visited.add(source_device)

        # Get connected devices
        device = self.devices.get(source_device)
        if not device:
            return None

        for interface, connected_id in device.interfaces.items():
            if connected_id in visited:
                continue

            path = self.find_path(connected_id, dest_device, visited.copy())
            if path:
                return [source_device] + path

        return None
