"""Data models for network topology: VLANs, hosts, switches, routers, and the overall topology."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class VLAN(BaseModel):
    """Represents a VLAN (Virtual LAN) with its ID, name, subnet, and gateway.

    Example:
        VLAN(id=10, name="Management", subnet="10.0.10.0/24", gateway="10.0.10.1")
    """

    id: int = Field(..., ge=1, le=4094, description="VLAN ID (1-4094)")
    name: str = Field(..., min_length=1, description="Human-readable VLAN name")
    subnet: str = Field(..., description="Subnet in CIDR notation, e.g., '10.0.10.0/24'")
    gateway: str = Field(..., description="Gateway IP address for this VLAN")
    description: str | None = None

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        if "/" not in v:
            raise ValueError("Subnet must be CIDR notation like '10.0.10.0/24'")
        parts = v.split("/")
        if len(parts) != 2:
            raise ValueError("Subnet must be CIDR notation like '10.0.10.0/24'")
        ip_parts = parts[0].split(".")
        if len(ip_parts) != 4 or not all(p.isdigit() for p in ip_parts):
            raise ValueError("Subnet IP must be like '10.0.10.0'")
        try:
            prefix = int(parts[1])
        except ValueError:
            raise ValueError("Subnet prefix must be an integer")
        if not (0 <= prefix <= 32):
            raise ValueError("Subnet prefix must be 0-32")
        return v

    @field_validator("gateway")
    @classmethod
    def validate_gateway(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            raise ValueError("Gateway must be like '10.0.10.1'")
        return v

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "subnet": self.subnet,
            "gateway": self.gateway,
            "description": self.description,
        }


class VirtualHost(BaseModel):
    """Represents a virtual host/device in the network.

    Example:
        VirtualHost(name="eng-laptop-01", mac="aa:bb:cc:01:00:01", ip="10.0.20.101", vlan_id=20)
    """

    name: str = Field(..., min_length=1, description="Unique host name")
    mac: str = Field(..., description="MAC address, e.g., 'aa:bb:cc:01:00:01'")
    ip: str = Field(..., description="IP address")
    vlan_id: int | None = Field(None, ge=1, le=4094, description="VLAN ID if tagged")
    role: Literal["endpoint", "server", "gateway", "other"] = "endpoint"
    description: str | None = None

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        parts = v.split(":")
        if len(parts) != 6 or not all(len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts):
            raise ValueError("MAC must be like 'aa:bb:cc:01:00:01'")
        return v.lower()

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            raise ValueError("IP must be like '192.168.1.50'")
        return v

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "mac": self.mac,
            "ip": self.ip,
            "vlan_id": self.vlan_id,
            "role": self.role,
            "description": self.description,
        }


class SwitchPort(BaseModel):
    """Represents a port on a virtual switch.

    Example:
        SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10, connected_to="pc-01")
        SwitchPort(id=10, name="Gi1/0/10", mode="trunk", allowed_vlans=[10, 20, 30])
    """

    id: int = Field(..., ge=1, description="Port ID (unique within switch)")
    name: str = Field(..., min_length=1, description="Port name, e.g., 'Gi1/0/1'")
    mode: Literal["access", "trunk"] = "access"
    access_vlan: int | None = Field(None, ge=1, le=4094, description="VLAN for access ports")
    allowed_vlans: list[int] = Field(default_factory=list, description="Allowed VLANs for trunk ports")
    connected_to: str | None = Field(None, description="Name of connected host/switch")

    @model_validator(mode="after")
    def validate_port_mode_consistency(self) -> "SwitchPort":
        if self.mode == "access":
            if self.access_vlan is None:
                raise ValueError("Access port must have access_vlan set")
            if self.allowed_vlans:
                raise ValueError("Access port should not have allowed_vlans")
        elif self.mode == "trunk":
            if self.access_vlan is not None:
                raise ValueError("Trunk port should not have access_vlan (use allowed_vlans)")
            if not self.allowed_vlans:
                raise ValueError("Trunk port must have at least one allowed_vlan")
        # Validate allowed_vlans contents
        for vid in self.allowed_vlans:
            if not (1 <= vid <= 4094):
                raise ValueError(f"VLAN ID {vid} must be 1-4094")
        return self

    def is_trunk(self) -> bool:
        return self.mode == "trunk"

    def is_access(self) -> bool:
        return self.mode == "access"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "mode": self.mode,
            "access_vlan": self.access_vlan,
            "allowed_vlans": self.allowed_vlans,
            "connected_to": self.connected_to,
        }


class VirtualSwitch(BaseModel):
    """Represents a virtual Layer-2 switch with VLAN-aware ports.

    Example:
        VirtualSwitch(name="core-sw-01", ports=[...], vlans=[10, 20])
    """

    name: str = Field(..., min_length=1, description="Switch name")
    ports: list[SwitchPort] = Field(default_factory=list)
    vlans: list[int] = Field(default_factory=list, description="VLANs this switch knows about (SVI or trunk)")
    description: str | None = None

    def get_port(self, port_id: int) -> SwitchPort | None:
        for p in self.ports:
            if p.id == port_id:
                return p
        return None

    def get_port_by_name(self, name: str) -> SwitchPort | None:
        for p in self.ports:
            if p.name == name:
                return p
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ports": [p.to_dict() for p in self.ports],
            "vlans": self.vlans,
            "description": self.description,
        }


class RouterInterface(BaseModel):
    """Represents an interface on a router (may be VLAN-tagged)."""

    name: str = Field(..., min_length=1)
    ip: str = Field(..., description="Interface IP address")
    subnet: str = Field(..., description="Subnet this interface serves")
    vlan_id: int | None = Field(None, ge=1, le=4094, description="VLAN if sub-interface")
    description: str | None = None

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            raise ValueError("IP must be like '192.168.1.1'")
        return v

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        if "/" not in v:
            raise ValueError("Subnet must be CIDR notation")
        return v

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ip": self.ip,
            "subnet": self.subnet,
            "vlan_id": self.vlan_id,
            "description": self.description,
        }


class RouteEntry(BaseModel):
    """A static route entry."""

    destination: str = Field(..., description="Destination subnet (CIDR)")
    next_hop: str = Field(..., description="Next hop IP")
    interface: str = Field(..., description="Outgoing interface name")

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, v: str) -> str:
        if "/" not in v:
            raise ValueError("Destination must be CIDR notation")
        return v

    @field_validator("next_hop")
    @classmethod
    def validate_next_hop(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            raise ValueError("Next hop must be like '192.168.1.1'")
        return v

    def to_dict(self) -> dict:
        return {
            "destination": self.destination,
            "next_hop": self.next_hop,
            "interface": self.interface,
        }


class Router(BaseModel):
    """Represents a virtual Layer-3 router with interfaces and routing table."""

    name: str = Field(..., min_length=1)
    interfaces: list[RouterInterface] = Field(default_factory=list)
    routing_table: list[RouteEntry] = Field(default_factory=list)
    description: str | None = None

    def get_interface(self, name: str) -> RouterInterface | None:
        for iface in self.interfaces:
            if iface.name == name:
                return iface
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "interfaces": [i.to_dict() for i in self.interfaces],
            "routing_table": [r.to_dict() for r in self.routing_table],
            "description": self.description,
        }


class Topology(BaseModel):
    """The complete network topology: VLANs, hosts, switches, and routers."""

    name: str = Field(..., min_length=1, description="Topology name")
    vlans: list[VLAN] = Field(default_factory=list)
    hosts: list[VirtualHost] = Field(default_factory=list)
    switches: list[VirtualSwitch] = Field(default_factory=list)
    routers: list[Router] = Field(default_factory=list)
    description: str | None = None

    def get_vlan(self, vlan_id: int) -> VLAN | None:
        for v in self.vlans:
            if v.id == vlan_id:
                return v
        return None

    def get_host(self, name: str) -> VirtualHost | None:
        for h in self.hosts:
            if h.name == name:
                return h
        return None

    def get_switch(self, name: str) -> VirtualSwitch | None:
        for s in self.switches:
            if s.name == name:
                return s
        return None

    def get_router(self, name: str) -> Router | None:
        for r in self.routers:
            if r.name == name:
                return r
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vlans": [v.to_dict() for v in self.vlans],
            "hosts": [h.to_dict() for h in self.hosts],
            "switches": [s.to_dict() for s in self.switches],
            "routers": [r.to_dict() for r in self.routers],
            "description": self.description,
        }
