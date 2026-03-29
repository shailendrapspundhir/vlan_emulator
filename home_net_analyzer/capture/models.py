"""Data models for captured packets."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class CapturedPacket(BaseModel):
    """Normalized representation of a captured network packet."""

    # Timestamp
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Layer 2
    src_mac: str | None = None
    dst_mac: str | None = None
    eth_type: int | None = None  # e.g., 0x0800 for IPv4, 0x86DD for IPv6

    # 802.1Q VLAN tagging (Layer 2.5)
    vlan_id: int | None = None  # VLAN ID 1-4094 (None = untagged)
    vlan_prio: int | None = None  # Priority Code Point (PCP) 0-7
    vlan_dei: bool = False  # Drop Eligible Indicator (DEI)

    # Layer 3 (IP)
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: int | None = None  # 4 or 6
    ip_ttl: int | None = None
    ip_protocol: int | None = None  # 1=ICMP, 6=TCP, 17=UDP, etc.

    # Layer 4 (Transport)
    src_port: int | None = None
    dst_port: int | None = None
    transport_protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None

    # TCP-specific
    tcp_flags: int | None = None  # raw flags byte
    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_fin: bool = False
    tcp_rst: bool = False
    tcp_psh: bool = False
    tcp_urg: bool = False

    # Packet metadata
    length: int = 0  # total length in bytes
    payload: bytes | None = None  # optional raw payload (truncated)
    payload_len: int = 0  # length of payload stored

    # Protocol hints (higher-level)
    application_protocol: str | None = None  # e.g., "DNS", "HTTP", "TLS", "SSH"

    # Capture context
    interface: str | None = None
    captured_by: str = "scapy"  # or "pyshark", etc.

    model_config = {"arbitrary_types_allowed": True}

    # -----------------------------------------------------------------
    # Validators
    # -----------------------------------------------------------------

    @field_validator("vlan_id")
    @classmethod
    def validate_vlan_id(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 4094):
            raise ValueError("vlan_id must be 1-4094")
        return v

    @field_validator("vlan_prio")
    @classmethod
    def validate_vlan_prio(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 7):
            raise ValueError("vlan_prio (PCP) must be 0-7")
        return v

    # -----------------------------------------------------------------
    # VLAN helpers
    # -----------------------------------------------------------------

    def is_vlan_tagged(self) -> bool:
        """Return True if packet has an 802.1Q VLAN tag."""
        return self.vlan_id is not None

    def vlan_tag(self) -> dict | None:
        """Return VLAN tag info as dict, or None if untagged."""
        if self.vlan_id is None:
            return None
        return {
            "vlan_id": self.vlan_id,
            "priority": self.vlan_prio if self.vlan_prio is not None else 0,
            "dei": self.vlan_dei,
        }

    # -----------------------------------------------------------------
    # Protocol helpers
    # -----------------------------------------------------------------

    def is_tcp(self) -> bool:
        return self.transport_protocol == "TCP"

    def is_udp(self) -> bool:
        return self.transport_protocol == "UDP"

    def is_icmp(self) -> bool:
        return self.transport_protocol == "ICMP"

    def is_suspicious_port_scan(self) -> bool:
        """Heuristic: SYN without ACK might indicate a probe."""
        return self.tcp_syn and not self.tcp_ack

    def is_dns(self) -> bool:
        return self.application_protocol == "DNS"

    def is_http(self) -> bool:
        return self.application_protocol == "HTTP"

    def is_https_tls(self) -> bool:
        return self.application_protocol == "TLS"

    def to_dict(self) -> dict:
        """Convert to a plain dict (useful for DB storage)."""
        d = {
            "timestamp": self.timestamp.isoformat(),
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "eth_type": self.eth_type,
            # VLAN (802.1Q)
            "vlan_id": self.vlan_id,
            "vlan_prio": self.vlan_prio,
            "vlan_dei": self.vlan_dei,
            # Layer 3
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ip_version": self.ip_version,
            "ip_ttl": self.ip_ttl,
            "ip_protocol": self.ip_protocol,
            # Layer 4
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "transport_protocol": self.transport_protocol,
            "tcp_flags": self.tcp_flags,
            "tcp_syn": self.tcp_syn,
            "tcp_ack": self.tcp_ack,
            "tcp_fin": self.tcp_fin,
            "tcp_rst": self.tcp_rst,
            "tcp_psh": self.tcp_psh,
            "tcp_urg": self.tcp_urg,
            # Metadata
            "length": self.length,
            "payload_len": self.payload_len,
            "application_protocol": self.application_protocol,
            "interface": self.interface,
            "captured_by": self.captured_by,
        }
        return d
