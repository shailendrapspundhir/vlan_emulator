"""Storage data models."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from home_net_analyzer.capture.models import CapturedPacket


class PacketRecord(BaseModel):
    """Database record for a captured packet (flattened for storage)."""

    id: int | None = None  # DB-assigned

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Layer 2
    src_mac: str | None = None
    dst_mac: str | None = None
    eth_type: int | None = None

    # Layer 3
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: int | None = None
    ip_ttl: int | None = None
    ip_protocol: int | None = None

    # Layer 4
    src_port: int | None = None
    dst_port: int | None = None
    transport_protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None

    # TCP flags
    tcp_flags: int | None = None
    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_fin: bool = False
    tcp_rst: bool = False
    tcp_psh: bool = False
    tcp_urg: bool = False

    # Metadata
    length: int = 0
    payload_len: int = 0
    application_protocol: str | None = None

    # Context
    interface: str | None = None
    captured_by: str = "scapy"

    @classmethod
    def from_captured_packet(cls, cp: "CapturedPacket") -> "PacketRecord":
        """Create a PacketRecord from a CapturedPacket."""
        d = cp.to_dict()
        return cls(
            timestamp=datetime.fromisoformat(d["timestamp"]),
            src_mac=d["src_mac"],
            dst_mac=d["dst_mac"],
            eth_type=d["eth_type"],
            src_ip=d["src_ip"],
            dst_ip=d["dst_ip"],
            ip_version=d["ip_version"],
            ip_ttl=d["ip_ttl"],
            ip_protocol=d["ip_protocol"],
            src_port=d["src_port"],
            dst_port=d["dst_port"],
            transport_protocol=d["transport_protocol"],
            tcp_flags=d["tcp_flags"],
            tcp_syn=d["tcp_syn"],
            tcp_ack=d["tcp_ack"],
            tcp_fin=d["tcp_fin"],
            tcp_rst=d["tcp_rst"],
            tcp_psh=d["tcp_psh"],
            tcp_urg=d["tcp_urg"],
            length=d["length"],
            payload_len=d["payload_len"],
            application_protocol=d["application_protocol"],
            interface=d["interface"],
            captured_by=d["captured_by"],
        )

    def to_tuple(self) -> tuple:
        """Return values as tuple for DB insertion (excludes id)."""
        return (
            self.timestamp.isoformat(),
            self.src_mac,
            self.dst_mac,
            self.eth_type,
            self.src_ip,
            self.dst_ip,
            self.ip_version,
            self.ip_ttl,
            self.ip_protocol,
            self.src_port,
            self.dst_port,
            self.transport_protocol,
            self.tcp_flags,
            int(self.tcp_syn),
            int(self.tcp_ack),
            int(self.tcp_fin),
            int(self.tcp_rst),
            int(self.tcp_psh),
            int(self.tcp_urg),
            self.length,
            self.payload_len,
            self.application_protocol,
            self.interface,
            self.captured_by,
        )
