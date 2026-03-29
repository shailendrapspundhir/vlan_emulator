"""Traffic generation: define scenarios, flows, and generate synthetic CapturedPacket objects.

This module lets you define network traffic scenarios (e.g., web browsing, DNS queries)
and generate synthetic CapturedPacket objects for testing, simulation, and storage.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from home_net_analyzer.capture.models import CapturedPacket


class TrafficFlow(BaseModel):
    """A single traffic flow between two endpoints.

    Example:
        TrafficFlow(src="eng-laptop", dst="web-server", protocol="tcp",
                    src_port=54321, dst_port=80, count=10, app="HTTP")
    """

    src: str = Field(..., description="Source host name or IP")
    dst: str = Field(..., description="Destination host name or IP")
    protocol: Literal["tcp", "udp", "icmp"] = "tcp"
    src_port: int | None = Field(None, ge=1, le=65535)
    dst_port: int | None = Field(None, ge=1, le=65535)
    count: int = Field(1, ge=1, description="Number of packets to generate")
    app: str | None = Field(None, description="Application hint (HTTP, DNS, SSH, etc.)")
    vlan_id: int | None = Field(None, ge=1, le=4094, description="VLAN tag if any")
    src_mac: str | None = Field(None, description="Source MAC (optional)")
    dst_mac: str | None = Field(None, description="Destination MAC (optional)")
    length: int = Field(64, ge=0, description="Packet length hint")

    def to_dict(self) -> dict:
        return self.model_dump()


class TrafficScenario(BaseModel):
    """A named collection of traffic flows representing a scenario.

    Example:
        TrafficScenario(name="web_browsing", description="Typical web browsing",
                        flows=[TrafficFlow(...), ...])
    """

    name: str = Field(..., min_length=1, description="Scenario name")
    description: str | None = None
    flows: list[TrafficFlow] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "flows": [f.to_dict() for f in self.flows],
        }


class TrafficGenerator:
    """Generate synthetic CapturedPacket objects from TrafficScenario/Flow definitions.

    Generated packets use the existing CapturedPacket model so they can be
    stored directly via PacketStore.
    """

    # Default port mappings for common applications
    APP_PORTS: dict[str, tuple[int, int]] = {
        "HTTP": (80, 80),
        "HTTPS": (443, 443),
        "DNS": (53, 53),
        "SSH": (22, 22),
        "TELNET": (23, 23),
        "FTP": (21, 21),
        "SMTP": (25, 25),
        "IMAP": (143, 143),
        "POP3": (110, 110),
        "RDP": (3389, 3389),
    }

    def __init__(
        self,
        *,
        default_src_mac: str = "00:11:22:33:44:55",
        default_dst_mac: str = "66:77:88:99:aa:bb",
        default_ttl: int = 64,
    ) -> None:
        self.default_src_mac = default_src_mac
        self.default_dst_mac = default_dst_mac
        self.default_ttl = default_ttl

    def generate_flow(self, flow: TrafficFlow) -> list[CapturedPacket]:
        """Generate packets for a single TrafficFlow."""
        packets: list[CapturedPacket] = []

        # Resolve ports from app hint if not provided
        src_port = flow.src_port
        dst_port = flow.dst_port
        if flow.app and (src_port is None or dst_port is None):
            ports = self.APP_PORTS.get(flow.app.upper())
            if ports:
                if dst_port is None:
                    dst_port = ports[1]
                if src_port is None:
                    # Pick an ephemeral source port
                    src_port = random.randint(49152, 65535)

        # Protocol -> transport_protocol and ip_protocol
        if flow.protocol == "tcp":
            transport_protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] = "TCP"
            ip_protocol = 6
        elif flow.protocol == "udp":
            transport_protocol = "UDP"
            ip_protocol = 17
        elif flow.protocol == "icmp":
            transport_protocol = "ICMP"
            ip_protocol = 1
        else:
            transport_protocol = "OTHER"
            ip_protocol = None

        # Determine application_protocol
        app_proto = flow.app.upper() if flow.app else None
        # Map common app names
        if app_proto == "HTTPS":
            app_proto = "TLS"

        for i in range(flow.count):
            # Build a realistic-looking packet
            pkt = CapturedPacket(
                timestamp=datetime.now(timezone.utc),
                src_mac=flow.src_mac or self.default_src_mac,
                dst_mac=flow.dst_mac or self.default_dst_mac,
                eth_type=0x0800,  # IPv4
                vlan_id=flow.vlan_id,
                src_ip=self._resolve_ip(flow.src),
                dst_ip=self._resolve_ip(flow.dst),
                ip_version=4,
                ip_ttl=self.default_ttl,
                ip_protocol=ip_protocol,
                src_port=src_port,
                dst_port=dst_port,
                transport_protocol=transport_protocol,
                length=flow.length,
                application_protocol=app_proto,
                captured_by="simulator",
            )

            # Set TCP flags for TCP flows (first packet: SYN)
            if flow.protocol == "tcp":
                if i == 0:
                    pkt.tcp_syn = True
                    pkt.tcp_flags = 0x02  # SYN
                else:
                    pkt.tcp_ack = True
                    pkt.tcp_flags = 0x10  # ACK

            packets.append(pkt)

        return packets

    def generate_scenario(self, scenario: TrafficScenario) -> list[CapturedPacket]:
        """Generate all packets for a TrafficScenario."""
        packets: list[CapturedPacket] = []
        for flow in scenario.flows:
            packets.extend(self.generate_flow(flow))
        return packets

    def _resolve_ip(self, host_or_ip: str) -> str:
        """If host_or_ip looks like an IP, return it; otherwise return a placeholder.

        In a full simulator, you'd look up the host's IP from a topology.
        For now, we pass through IPs and use a convention for names.
        """
        # Simple heuristic: if it has dots and all parts are digits or valid, treat as IP
        parts = host_or_ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return host_or_ip
        # Not an IP; use a placeholder derived from name hash (stable)
        h = abs(hash(host_or_ip)) % 250
        return f"10.0.0.{h + 1}"

    def generate(
        self,
        *,
        src: str | None = None,
        dst: str | None = None,
        protocol: Literal["tcp", "udp", "icmp"] = "tcp",
        dst_port: int | None = None,
        count: int = 1,
        app: str | None = None,
        vlan_id: int | None = None,
    ) -> list[CapturedPacket]:
        """Convenience: generate packets from simple parameters (no Scenario object needed)."""
        flow = TrafficFlow(
            src=src or "sim-src",
            dst=dst or "sim-dst",
            protocol=protocol,
            dst_port=dst_port,
            count=count,
            app=app,
            vlan_id=vlan_id,
        )
        return self.generate_flow(flow)
