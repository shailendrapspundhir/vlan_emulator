"""Packet parser: converts raw scapy packets to CapturedPacket models."""

from datetime import datetime, timezone
from typing import Any

from home_net_analyzer.capture.models import CapturedPacket


class PacketParser:
    """Parses raw scapy packets into normalized CapturedPacket objects."""

    def __init__(self, *, parse_raw_payload: bool = False, max_payload_bytes: int = 512) -> None:
        self.parse_raw_payload = parse_raw_payload
        self.max_payload_bytes = max_payload_bytes

    def parse(self, pkt: Any, *, interface: str | None = None) -> CapturedPacket:
        """Parse a scapy packet into a CapturedPacket.

        Args:
            pkt: A scapy Packet object.
            interface: Optional interface name for context.

        Returns:
            CapturedPacket with extracted fields.
        """
        from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, Raw, Ether  # type: ignore

        cp = CapturedPacket(interface=interface, captured_by="scapy")

        # Timestamp
        if hasattr(pkt, "time") and pkt.time:
            ts = float(pkt.time)
            cp.timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)

        # Layer 2 (Ethernet)
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            cp.src_mac = eth.src
            cp.dst_mac = eth.dst
            cp.eth_type = eth.type
            cp.length = len(pkt)

        # Layer 3 - IPv4
        if pkt.haslayer(IP):
            ip = pkt[IP]
            cp.src_ip = ip.src
            cp.dst_ip = ip.dst
            cp.ip_version = 4
            cp.ip_ttl = ip.ttl
            cp.ip_protocol = ip.proto
            cp.length = len(pkt)
            if not cp.length:
                cp.length = ip.len

            # Higher-level protocol detection for IP
            if cp.ip_protocol == 1:
                cp.transport_protocol = "ICMP"
            elif cp.ip_protocol == 6:
                cp.transport_protocol = "TCP"
            elif cp.ip_protocol == 17:
                cp.transport_protocol = "UDP"
            else:
                cp.transport_protocol = "OTHER"

        # Layer 3 - IPv6
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            cp.src_ip = ip6.src
            cp.dst_ip = ip6.dst
            cp.ip_version = 6
            cp.ip_ttl = ip6.hlim
            cp.ip_protocol = ip6.nh
            cp.length = len(pkt)
            if ip6.nh == 6:
                cp.transport_protocol = "TCP"
            elif ip6.nh == 17:
                cp.transport_protocol = "UDP"
            elif ip6.nh == 58:
                cp.transport_protocol = "ICMP"
            else:
                cp.transport_protocol = "OTHER"

        # Layer 4 - TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            cp.src_port = tcp.sport
            cp.dst_port = tcp.dport
            cp.transport_protocol = "TCP"
            cp.tcp_flags = tcp.flags
            cp.tcp_syn = bool(tcp.flags & 0x02)
            cp.tcp_ack = bool(tcp.flags & 0x10)
            cp.tcp_fin = bool(tcp.flags & 0x01)
            cp.tcp_rst = bool(tcp.flags & 0x04)
            cp.tcp_psh = bool(tcp.flags & 0x08)
            cp.tcp_urg = bool(tcp.flags & 0x20)

            # Application protocol hints
            if cp.dst_port == 53 or cp.src_port == 53:
                cp.application_protocol = "DNS"
            elif cp.dst_port == 80 or cp.src_port == 80:
                cp.application_protocol = "HTTP"
            elif cp.dst_port == 443 or cp.src_port == 443:
                cp.application_protocol = "TLS"
            elif cp.dst_port == 22 or cp.src_port == 22:
                cp.application_protocol = "SSH"
            elif cp.dst_port == 23 or cp.src_port == 23:
                cp.application_protocol = "TELNET"

        # Layer 4 - UDP
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            cp.src_port = udp.sport
            cp.dst_port = udp.dport
            cp.transport_protocol = "UDP"
            if cp.dst_port == 53 or cp.src_port == 53:
                cp.application_protocol = "DNS"
            elif cp.dst_port == 67 or cp.dst_port == 68:
                cp.application_protocol = "DHCP"

        # Layer 4 - ICMP
        elif pkt.haslayer(ICMP):
            cp.transport_protocol = "ICMP"
            if cp.dst_port is None:
                # For ICMP, dst_port/src_port are N/A; keep None
                pass

        # DNS detection (explicit)
        if pkt.haslayer(DNS):
            cp.application_protocol = "DNS"

        # Payload extraction
        if self.parse_raw_payload and pkt.haslayer(Raw):
            raw = pkt[Raw]
            data = bytes(raw.load) if raw.load else b""
            if len(data) > self.max_payload_bytes:
                data = data[: self.max_payload_bytes]
            cp.payload = data
            cp.payload_len = len(data)

        return cp
