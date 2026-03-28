"""Unit tests for PacketParser."""

import pytest
from unittest.mock import MagicMock

from home_net_analyzer.capture.parser import PacketParser
from home_net_analyzer.capture.models import CapturedPacket


class TestPacketParserBasics:
    """Basic parser construction and empty packet handling."""

    def test_default_construction(self) -> None:
        p = PacketParser()
        assert p.parse_raw_payload is False
        assert p.max_payload_bytes == 512

    def test_custom_options(self) -> None:
        p = PacketParser(parse_raw_payload=True, max_payload_bytes=1024)
        assert p.parse_raw_payload is True
        assert p.max_payload_bytes == 1024


class TestPacketParserWithMockScapy:
    """Tests using mocked scapy packets."""

    def _make_mock_packet(self, **layers: dict) -> MagicMock:
        """Create a MagicMock that simulates a scapy packet with given layers."""
        pkt = MagicMock()
        # haslayer returns True if key is in layers
        pkt.haslayer.side_effect = lambda L: L.__name__ in layers
        # Indexing returns a MagicMock configured for that layer
        def getitem(key: type) -> MagicMock:
            name = key.__name__
            layer_data = layers.get(name, {})
            m = MagicMock()
            for k, v in layer_data.items():
                setattr(m, k, v)
            return m

        pkt.__getitem__ = lambda self, key: getitem(key)
        pkt.time = 1700000000.0
        pkt.__len__ = lambda s: layers.get("len", 100)
        return pkt

    def test_parse_ipv4_tcp(self) -> None:
        parser = PacketParser()
        pkt = self._make_mock_packet(
            Ether={"src": "aa:bb:cc:dd:ee:01", "dst": "11:22:33:44:55:01", "type": 0x0800},
            IP={"src": "192.168.1.10", "dst": "93.184.216.34", "ttl": 64, "proto": 6, "len": 200},
            TCP={"sport": 54321, "dport": 443, "flags": 0x02},  # SYN
            len=200,
        )
        cp = parser.parse(pkt, interface="eth0")

        assert cp.src_ip == "192.168.1.10"
        assert cp.dst_ip == "93.184.216.34"
        assert cp.ip_version == 4
        assert cp.transport_protocol == "TCP"
        assert cp.src_port == 54321
        assert cp.dst_port == 443
        assert cp.tcp_syn is True
        assert cp.tcp_ack is False
        assert cp.application_protocol == "TLS"  # port 443
        assert cp.interface == "eth0"
        assert cp.captured_by == "scapy"

    def test_parse_ipv4_udp_dns(self) -> None:
        parser = PacketParser()
        pkt = self._make_mock_packet(
            Ether={"src": "aa:bb:cc:dd:ee:02", "dst": "11:22:33:44:55:02", "type": 0x0800},
            IP={"src": "10.0.0.5", "dst": "8.8.8.8", "ttl": 128, "proto": 17, "len": 60},
            UDP={"sport": 54321, "dport": 53},
            DNS={},  # explicit DNS layer
            len=60,
        )
        cp = parser.parse(pkt)
        assert cp.transport_protocol == "UDP"
        assert cp.src_port == 54321
        assert cp.dst_port == 53
        assert cp.application_protocol == "DNS"
        assert cp.is_dns() is True

    def test_parse_ipv4_icmp(self) -> None:
        parser = PacketParser()
        pkt = self._make_mock_packet(
            Ether={"src": "aa:bb:cc:dd:ee:03", "dst": "11:22:33:44:55:03", "type": 0x0800},
            IP={"src": "192.168.0.1", "dst": "192.168.0.2", "ttl": 64, "proto": 1, "len": 42},
            ICMP={},
            len=42,
        )
        cp = parser.parse(pkt)
        assert cp.transport_protocol == "ICMP"
        assert cp.is_icmp() is True

    def test_parse_ipv6_tcp(self) -> None:
        parser = PacketParser()
        pkt = self._make_mock_packet(
            IPv6={"src": "2001:db8::1", "dst": "2001:db8::2", "hlim": 64, "nh": 6},
            TCP={"sport": 22, "dport": 54321, "flags": 0x18},  # PSH+ACK
            len=100,
        )
        cp = parser.parse(pkt)
        assert cp.ip_version == 6
        assert cp.src_ip == "2001:db8::1"
        assert cp.dst_ip == "2001:db8::2"
        assert cp.transport_protocol == "TCP"
        assert cp.application_protocol == "SSH"

    def test_parse_ipv6_udp(self) -> None:
        parser = PacketParser()
        pkt = self._make_mock_packet(
            IPv6={"src": "fe80::1", "dst": "ff02::1", "hlim": 255, "nh": 17},
            UDP={"sport": 5353, "dport": 5353},
            len=100,
        )
        cp = parser.parse(pkt)
        assert cp.ip_version == 6
        assert cp.transport_protocol == "UDP"

    def test_parse_non_ip_fallback(self) -> None:
        parser = PacketParser()
        # Packet with only Ether layer (e.g., ARP or raw)
        pkt = self._make_mock_packet(
            Ether={"src": "aa:bb:cc:dd:ee:ff", "dst": "ff:ff:ff:ff:ff:ff", "type": 0x0806},
            len=42,
        )
        cp = parser.parse(pkt)
        assert cp.src_mac == "aa:bb:cc:dd:ee:ff"
        assert cp.eth_type == 0x0806
        assert cp.length == 42
        # No IP layer, so ip fields stay None
        assert cp.src_ip is None

    def test_payload_extraction_when_enabled(self) -> None:
        parser = PacketParser(parse_raw_payload=True, max_payload_bytes=10)
        pkt = self._make_mock_packet(
            Ether={"src": "aa:bb", "dst": "cc:dd", "type": 0x0800},
            IP={"src": "1.1.1.1", "dst": "2.2.2.2", "ttl": 64, "proto": 17, "len": 50},
            UDP={"sport": 1234, "dport": 5678},
            Raw={"load": b"hello world payload"},
            len=50,
        )
        cp = parser.parse(pkt)
        assert cp.payload == b"hello worl"  # truncated to 10 bytes
        assert cp.payload_len == 10

    def test_payload_not_extracted_by_default(self) -> None:
        parser = PacketParser(parse_raw_payload=False)
        pkt = self._make_mock_packet(
            Ether={"src": "aa:bb", "dst": "cc:dd", "type": 0x0800},
            IP={"src": "1.1.1.1", "dst": "2.2.2.2", "ttl": 64, "proto": 17, "len": 50},
            UDP={"sport": 1234, "dport": 5678},
            Raw={"load": b"secret"},
            len=50,
        )
        cp = parser.parse(pkt)
        assert cp.payload is None
        assert cp.payload_len == 0
