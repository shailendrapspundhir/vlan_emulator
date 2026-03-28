"""Unit tests for CapturedPacket model."""

import pytest
from datetime import datetime, timezone

from home_net_analyzer.capture.models import CapturedPacket


class TestCapturedPacketBasics:
    """Basic model construction and defaults."""

    def test_default_construction(self) -> None:
        cp = CapturedPacket()
        assert cp.length == 0
        assert cp.src_ip is None
        assert cp.dst_ip is None
        assert cp.transport_protocol is None
        assert cp.tcp_syn is False
        assert isinstance(cp.timestamp, datetime)

    def test_timestamp_is_utc(self) -> None:
        cp = CapturedPacket()
        assert cp.timestamp.tzinfo is not None
        assert cp.timestamp.tzinfo == timezone.utc

    def test_custom_values(self) -> None:
        cp = CapturedPacket(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            transport_protocol="TCP",
            src_port=54321,
            dst_port=443,
            length=1500,
        )
        assert cp.src_ip == "192.168.1.1"
        assert cp.dst_ip == "10.0.0.1"
        assert cp.transport_protocol == "TCP"
        assert cp.src_port == 54321
        assert cp.dst_port == 443
        assert cp.length == 1500


class TestCapturedPacketMethods:
    """Helper methods on CapturedPacket."""

    def test_is_tcp(self) -> None:
        cp = CapturedPacket(transport_protocol="TCP")
        assert cp.is_tcp() is True
        assert cp.is_udp() is False
        assert cp.is_icmp() is False

    def test_is_udp(self) -> None:
        cp = CapturedPacket(transport_protocol="UDP")
        assert cp.is_tcp() is False
        assert cp.is_udp() is True
        assert cp.is_icmp() is False

    def test_is_icmp(self) -> None:
        cp = CapturedPacket(transport_protocol="ICMP")
        assert cp.is_icmp() is True
        assert cp.is_tcp() is False
        assert cp.is_udp() is False

    def test_is_suspicious_port_scan_true(self) -> None:
        cp = CapturedPacket(tcp_syn=True, tcp_ack=False)
        assert cp.is_suspicious_port_scan() is True

    def test_is_suspicious_port_scan_false_syn_ack(self) -> None:
        cp = CapturedPacket(tcp_syn=True, tcp_ack=True)
        assert cp.is_suspicious_port_scan() is False

    def test_is_dns(self) -> None:
        cp = CapturedPacket(application_protocol="DNS")
        assert cp.is_dns() is True
        assert cp.is_http() is False

    def test_is_http(self) -> None:
        cp = CapturedPacket(application_protocol="HTTP")
        assert cp.is_http() is True
        assert cp.is_https_tls() is False

    def test_is_https_tls(self) -> None:
        cp = CapturedPacket(application_protocol="TLS")
        assert cp.is_https_tls() is True


class TestCapturedPacketSerialization:
    """to_dict and field completeness."""

    def test_to_dict_contains_expected_keys(self) -> None:
        cp = CapturedPacket(
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            transport_protocol="TCP",
            length=100,
        )
        d = cp.to_dict()
        assert "timestamp" in d
        assert "src_ip" in d
        assert "dst_ip" in d
        assert "transport_protocol" in d
        assert "length" in d
        assert d["src_ip"] == "1.2.3.4"
        assert d["dst_ip"] == "5.6.7.8"

    def test_to_dict_timestamp_is_iso_string(self) -> None:
        cp = CapturedPacket()
        d = cp.to_dict()
        # Should be parseable as ISO format
        parsed = datetime.fromisoformat(d["timestamp"])
        assert isinstance(parsed, datetime)
