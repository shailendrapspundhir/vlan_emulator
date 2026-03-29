"""Unit tests for traffic generation: TrafficFlow, TrafficScenario, TrafficGenerator."""

import pytest

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.simulation.traffic import TrafficFlow, TrafficGenerator, TrafficScenario


class TestTrafficFlow:
    """Tests for TrafficFlow model."""

    def test_basic(self) -> None:
        f = TrafficFlow(src="a", dst="b", protocol="tcp", dst_port=80, count=5)
        assert f.src == "a"
        assert f.dst == "b"
        assert f.protocol == "tcp"
        assert f.dst_port == 80
        assert f.count == 5

    def test_defaults(self) -> None:
        f = TrafficFlow(src="x", dst="y")
        assert f.protocol == "tcp"
        assert f.count == 1
        assert f.src_port is None
        assert f.app is None

    def test_vlan(self) -> None:
        f = TrafficFlow(src="a", dst="b", vlan_id=100)
        assert f.vlan_id == 100

    def test_invalid_port(self) -> None:
        with pytest.raises(ValueError):
            TrafficFlow(src="a", dst="b", dst_port=70000)

    def test_invalid_count(self) -> None:
        with pytest.raises(ValueError):
            TrafficFlow(src="a", dst="b", count=0)


class TestTrafficScenario:
    """Tests for TrafficScenario model."""

    def test_empty(self) -> None:
        s = TrafficScenario(name="empty")
        assert s.name == "empty"
        assert s.flows == []

    def test_with_flows(self) -> None:
        f1 = TrafficFlow(src="c", dst="s", protocol="udp", dst_port=53, app="DNS")
        f2 = TrafficFlow(src="c", dst="s", protocol="tcp", dst_port=80, app="HTTP")
        s = TrafficScenario(name="web", description="Web browsing", flows=[f1, f2])
        assert len(s.flows) == 2
        assert s.flows[0].app == "DNS"

    def test_to_dict(self) -> None:
        s = TrafficScenario(name="t", flows=[TrafficFlow(src="a", dst="b")])
        d = s.to_dict()
        assert d["name"] == "t"
        assert len(d["flows"]) == 1


class TestTrafficGenerator:
    """Tests for TrafficGenerator."""

    def test_generate_flow_tcp(self) -> None:
        gen = TrafficGenerator()
        f = TrafficFlow(src="client", dst="server", protocol="tcp", dst_port=22, count=3, app="SSH")
        pkts = gen.generate_flow(f)
        assert len(pkts) == 3
        # First packet should be SYN
        assert pkts[0].tcp_syn is True
        assert pkts[0].transport_protocol == "TCP"
        assert pkts[0].application_protocol == "SSH"
        assert pkts[0].dst_port == 22
        # Subsequent packets ACK
        assert pkts[1].tcp_ack is True

    def test_generate_flow_udp(self) -> None:
        gen = TrafficGenerator()
        f = TrafficFlow(src="c", dst="dns", protocol="udp", dst_port=53, count=2, app="DNS")
        pkts = gen.generate_flow(f)
        assert len(pkts) == 2
        assert all(p.transport_protocol == "UDP" for p in pkts)
        assert all(p.application_protocol == "DNS" for p in pkts)

    def test_generate_flow_icmp(self) -> None:
        gen = TrafficGenerator()
        f = TrafficFlow(src="a", dst="b", protocol="icmp", count=4)
        pkts = gen.generate_flow(f)
        assert len(pkts) == 4
        assert all(p.transport_protocol == "ICMP" for p in pkts)

    def test_generate_flow_vlan_tagged(self) -> None:
        gen = TrafficGenerator()
        f = TrafficFlow(src="a", dst="b", vlan_id=42, count=1)
        pkts = gen.generate_flow(f)
        assert pkts[0].vlan_id == 42
        assert pkts[0].is_vlan_tagged() is True

    def test_generate_flow_app_ports(self) -> None:
        gen = TrafficGenerator()
        # HTTP should auto-assign port 80 if dst_port not given
        f = TrafficFlow(src="c", dst="w", protocol="tcp", app="HTTP", count=1)
        pkts = gen.generate_flow(f)
        assert pkts[0].dst_port == 80
        assert pkts[0].application_protocol == "HTTP"

    def test_generate_scenario(self) -> None:
        gen = TrafficGenerator()
        s = TrafficScenario(
            name="test",
            flows=[
                TrafficFlow(src="a", dst="b", protocol="tcp", dst_port=80, count=2),
                TrafficFlow(src="b", dst="a", protocol="icmp", count=1),
            ],
        )
        pkts = gen.generate_scenario(s)
        assert len(pkts) == 3

    def test_generate_convenience(self) -> None:
        gen = TrafficGenerator()
        pkts = gen.generate(src="x", dst="y", protocol="tcp", dst_port=443, count=2, app="HTTPS")
        assert len(pkts) == 2
        assert pkts[0].dst_port == 443
        assert pkts[0].application_protocol == "TLS"  # HTTPS -> TLS

    def test_packets_are_captured_packets(self) -> None:
        gen = TrafficGenerator()
        f = TrafficFlow(src="a", dst="b", count=1)
        pkts = gen.generate_flow(f)
        assert isinstance(pkts[0], CapturedPacket)
        assert pkts[0].captured_by == "simulator"

    def test_resolve_ip_passthrough(self) -> None:
        gen = TrafficGenerator()
        assert gen._resolve_ip("192.168.1.1") == "192.168.1.1"

    def test_resolve_ip_from_name(self) -> None:
        gen = TrafficGenerator()
        ip = gen._resolve_ip("myhost")
        assert ip.startswith("10.0.0.")
