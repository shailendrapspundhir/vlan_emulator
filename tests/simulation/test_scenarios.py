"""Unit tests for pre-built traffic scenarios."""

import pytest

from home_net_analyzer.simulation import (
    SCENARIOS,
    get_scenario,
    list_scenarios,
    TrafficGenerator,
)


class TestScenariosRegistry:
    """Tests for the SCENARIOS registry."""

    def test_list_scenarios(self) -> None:
        names = list_scenarios()
        assert "web_browsing" in names
        assert "dns_resolution" in names
        assert "inter_vlan_ping" in names
        assert "port_scan" in names
        assert "file_transfer" in names
        assert "ssh_admin" in names
        assert "https_browsing" in names
        assert "full_corporate" in names

    def test_get_scenario_ok(self) -> None:
        s = get_scenario("web_browsing")
        assert s.name == "web_browsing"
        assert len(s.flows) >= 1

    def test_get_scenario_unknown(self) -> None:
        with pytest.raises(KeyError):
            get_scenario("nonexistent_scenario")

    def test_scenario_has_flows(self) -> None:
        for name in list_scenarios():
            s = SCENARIOS[name]
            assert len(s.flows) >= 1, f"Scenario {name} has no flows"


class TestScenarioContents:
    """Check contents of specific scenarios."""

    def test_web_browsing(self) -> None:
        s = get_scenario("web_browsing")
        # Should have DNS + HTTP
        apps = [f.app for f in s.flows]
        assert "DNS" in apps
        assert "HTTP" in apps

    def test_dns_resolution(self) -> None:
        s = get_scenario("dns_resolution")
        assert len(s.flows) == 2
        assert s.flows[0].app == "DNS"
        assert s.flows[1].app == "DNS"

    def test_inter_vlan_ping(self) -> None:
        s = get_scenario("inter_vlan_ping")
        # Both directions across VLANs
        assert any(f.vlan_id == 10 for f in s.flows)
        assert any(f.vlan_id == 20 for f in s.flows)
        assert all(f.protocol == "icmp" for f in s.flows)

    def test_port_scan(self) -> None:
        s = get_scenario("port_scan")
        # 6 common ports
        ports = [f.dst_port for f in s.flows]
        assert 22 in ports  # SSH
        assert 80 in ports  # HTTP
        assert 443 in ports  # HTTPS

    def test_file_transfer(self) -> None:
        s = get_scenario("file_transfer")
        f = s.flows[0]
        assert f.app == "FTP"
        assert f.count >= 10  # Large transfer

    def test_full_corporate(self) -> None:
        s = get_scenario("full_corporate")
        apps = [f.app for f in s.flows]
        # Mix of protocols/apps
        assert "DNS" in apps
        assert "HTTP" in apps
        assert "HTTPS" in apps or "TLS" in apps
        assert "SSH" in apps


class TestGenerateScenarios:
    """Generate packets from pre-built scenarios."""

    def test_generate_web_browsing(self) -> None:
        gen = TrafficGenerator()
        s = get_scenario("web_browsing")
        pkts = gen.generate_scenario(s)
        assert len(pkts) > 0
        # Should include some TCP and some UDP (DNS)
        protos = {p.transport_protocol for p in pkts}
        assert "TCP" in protos
        assert "UDP" in protos

    def test_generate_port_scan(self) -> None:
        gen = TrafficGenerator()
        s = get_scenario("port_scan")
        pkts = gen.generate_scenario(s)
        # 6 ports, 1 packet each
        assert len(pkts) == 6
        assert all(p.tcp_syn for p in pkts)  # Port scan = SYN packets

    def test_generate_inter_vlan_ping(self) -> None:
        gen = TrafficGenerator()
        s = get_scenario("inter_vlan_ping")
        pkts = gen.generate_scenario(s)
        # 4 pings each direction = 8 packets
        assert len(pkts) == 8
        assert all(p.transport_protocol == "ICMP" for p in pkts)
        vlans = {p.vlan_id for p in pkts}
        assert 10 in vlans
        assert 20 in vlans
