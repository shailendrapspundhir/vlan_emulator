"""Unit tests for protocol simulations."""

import pytest

from home_net_analyzer.simulation.network.protocols import (
    DHCPTransaction,
    DHCPState,
    DNSEntry,
    DNSResolver,
    DNSQuery,
    HTTPEndpoint,
    HTTPServer,
    ICMPPing,
    ProtocolSimulator,
)


class TestDHCPTransaction:
    """Tests for DHCP transaction simulation."""

    def test_basic_creation(self) -> None:
        dhcp = DHCPTransaction(client_mac="aa:bb:cc:dd:ee:01")
        assert dhcp.client_mac == "aa:bb:cc:dd:ee:01"
        assert dhcp.state == DHCPState.INIT

    def test_simulate_dhcp_success(self) -> None:
        dhcp = DHCPTransaction(client_mac="aa:bb:cc:dd:ee:01")
        result = dhcp.simulate_dhcp(
            subnet="192.168.1.0/24",
            gateway="192.168.1.1"
        )

        assert result["success"] is True
        assert "ip" in result
        assert result["gateway"] == "192.168.1.1"
        assert len(result["steps"]) == 4  # DORA process

    def test_dhcp_steps_content(self) -> None:
        dhcp = DHCPTransaction(client_mac="aa:bb:cc:dd:ee:01")
        result = dhcp.simulate_dhcp(
            subnet="192.168.1.0/24",
            gateway="192.168.1.1"
        )

        steps = result["steps"]
        assert steps[0]["message"] == "DHCPDISCOVER"
        assert steps[1]["message"] == "DHCPOFFER"
        assert steps[2]["message"] == "DHCPREQUEST"
        assert steps[3]["message"] == "DHCPACK"

    def test_assigned_ip_in_subnet(self) -> None:
        dhcp = DHCPTransaction(client_mac="aa:bb:cc:dd:ee:01")
        result = dhcp.simulate_dhcp(
            subnet="192.168.1.0/24",
            gateway="192.168.1.1"
        )

        ip = result["ip"]
        assert ip.startswith("192.168.1.")

    def test_final_state_bound(self) -> None:
        dhcp = DHCPTransaction(client_mac="aa:bb:cc:dd:ee:01")
        dhcp.simulate_dhcp(
            subnet="192.168.1.0/24",
            gateway="192.168.1.1"
        )
        assert dhcp.state == DHCPState.BOUND


class TestDNSResolver:
    """Tests for DNS resolver."""

    def test_add_record(self) -> None:
        resolver = DNSResolver()
        resolver.add_record("test.local", "A", "192.168.1.10")

        entries = resolver.resolve("test.local")
        assert len(entries) == 1
        assert entries[0].value == "192.168.1.10"

    def test_resolve_case_insensitive(self) -> None:
        resolver = DNSResolver()
        resolver.add_record("Test.Local", "A", "192.168.1.10")

        entries = resolver.resolve("test.local")
        assert len(entries) == 1

    def test_resolve_wrong_type(self) -> None:
        resolver = DNSResolver()
        resolver.add_record("test.local", "A", "192.168.1.10")

        entries = resolver.resolve("test.local", "AAAA")
        assert len(entries) == 0

    def test_resolve_not_found(self) -> None:
        resolver = DNSResolver()
        entries = resolver.resolve("nonexistent.local")
        assert len(entries) == 0

    def test_default_records_exist(self) -> None:
        resolver = DNSResolver()

        google = resolver.resolve("google.com")
        assert len(google) > 0

    def test_add_local_zone(self) -> None:
        resolver = DNSResolver()
        resolver.add_local_zone("corp.local", {
            "www": "192.168.1.10",
            "mail": "192.168.1.20"
        })

        www = resolver.resolve("www.corp.local")
        assert www[0].value == "192.168.1.10"


class TestDNSQuery:
    """Tests for DNS query simulation."""

    def test_successful_query(self) -> None:
        resolver = DNSResolver()
        resolver.add_record("test.local", "A", "192.168.1.10")

        query = DNSQuery(query_name="test.local")
        result = query.simulate_query(resolver)

        assert result["success"] is True
        assert len(result["answers"]) == 1

    def test_failed_query(self) -> None:
        resolver = DNSResolver()

        query = DNSQuery(query_name="nonexistent.local")
        result = query.simulate_query(resolver)

        assert result["success"] is False
        assert result["error"] == "NXDOMAIN"

    def test_query_steps(self) -> None:
        resolver = DNSResolver()
        resolver.add_record("test.local", "A", "192.168.1.10")

        query = DNSQuery(query_name="test.local")
        result = query.simulate_query(resolver)

        assert len(result["steps"]) == 2
        assert result["steps"][0]["message"] == "DNS Query"
        assert result["steps"][1]["message"] == "DNS Response"


class TestICMPPing:
    """Tests for ICMP ping simulation."""

    def test_basic_creation(self) -> None:
        ping = ICMPPing(
            source_ip="192.168.1.10",
            dest_ip="192.168.1.1",
            count=4
        )
        assert ping.source_ip == "192.168.1.10"
        assert ping.count == 4

    def test_simulate_reachable(self) -> None:
        ping = ICMPPing(
            source_ip="192.168.1.10",
            dest_ip="192.168.1.1",
            count=4
        )
        result = ping.simulate(reachable=True, latency_base=1.0)

        assert result["success"] is True
        assert result["packets_sent"] == 4
        assert result["packets_received"] == 4
        assert result["packet_loss_percent"] == 0.0

    def test_simulate_unreachable(self) -> None:
        ping = ICMPPing(
            source_ip="192.168.1.10",
            dest_ip="192.168.2.1",
            count=4
        )
        result = ping.simulate(reachable=False)

        assert result["success"] is False
        assert result["packets_received"] == 0
        assert result["packet_loss_percent"] == 100.0

    def test_simulate_with_loss(self) -> None:
        ping = ICMPPing(
            source_ip="192.168.1.10",
            dest_ip="192.168.1.1",
            count=100
        )
        result = ping.simulate(reachable=True, packet_loss_rate=0.5)

        # Should have roughly 50% loss (with randomness)
        assert result["packets_received"] < result["packets_sent"]

    def test_latency_stats(self) -> None:
        ping = ICMPPing(
            source_ip="192.168.1.10",
            dest_ip="192.168.1.1",
            count=4
        )
        result = ping.simulate(reachable=True, latency_base=5.0)

        assert result["min_time_ms"] is not None
        assert result["avg_time_ms"] is not None
        assert result["max_time_ms"] is not None
        assert result["min_time_ms"] <= result["avg_time_ms"] <= result["max_time_ms"]


class TestHTTPServer:
    """Tests for HTTP server simulation."""

    def test_basic_creation(self) -> None:
        server = HTTPServer(server_ip="192.168.1.10")
        assert server.server_ip == "192.168.1.10"
        assert "/" in [e.path for e in server.endpoints.values()]

    def test_handle_root_request(self) -> None:
        server = HTTPServer(server_ip="192.168.1.10")
        result = server.handle_request("/", "GET")

        assert result["success"] is True
        assert result["status_code"] == 200

    def test_handle_404(self) -> None:
        server = HTTPServer(server_ip="192.168.1.10")
        result = server.handle_request("/nonexistent", "GET")

        assert result["success"] is False
        assert result["status_code"] == 404

    def test_add_custom_endpoint(self) -> None:
        server = HTTPServer(server_ip="192.168.1.10")
        server.add_endpoint(HTTPEndpoint(
            path="/api/test",
            method="GET",
            status_code=200,
            response_body='{"test": true}',
            content_type="application/json"
        ))

        result = server.handle_request("/api/test", "GET")
        assert result["success"] is True
        assert result["body"] == '{"test": true}'


class TestProtocolSimulator:
    """Tests for high-level protocol simulator."""

    def test_dhcp_request(self) -> None:
        sim = ProtocolSimulator()
        result = sim.dhcp_request("aa:bb:cc:dd:ee:01", "192.168.1.0/24")

        assert result["success"] is True
        assert "ip" in result

    def test_dns_query(self) -> None:
        sim = ProtocolSimulator()
        result = sim.dns_query("google.com")

        assert result["success"] is True
        assert len(result["answers"]) > 0

    def test_ping(self) -> None:
        sim = ProtocolSimulator()
        result = sim.ping("192.168.1.10", "8.8.8.8", count=4)

        assert "packets_sent" in result
        assert result["packets_sent"] == 4

    def test_http_get_by_ip(self) -> None:
        sim = ProtocolSimulator()
        result = sim.http_get("http://93.184.216.34/")

        assert result["success"] is True
        assert result["status_code"] == 200

    def test_http_get_by_hostname(self) -> None:
        sim = ProtocolSimulator()
        result = sim.http_get("http://example.com/")

        assert result["success"] is True
        assert result["status_code"] == 200

    def test_http_get_not_found(self) -> None:
        sim = ProtocolSimulator()
        result = sim.http_get("http://192.168.255.255/")

        assert result["success"] is False
