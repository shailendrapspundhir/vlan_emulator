"""Unit tests for RouterEngine."""

import pytest

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.simulation.router.engine import ForwardingDecision, RouterEngine
from home_net_analyzer.simulation.router.models import (
    RouteEntry,
    RouteType,
    RouterInterface,
    SVI,
)


@pytest.fixture
def basic_router() -> RouterEngine:
    """Create a basic router with two SVIs."""
    router = RouterEngine(name="test-router")

    # Add SVIs for VLAN routing
    router.add_svi(SVI(
        vlan_id=10,
        ip_address="192.168.10.1",
        subnet_mask="255.255.255.0",
        mac_address="aa:bb:cc:00:00:10"
    ))
    router.add_svi(SVI(
        vlan_id=20,
        ip_address="192.168.20.1",
        subnet_mask="255.255.255.0",
        mac_address="aa:bb:cc:00:00:20"
    ))

    # Add physical interface
    router.add_physical_interface(RouterInterface(
        name="eth0",
        ip_address="10.0.0.1",
        subnet_mask="255.255.255.0",
        mac_address="aa:bb:cc:00:00:01"
    ))

    return router


class TestRouterEngineBasic:
    """Basic tests for RouterEngine."""

    def test_engine_creation(self) -> None:
        router = RouterEngine(name="test-router")
        assert router.name == "test-router"
        assert router.stats.packets_received == 0

    def test_add_svi_creates_connected_route(self, basic_router: RouterEngine) -> None:
        routes = basic_router.get_routes()
        svi_routes = [r for r in routes if r.interface.startswith("Vlan")]
        assert len(svi_routes) == 2

        vlan10_route = [r for r in svi_routes if r.interface == "Vlan10"][0]
        assert vlan10_route.destination == "192.168.10.0/24"
        assert vlan10_route.route_type == RouteType.CONNECTED

    def test_add_physical_interface_creates_route(self, basic_router: RouterEngine) -> None:
        routes = basic_router.get_routes()
        eth_route = [r for r in routes if r.interface == "eth0"][0]
        assert eth_route.destination == "10.0.0.0/24"
        assert eth_route.route_type == RouteType.CONNECTED


class TestRouterEnginePacketProcessing:
    """Tests for packet processing."""

    def test_packet_for_router_itself(self, basic_router: RouterEngine) -> None:
        # Learn ARP first
        basic_router.learn_arp("192.168.10.50", "aa:bb:cc:dd:ee:01", "Vlan10")

        packet = CapturedPacket(
            src_ip="192.168.10.50",
            dst_ip="192.168.10.1",  # Router's SVI IP
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:00:00:10"
        )

        decision = basic_router.process_packet(packet, "Vlan10")

        assert decision.action == "deliver_local"
        assert basic_router.stats.packets_to_self == 1

    def test_inter_vlan_routing(self, basic_router: RouterEngine) -> None:
        # Learn ARP entries for both VLANs
        basic_router.learn_arp("192.168.10.50", "aa:bb:cc:dd:ee:01", "Vlan10")
        basic_router.learn_arp("192.168.20.50", "aa:bb:cc:dd:ee:02", "Vlan20")

        # Send packet from VLAN 10 to VLAN 20
        packet = CapturedPacket(
            src_ip="192.168.10.50",
            dst_ip="192.168.20.50",
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:00:00:10"  # Router's MAC
        )

        decision = basic_router.process_packet(packet, "Vlan10")

        assert decision.action == "forward"
        assert decision.outgoing_interface == "Vlan20"
        assert decision.next_hop_ip == "192.168.20.50"
        assert decision.next_hop_mac == "aa:bb:cc:dd:ee:02"

    def test_no_route_to_destination(self, basic_router: RouterEngine) -> None:
        packet = CapturedPacket(
            src_ip="192.168.10.50",
            dst_ip="172.16.0.1",  # No route to this network
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:00:00:10"
        )

        decision = basic_router.process_packet(packet, "Vlan10")

        assert decision.action == "drop"
        assert "No route" in decision.reason
        assert basic_router.stats.routing_failures == 1

    def test_arp_resolution_failure(self, basic_router: RouterEngine) -> None:
        # Don't learn ARP - should fail resolution

        packet = CapturedPacket(
            src_ip="192.168.10.50",
            dst_ip="192.168.20.50",
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:00:00:10"
        )

        decision = basic_router.process_packet(packet, "Vlan10")

        assert decision.action == "drop"
        assert "ARP resolution failed" in decision.reason
        assert basic_router.stats.arp_failures == 1

    def test_default_route(self, basic_router: RouterEngine) -> None:
        # Add default route
        basic_router.add_route(RouteEntry(
            destination="0.0.0.0/0",
            next_hop="10.0.0.254",
            interface="eth0",
            metric=1
        ))

        # Learn ARP for next hop
        basic_router.learn_arp("10.0.0.254", "aa:bb:cc:dd:ee:ff", "eth0")

        packet = CapturedPacket(
            src_ip="192.168.10.50",
            dst_ip="8.8.8.8",  # Internet destination
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:00:00:10"
        )

        decision = basic_router.process_packet(packet, "Vlan10")

        assert decision.action == "forward"
        assert decision.outgoing_interface == "eth0"
        assert decision.next_hop_ip == "10.0.0.254"


class TestRouterEngineStaticRoutes:
    """Tests for static route handling."""

    def test_add_static_route(self, basic_router: RouterEngine) -> None:
        basic_router.add_route(RouteEntry(
            destination="10.10.0.0/16",
            next_hop="10.0.0.2",
            interface="eth0",
            metric=1
        ))

        routes = basic_router.get_routes()
        static_routes = [r for r in routes if r.route_type == RouteType.STATIC]
        assert len(static_routes) == 1
        assert static_routes[0].destination == "10.10.0.0/16"

    def test_remove_static_route(self, basic_router: RouterEngine) -> None:
        basic_router.add_route(RouteEntry(
            destination="10.10.0.0/16",
            next_hop="10.0.0.2",
            interface="eth0",
            metric=1
        ))

        removed = basic_router.remove_route("10.10.0.0/16")
        assert removed

        routes = basic_router.get_routes()
        static_routes = [r for r in routes if r.route_type == RouteType.STATIC]
        assert len(static_routes) == 0


class TestRouterEngineARP:
    """Tests for ARP functionality."""

    def test_learn_arp(self, basic_router: RouterEngine) -> None:
        basic_router.learn_arp("192.168.10.50", "aa:bb:cc:dd:ee:01", "Vlan10")

        entries = basic_router.get_arp_entries()
        assert len(entries) == 1
        assert entries[0]["ip"] == "192.168.10.50"
        assert entries[0]["mac"] == "aa:bb:cc:dd:ee:01"

    def test_arp_lookup(self, basic_router: RouterEngine) -> None:
        basic_router.learn_arp("192.168.10.50", "aa:bb:cc:dd:ee:01", "Vlan10")

        mac = basic_router.arp_table.resolve("192.168.10.50")
        assert mac == "aa:bb:cc:dd:ee:01"

    def test_clear_arp_table(self, basic_router: RouterEngine) -> None:
        basic_router.learn_arp("192.168.10.50", "aa:bb:cc:dd:ee:01", "Vlan10")
        basic_router.learn_arp("192.168.20.50", "aa:bb:cc:dd:ee:02", "Vlan20")

        cleared = basic_router.clear_arp_table()
        assert cleared == 2
        assert len(basic_router.get_arp_entries()) == 0


class TestRouterEngineStats:
    """Tests for statistics."""

    def test_stats_tracking(self, basic_router: RouterEngine) -> None:
        # Learn ARP
        basic_router.learn_arp("192.168.10.50", "aa:bb:cc:dd:ee:01", "Vlan10")
        basic_router.learn_arp("192.168.20.50", "aa:bb:cc:dd:ee:02", "Vlan20")

        # Send inter-VLAN packet
        packet = CapturedPacket(
            src_ip="192.168.10.50",
            dst_ip="192.168.20.50",
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:00:00:10"
        )
        basic_router.process_packet(packet, "Vlan10")

        stats = basic_router.get_stats()
        assert stats["packets_received"] == 1
        assert stats["packets_forwarded"] == 1
        assert stats["router_name"] == "test-router"
        assert stats["svi_count"] == 2


class TestRouterEngineSVI:
    """Tests for SVI functionality."""

    def test_get_svi(self, basic_router: RouterEngine) -> None:
        svi = basic_router.get_svi(10)
        assert svi is not None
        assert svi.vlan_id == 10
        assert svi.ip_address == "192.168.10.1"

    def test_get_svi_for_network(self, basic_router: RouterEngine) -> None:
        svi = basic_router.get_svi_for_network("192.168.10.50")
        assert svi is not None
        assert svi.vlan_id == 10

        svi = basic_router.get_svi_for_network("192.168.20.50")
        assert svi is not None
        assert svi.vlan_id == 20

        svi = basic_router.get_svi_for_network("10.0.0.50")
        assert svi is None  # Physical interface, not SVI


class TestRouterEngineInterface:
    """Tests for interface handling."""

    def test_get_physical_interface(self, basic_router: RouterEngine) -> None:
        iface = basic_router.get_interface("eth0")
        assert iface is not None
        assert iface.name == "eth0"

    def test_get_svi_interface(self, basic_router: RouterEngine) -> None:
        iface = basic_router.get_interface("Vlan10")
        assert iface is not None
        assert isinstance(iface, SVI)
        assert iface.vlan_id == 10

    def test_get_nonexistent_interface(self, basic_router: RouterEngine) -> None:
        iface = basic_router.get_interface("eth99")
        assert iface is None
