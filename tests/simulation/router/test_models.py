"""Unit tests for router simulator models."""

import time

import pytest

from home_net_analyzer.simulation.router.models import (
    ARPEntry,
    ARPTable,
    RouteEntry,
    RouteType,
    RouterInterface,
    RoutingTable,
    SVI,
)


class TestRouteEntry:
    """Tests for RouteEntry model."""

    def test_basic_creation(self) -> None:
        route = RouteEntry(
            destination="192.168.1.0/24",
            next_hop="10.0.0.1",
            interface="eth0",
            metric=1
        )
        assert route.destination == "192.168.1.0/24"
        assert route.next_hop == "10.0.0.1"
        assert route.interface == "eth0"
        assert route.metric == 1
        assert route.route_type == RouteType.STATIC

    def test_connected_route(self) -> None:
        route = RouteEntry(
            destination="192.168.1.0/24",
            next_hop=None,
            interface="eth0",
            route_type=RouteType.CONNECTED
        )
        assert route.next_hop is None
        assert route.route_type == RouteType.CONNECTED

    def test_matches_ip_in_network(self) -> None:
        route = RouteEntry(destination="192.168.1.0/24", interface="eth0")
        assert route.matches("192.168.1.1")
        assert route.matches("192.168.1.254")
        assert not route.matches("192.168.2.1")
        assert not route.matches("10.0.0.1")

    def test_matches_default_route(self) -> None:
        route = RouteEntry(destination="0.0.0.0/0", interface="eth0")
        assert route.matches("192.168.1.1")
        assert route.matches("10.0.0.1")
        assert route.matches("8.8.8.8")

    def test_prefix_length(self) -> None:
        route24 = RouteEntry(destination="192.168.1.0/24", interface="eth0")
        assert route24.prefix_length() == 24

        route16 = RouteEntry(destination="10.0.0.0/16", interface="eth0")
        assert route16.prefix_length() == 16

        route0 = RouteEntry(destination="0.0.0.0/0", interface="eth0")
        assert route0.prefix_length() == 0

    def test_invalid_destination(self) -> None:
        with pytest.raises(ValueError):
            RouteEntry(destination="invalid", interface="eth0")

    def test_hash_and_equality(self) -> None:
        route1 = RouteEntry(destination="192.168.1.0/24", interface="eth0")
        route2 = RouteEntry(destination="192.168.1.0/24", interface="eth0")
        route3 = RouteEntry(destination="192.168.1.0/24", interface="eth1")

        assert route1 == route2
        assert hash(route1) == hash(route2)
        assert route1 != route3


class TestRoutingTable:
    """Tests for RoutingTable class."""

    def test_add_route(self) -> None:
        table = RoutingTable()
        route = RouteEntry(destination="192.168.1.0/24", interface="eth0")
        table.add_route(route)

        assert len(table.get_routes()) == 1

    def test_remove_route(self) -> None:
        table = RoutingTable()
        table.add_route(RouteEntry(destination="192.168.1.0/24", interface="eth0"))
        table.add_route(RouteEntry(destination="10.0.0.0/8", interface="eth1"))

        removed = table.remove_route("192.168.1.0/24")
        assert removed
        assert len(table.get_routes()) == 1

    def test_lookup_exact_match(self) -> None:
        table = RoutingTable()
        table.add_route(RouteEntry(destination="192.168.1.0/24", interface="eth0"))

        route = table.lookup("192.168.1.50")
        assert route is not None
        assert route.destination == "192.168.1.0/24"
        assert route.interface == "eth0"

    def test_lookup_no_match(self) -> None:
        table = RoutingTable()
        table.add_route(RouteEntry(destination="192.168.1.0/24", interface="eth0"))

        route = table.lookup("10.0.0.1")
        assert route is None

    def test_longest_prefix_match(self) -> None:
        """Test that most specific route is chosen."""
        table = RoutingTable()
        table.add_route(RouteEntry(destination="0.0.0.0/0", interface="eth0"))
        table.add_route(RouteEntry(destination="192.168.0.0/16", interface="eth1"))
        table.add_route(RouteEntry(destination="192.168.1.0/24", interface="eth2"))

        # Should match /24 route
        route = table.lookup("192.168.1.50")
        assert route.interface == "eth2"

        # Should match /16 route
        route = table.lookup("192.168.2.50")
        assert route.interface == "eth1"

        # Should match default route
        route = table.lookup("10.0.0.1")
        assert route.interface == "eth0"

    def test_metric_tiebreaker(self) -> None:
        """Test that lower metric wins when prefix length is equal."""
        table = RoutingTable()
        table.add_route(RouteEntry(destination="192.168.1.0/24", interface="eth0", metric=10))
        table.add_route(RouteEntry(destination="192.168.1.0/24", interface="eth1", metric=5))

        route = table.lookup("192.168.1.50")
        assert route.interface == "eth1"  # Lower metric

    def test_stats_tracking(self) -> None:
        table = RoutingTable()
        table.add_route(RouteEntry(destination="192.168.1.0/24", interface="eth0"))

        table.lookup("192.168.1.1")  # Hit
        table.lookup("10.0.0.1")     # Miss
        table.lookup("192.168.1.2")  # Hit

        stats = table.get_stats()
        assert stats["lookups"] == 3
        assert stats["hits"] == 2
        assert stats["misses"] == 1

    def test_clear(self) -> None:
        table = RoutingTable()
        table.add_route(RouteEntry(destination="192.168.1.0/24", interface="eth0"))
        table.add_route(RouteEntry(destination="10.0.0.0/8", interface="eth1"))

        cleared = table.clear()
        assert cleared == 2
        assert len(table.get_routes()) == 0


class TestARPEntry:
    """Tests for ARPEntry model."""

    def test_basic_creation(self) -> None:
        entry = ARPEntry(
            ip_address="192.168.1.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            interface="eth0"
        )
        assert entry.ip_address == "192.168.1.1"
        assert entry.mac_address == "aa:bb:cc:dd:ee:ff"
        assert entry.interface == "eth0"
        assert entry.entry_type == "dynamic"
        assert entry.ttl == 300

    def test_is_expired(self) -> None:
        entry = ARPEntry(
            ip_address="192.168.1.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            interface="eth0",
            ttl=1
        )
        assert not entry.is_expired()
        time.sleep(1.1)
        assert entry.is_expired()

    def test_static_not_expired(self) -> None:
        entry = ARPEntry(
            ip_address="192.168.1.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            interface="eth0",
            entry_type="static",
            ttl=0
        )
        time.sleep(0.1)
        assert not entry.is_expired()

    def test_touch_updates_timestamp(self) -> None:
        entry = ARPEntry(
            ip_address="192.168.1.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            interface="eth0",
            ttl=1
        )
        time.sleep(0.5)
        entry.touch()
        time.sleep(0.5)
        assert not entry.is_expired()

    def test_invalid_ip(self) -> None:
        with pytest.raises(ValueError):
            ARPEntry(ip_address="invalid", mac_address="aa:bb:cc:dd:ee:ff", interface="eth0")


class TestARPTable:
    """Tests for ARPTable class."""

    def test_learn_new_entry(self) -> None:
        table = ARPTable()
        entry = table.learn("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")

        assert entry.ip_address == "192.168.1.1"
        assert entry.mac_address == "aa:bb:cc:dd:ee:ff"
        assert table.get_entry_count() == 1

    def test_learn_updates_existing(self) -> None:
        table = ARPTable()
        table.learn("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")
        entry = table.learn("192.168.1.1", "11:22:33:44:55:66", "eth0")

        assert entry.mac_address == "11:22:33:44:55:66"
        assert table.get_entry_count() == 1

    def test_resolve_found(self) -> None:
        table = ARPTable()
        table.learn("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")

        mac = table.resolve("192.168.1.1")
        assert mac == "aa:bb:cc:dd:ee:ff"

    def test_resolve_not_found(self) -> None:
        table = ARPTable()
        mac = table.resolve("192.168.1.1")
        assert mac is None

    def test_resolve_with_interface(self) -> None:
        table = ARPTable()
        table.learn("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")
        table.learn("192.168.1.1", "11:22:33:44:55:66", "eth1")

        # Should find specific interface
        mac = table.resolve("192.168.1.1", "eth1")
        assert mac == "11:22:33:44:55:66"

    def test_resolve_expired(self) -> None:
        table = ARPTable(default_ttl=1)
        table.learn("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")

        time.sleep(1.1)
        mac = table.resolve("192.168.1.1")
        assert mac is None
        assert table.get_entry_count() == 0

    def test_add_static(self) -> None:
        table = ARPTable()
        table.add_static("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")

        time.sleep(0.1)
        mac = table.resolve("192.168.1.1")
        assert mac == "aa:bb:cc:dd:ee:ff"

    def test_remove(self) -> None:
        table = ARPTable()
        table.learn("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")
        table.learn("192.168.1.2", "11:22:33:44:55:66", "eth0")

        table.remove("192.168.1.1")
        assert table.get_entry_count() == 1
        assert table.resolve("192.168.1.1") is None

    def test_clear(self) -> None:
        table = ARPTable()
        table.learn("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")
        table.learn("192.168.1.2", "11:22:33:44:55:66", "eth0")

        cleared = table.clear()
        assert cleared == 2
        assert table.get_entry_count() == 0


class TestRouterInterface:
    """Tests for RouterInterface model."""

    def test_basic_creation(self) -> None:
        iface = RouterInterface(
            name="eth0",
            ip_address="192.168.1.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:dd:ee:ff"
        )
        assert iface.name == "eth0"
        assert iface.ip_address == "192.168.1.1"
        assert iface.enabled is True

    def test_get_network(self) -> None:
        iface = RouterInterface(
            name="eth0",
            ip_address="192.168.1.1",
            subnet_mask="255.255.255.0"
        )
        assert iface.get_network() == "192.168.1.0/24"

    def test_is_in_network(self) -> None:
        iface = RouterInterface(
            name="eth0",
            ip_address="192.168.1.1",
            subnet_mask="255.255.255.0"
        )
        assert iface.is_in_network("192.168.1.50")
        assert not iface.is_in_network("192.168.2.50")


class TestSVI:
    """Tests for SVI model."""

    def test_basic_creation(self) -> None:
        svi = SVI(
            vlan_id=10,
            ip_address="192.168.10.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:dd:ee:ff"
        )
        assert svi.vlan_id == 10
        assert svi.ip_address == "192.168.10.1"
        assert svi.get_interface_name() == "Vlan10"

    def test_get_network(self) -> None:
        svi = SVI(
            vlan_id=10,
            ip_address="192.168.10.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:dd:ee:ff"
        )
        assert svi.get_network() == "192.168.10.0/24"

    def test_is_in_network(self) -> None:
        svi = SVI(
            vlan_id=10,
            ip_address="192.168.10.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:dd:ee:ff"
        )
        assert svi.is_in_network("192.168.10.50")
        assert not svi.is_in_network("192.168.20.50")

    def test_to_route_entry(self) -> None:
        svi = SVI(
            vlan_id=10,
            ip_address="192.168.10.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:dd:ee:ff"
        )
        route = svi.to_route_entry()
        assert route.destination == "192.168.10.0/24"
        assert route.interface == "Vlan10"
        assert route.route_type == RouteType.CONNECTED
        assert route.next_hop is None

    def test_invalid_vlan(self) -> None:
        with pytest.raises(ValueError):
            SVI(vlan_id=0, ip_address="192.168.1.1", subnet_mask="255.255.255.0", mac_address="aa:bb:cc:dd:ee:ff")

    def test_invalid_ip(self) -> None:
        with pytest.raises(ValueError):
            SVI(vlan_id=10, ip_address="invalid", subnet_mask="255.255.255.0", mac_address="aa:bb:cc:dd:ee:ff")
