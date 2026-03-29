"""Unit tests for topology models: VLAN, VirtualHost, SwitchPort, VirtualSwitch, Router, Topology."""

import pytest

from home_net_analyzer.topology.models import (
    RouteEntry,
    Router,
    RouterInterface,
    SwitchPort,
    Topology,
    VirtualHost,
    VirtualSwitch,
    VLAN,
)


class TestVLAN:
    """Tests for VLAN model."""

    def test_basic(self) -> None:
        vlan = VLAN(id=10, name="Management", subnet="10.0.10.0/24", gateway="10.0.10.1")
        assert vlan.id == 10
        assert vlan.name == "Management"
        assert vlan.subnet == "10.0.10.0/24"
        assert vlan.gateway == "10.0.10.1"

    def test_invalid_id_low(self) -> None:
        with pytest.raises(ValueError):
            VLAN(id=0, name="X", subnet="10.0.0.0/24", gateway="10.0.0.1")

    def test_invalid_id_high(self) -> None:
        with pytest.raises(ValueError):
            VLAN(id=4095, name="X", subnet="10.0.0.0/24", gateway="10.0.0.1")

    def test_invalid_subnet_no_slash(self) -> None:
        with pytest.raises(ValueError):
            VLAN(id=1, name="X", subnet="10.0.0.0", gateway="10.0.0.1")

    def test_invalid_gateway(self) -> None:
        with pytest.raises(ValueError):
            VLAN(id=1, name="X", subnet="10.0.0.0/24", gateway="not-an-ip")

    def test_to_dict(self) -> None:
        vlan = VLAN(id=20, name="Eng", subnet="10.0.20.0/24", gateway="10.0.20.1", description="Engineering")
        d = vlan.to_dict()
        assert d["id"] == 20
        assert d["name"] == "Eng"
        assert d["description"] == "Engineering"


class TestVirtualHost:
    """Tests for VirtualHost model."""

    def test_basic(self) -> None:
        host = VirtualHost(name="pc-01", mac="aa:bb:cc:01:00:01", ip="192.168.1.10")
        assert host.name == "pc-01"
        assert host.mac == "aa:bb:cc:01:00:01"
        assert host.ip == "192.168.1.10"
        assert host.vlan_id is None
        assert host.role == "endpoint"

    def test_with_vlan(self) -> None:
        host = VirtualHost(name="srv-01", mac="aa:bb:cc:02:00:01", ip="10.0.30.10", vlan_id=30, role="server")
        assert host.vlan_id == 30
        assert host.role == "server"

    def test_mac_normalized_lowercase(self) -> None:
        host = VirtualHost(name="x", mac="AA:BB:CC:01:00:01", ip="1.1.1.1")
        assert host.mac == "aa:bb:cc:01:00:01"

    def test_invalid_mac(self) -> None:
        with pytest.raises(ValueError):
            VirtualHost(name="x", mac="bad-mac", ip="1.1.1.1")

    def test_invalid_ip(self) -> None:
        with pytest.raises(ValueError):
            VirtualHost(name="x", mac="aa:bb:cc:01:00:01", ip="1.1.1")

    def test_to_dict(self) -> None:
        host = VirtualHost(name="h1", mac="aa:bb:cc:01:00:01", ip="1.1.1.1", vlan_id=5, description="Test")
        d = host.to_dict()
        assert d["name"] == "h1"
        assert d["vlan_id"] == 5


class TestSwitchPort:
    """Tests for SwitchPort model."""

    def test_access_port(self) -> None:
        port = SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10, connected_to="pc-01")
        assert port.mode == "access"
        assert port.access_vlan == 10
        assert port.is_access() is True
        assert port.is_trunk() is False

    def test_trunk_port(self) -> None:
        port = SwitchPort(id=2, name="Gi1/0/2", mode="trunk", allowed_vlans=[10, 20, 30])
        assert port.mode == "trunk"
        assert port.allowed_vlans == [10, 20, 30]
        assert port.is_trunk() is True
        assert port.is_access() is False

    def test_access_requires_vlan(self) -> None:
        with pytest.raises(ValueError):
            SwitchPort(id=1, name="p1", mode="access")  # no access_vlan

    def test_trunk_requires_allowed(self) -> None:
        with pytest.raises(ValueError):
            SwitchPort(id=1, name="p1", mode="trunk")  # empty allowed_vlans

    def test_trunk_rejects_access_vlan(self) -> None:
        with pytest.raises(ValueError):
            SwitchPort(id=1, name="p1", mode="trunk", allowed_vlans=[10], access_vlan=10)

    def test_invalid_vlan_in_allowed(self) -> None:
        with pytest.raises(ValueError):
            SwitchPort(id=1, name="p1", mode="trunk", allowed_vlans=[0])

    def test_to_dict(self) -> None:
        port = SwitchPort(id=5, name="Gi1/0/5", mode="access", access_vlan=100)
        d = port.to_dict()
        assert d["id"] == 5
        assert d["access_vlan"] == 100


class TestVirtualSwitch:
    """Tests for VirtualSwitch model."""

    def test_basic(self) -> None:
        sw = VirtualSwitch(name="core-sw-01")
        assert sw.name == "core-sw-01"
        assert sw.ports == []
        assert sw.vlans == []

    def test_with_ports_and_vlans(self) -> None:
        p1 = SwitchPort(id=1, name="p1", mode="access", access_vlan=10)
        sw = VirtualSwitch(name="sw1", ports=[p1], vlans=[10, 20])
        assert len(sw.ports) == 1
        assert sw.vlans == [10, 20]
        assert sw.get_port(1) is p1
        assert sw.get_port(999) is None
        assert sw.get_port_by_name("p1") is p1

    def test_to_dict(self) -> None:
        sw = VirtualSwitch(name="s1", vlans=[5], description="Test switch")
        d = sw.to_dict()
        assert d["name"] == "s1"
        assert d["vlans"] == [5]


class TestRouterInterface:
    """Tests for RouterInterface model."""

    def test_basic(self) -> None:
        iface = RouterInterface(name="vlan10", ip="10.0.10.1", subnet="10.0.10.0/24", vlan_id=10)
        assert iface.name == "vlan10"
        assert iface.vlan_id == 10

    def test_no_vlan(self) -> None:
        iface = RouterInterface(name="eth0", ip="192.168.1.1", subnet="192.168.1.0/24")
        assert iface.vlan_id is None

    def test_invalid_ip(self) -> None:
        with pytest.raises(ValueError):
            RouterInterface(name="x", ip="bad", subnet="1.0.0.0/24")

    def test_invalid_subnet(self) -> None:
        with pytest.raises(ValueError):
            RouterInterface(name="x", ip="1.1.1.1", subnet="1.0.0.0")


class TestRouteEntry:
    """Tests for RouteEntry model."""

    def test_basic(self) -> None:
        r = RouteEntry(destination="10.0.0.0/8", next_hop="192.168.1.254", interface="eth0")
        assert r.destination == "10.0.0.0/8"
        assert r.next_hop == "192.168.1.254"

    def test_invalid_destination(self) -> None:
        with pytest.raises(ValueError):
            RouteEntry(destination="10.0.0.0", next_hop="1.1.1.1", interface="eth0")

    def test_invalid_next_hop(self) -> None:
        with pytest.raises(ValueError):
            RouteEntry(destination="10.0.0.0/8", next_hop="bad", interface="eth0")


class TestRouter:
    """Tests for Router model."""

    def test_basic(self) -> None:
        r = Router(name="gw-01")
        assert r.name == "gw-01"
        assert r.interfaces == []
        assert r.routing_table == []

    def test_get_interface(self) -> None:
        iface = RouterInterface(name="vlan10", ip="10.0.10.1", subnet="10.0.10.0/24")
        r = Router(name="gw", interfaces=[iface])
        assert r.get_interface("vlan10") is iface
        assert r.get_interface("missing") is None

    def test_to_dict(self) -> None:
        r = Router(name="gw", description="Main router")
        d = r.to_dict()
        assert d["name"] == "gw"
        assert d["description"] == "Main router"


class TestTopology:
    """Tests for full Topology model."""

    def test_empty(self) -> None:
        topo = Topology(name="EmptyNet")
        assert topo.name == "EmptyNet"
        assert topo.vlans == []
        assert topo.hosts == []
        assert topo.switches == []
        assert topo.routers == []

    def test_getters(self) -> None:
        vlan = VLAN(id=10, name="V10", subnet="10.0.10.0/24", gateway="10.0.10.1")
        host = VirtualHost(name="h1", mac="aa:bb:cc:01:00:01", ip="10.0.10.10", vlan_id=10)
        sw = VirtualSwitch(name="sw1")
        rtr = Router(name="gw1")
        topo = Topology(name="Test", vlans=[vlan], hosts=[host], switches=[sw], routers=[rtr])

        assert topo.get_vlan(10) is vlan
        assert topo.get_vlan(999) is None
        assert topo.get_host("h1") is host
        assert topo.get_host("missing") is None
        assert topo.get_switch("sw1") is sw
        assert topo.get_router("gw1") is rtr

    def test_to_dict(self) -> None:
        topo = Topology(name="Net", description="A network")
        d = topo.to_dict()
        assert d["name"] == "Net"
        assert d["description"] == "A network"
        assert "vlans" in d and "hosts" in d and "switches" in d and "routers" in d
