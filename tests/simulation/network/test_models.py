"""Unit tests for network simulation models."""

import pytest

from home_net_analyzer.simulation.network.models import (
    DeviceType,
    HopLog,
    NetworkDevice,
    NetworkLink,
    NetworkTopology,
    PacketFlow,
    SimulationHost,
)


class TestSimulationHost:
    """Tests for SimulationHost model."""

    def test_basic_creation(self) -> None:
        host = SimulationHost(
            id="pc1",
            name="Test PC",
            mac="aa:bb:cc:dd:ee:01",
            ip="192.168.1.10",
            connected_switch="sw1",
            connected_port=1
        )
        assert host.id == "pc1"
        assert host.ip == "192.168.1.10"
        assert host.vlan_id is None

    def test_get_network(self) -> None:
        host = SimulationHost(
            id="pc1",
            name="Test PC",
            mac="aa:bb:cc:dd:ee:01",
            ip="192.168.1.10",
            subnet_mask="255.255.255.0",
            connected_switch="sw1",
            connected_port=1
        )
        assert host.get_network() == "192.168.1.0/24"

    def test_is_same_network_true(self) -> None:
        host = SimulationHost(
            id="pc1",
            name="Test PC",
            mac="aa:bb:cc:dd:ee:01",
            ip="192.168.1.10",
            subnet_mask="255.255.255.0",
            connected_switch="sw1",
            connected_port=1
        )
        assert host.is_same_network("192.168.1.50")

    def test_is_same_network_false(self) -> None:
        host = SimulationHost(
            id="pc1",
            name="Test PC",
            mac="aa:bb:cc:dd:ee:01",
            ip="192.168.1.10",
            subnet_mask="255.255.255.0",
            connected_switch="sw1",
            connected_port=1
        )
        assert not host.is_same_network("192.168.2.50")

    def test_with_vlan(self) -> None:
        host = SimulationHost(
            id="pc1",
            name="Test PC",
            mac="aa:bb:cc:dd:ee:01",
            ip="192.168.10.10",
            vlan_id=10,
            connected_switch="sw1",
            connected_port=1
        )
        assert host.vlan_id == 10


class TestNetworkDevice:
    """Tests for NetworkDevice model."""

    def test_switch_device(self) -> None:
        device = NetworkDevice(
            id="sw1",
            name="Core Switch",
            device_type=DeviceType.SWITCH
        )
        assert device.device_type == DeviceType.SWITCH
        assert device.id == "sw1"

    def test_router_device(self) -> None:
        device = NetworkDevice(
            id="r1",
            name="Edge Router",
            device_type=DeviceType.ROUTER
        )
        assert device.device_type == DeviceType.ROUTER

    def test_device_hash_and_equality(self) -> None:
        d1 = NetworkDevice(id="sw1", name="Switch 1", device_type=DeviceType.SWITCH)
        d2 = NetworkDevice(id="sw1", name="Switch 1", device_type=DeviceType.SWITCH)
        d3 = NetworkDevice(id="sw2", name="Switch 2", device_type=DeviceType.SWITCH)

        assert d1 == d2
        assert hash(d1) == hash(d2)
        assert d1 != d3


class TestNetworkLink:
    """Tests for NetworkLink model."""

    def test_access_link(self) -> None:
        link = NetworkLink(
            from_device="sw1",
            to_device="pc1",
            from_port=1,
            to_port=1,
            link_type="access"
        )
        assert link.link_type == "access"
        assert link.vlans == []

    def test_trunk_link(self) -> None:
        link = NetworkLink(
            from_device="sw1",
            to_device="sw2",
            from_port=24,
            to_port=24,
            link_type="trunk",
            vlans=[10, 20, 30]
        )
        assert link.link_type == "trunk"
        assert link.vlans == [10, 20, 30]

    def test_link_hash(self) -> None:
        link1 = NetworkLink(
            from_device="sw1",
            to_device="sw2",
            from_port=24,
            to_port=24
        )
        link2 = NetworkLink(
            from_device="sw1",
            to_device="sw2",
            from_port=24,
            to_port=24
        )
        assert hash(link1) == hash(link2)


class TestNetworkTopology:
    """Tests for NetworkTopology model."""

    def test_add_device(self) -> None:
        topo = NetworkTopology(name="test")
        device = NetworkDevice(id="sw1", name="Switch 1", device_type=DeviceType.SWITCH)
        topo.add_device(device)

        assert "sw1" in topo.devices
        assert topo.get_device("sw1") == device

    def test_add_host(self) -> None:
        topo = NetworkTopology(name="test")
        host = SimulationHost(
            id="pc1",
            name="PC1",
            mac="aa:bb:cc:dd:ee:01",
            ip="192.168.1.10",
            connected_switch="sw1",
            connected_port=1
        )
        topo.add_host(host)

        assert "pc1" in topo.hosts
        assert topo.get_host("pc1") == host

    def test_add_link_updates_interfaces(self) -> None:
        topo = NetworkTopology(name="test")

        sw1 = NetworkDevice(id="sw1", name="Switch 1", device_type=DeviceType.SWITCH)
        sw2 = NetworkDevice(id="sw2", name="Switch 2", device_type=DeviceType.SWITCH)
        topo.add_device(sw1)
        topo.add_device(sw2)

        link = NetworkLink(
            from_device="sw1",
            to_device="sw2",
            from_port=24,
            to_port=24
        )
        topo.add_link(link)

        assert topo.devices["sw1"].interfaces["24"] == "sw2"
        assert topo.devices["sw2"].interfaces["24"] == "sw1"

    def test_find_path_direct(self) -> None:
        topo = NetworkTopology(name="test")

        sw1 = NetworkDevice(id="sw1", name="Switch 1", device_type=DeviceType.SWITCH)
        sw2 = NetworkDevice(id="sw2", name="Switch 2", device_type=DeviceType.SWITCH)
        topo.add_device(sw1)
        topo.add_device(sw2)

        topo.add_link(NetworkLink(
            from_device="sw1",
            to_device="sw2",
            from_port=24,
            to_port=24
        ))

        path = topo.find_path("sw1", "sw2")
        assert path == ["sw1", "sw2"]

    def test_find_path_multi_hop(self) -> None:
        topo = NetworkTopology(name="test")

        for i in range(1, 4):
            topo.add_device(NetworkDevice(
                id=f"sw{i}",
                name=f"Switch {i}",
                device_type=DeviceType.SWITCH
            ))

        # sw1 -- sw2 -- sw3
        topo.add_link(NetworkLink(from_device="sw1", to_device="sw2", from_port=1, to_port=1))
        topo.add_link(NetworkLink(from_device="sw2", to_device="sw3", from_port=2, to_port=1))

        path = topo.find_path("sw1", "sw3")
        assert path == ["sw1", "sw2", "sw3"]

    def test_find_path_no_path(self) -> None:
        topo = NetworkTopology(name="test")

        topo.add_device(NetworkDevice(id="sw1", name="Switch 1", device_type=DeviceType.SWITCH))
        topo.add_device(NetworkDevice(id="sw2", name="Switch 2", device_type=DeviceType.SWITCH))
        # No link between them

        path = topo.find_path("sw1", "sw2")
        assert path is None


class TestPacketFlow:
    """Tests for PacketFlow model."""

    def test_basic_creation(self) -> None:
        flow = PacketFlow(
            flow_id="flow-001",
            source_host="pc1",
            dest_host="pc2",
            source_ip="192.168.1.10",
            dest_ip="192.168.1.20",
            protocol="ICMP"
        )
        assert flow.flow_id == "flow-001"
        assert flow.protocol == "ICMP"
        assert flow.success is False
        assert flow.final_action == "pending"

    def test_add_hop(self) -> None:
        flow = PacketFlow(
            flow_id="flow-001",
            source_host="pc1",
            dest_host="pc2",
            source_ip="192.168.1.10",
            dest_ip="192.168.1.20"
        )

        hop = HopLog(
            hop_number=1,
            device_id="sw1",
            device_name="Switch 1",
            device_type=DeviceType.SWITCH,
            action="forward"
        )
        flow.add_hop(hop)

        assert len(flow.hops) == 1
        assert flow.hops[0].device_id == "sw1"

    def test_complete_success(self) -> None:
        flow = PacketFlow(
            flow_id="flow-001",
            source_host="pc1",
            dest_host="pc2",
            source_ip="192.168.1.10",
            dest_ip="192.168.1.20"
        )
        flow.complete(success=True, action="Delivered")

        assert flow.success is True
        assert flow.final_action == "Delivered"
        assert flow.end_time is not None

    def test_get_duration(self) -> None:
        flow = PacketFlow(
            flow_id="flow-001",
            source_host="pc1",
            dest_host="pc2",
            source_ip="192.168.1.10",
            dest_ip="192.168.1.20"
        )
        # Before completion, duration should be 0
        assert flow.get_duration_ms() == 0.0

        flow.complete(success=True, action="Delivered")
        # After completion, should have some duration
        assert flow.get_duration_ms() >= 0

    def test_to_dict(self) -> None:
        flow = PacketFlow(
            flow_id="flow-001",
            source_host="pc1",
            dest_host="pc2",
            source_ip="192.168.1.10",
            dest_ip="192.168.1.20",
            protocol="ICMP"
        )
        flow.complete(success=True, action="Delivered")

        d = flow.to_dict()
        assert d["flow_id"] == "flow-001"
        assert d["source"] == "pc1"
        assert d["destination"] == "pc2"
        assert d["protocol"] == "ICMP"
        assert d["success"] is True


class TestHopLog:
    """Tests for HopLog model."""

    def test_basic_creation(self) -> None:
        hop = HopLog(
            hop_number=1,
            device_id="sw1",
            device_name="Core Switch",
            device_type=DeviceType.SWITCH,
            action="forward",
            ingress_port=1,
            egress_port=24,
            details="MAC learning"
        )
        assert hop.hop_number == 1
        assert hop.device_id == "sw1"
        assert hop.action == "forward"

    def test_timestamp_auto_set(self) -> None:
        hop = HopLog(
            hop_number=1,
            device_id="sw1",
            device_name="Switch",
            device_type=DeviceType.SWITCH,
            action="forward"
        )
        assert hop.timestamp is not None

    def test_packet_state(self) -> None:
        hop = HopLog(
            hop_number=1,
            device_id="sw1",
            device_name="Switch",
            device_type=DeviceType.SWITCH,
            action="forward",
            packet_state={"vlan_id": 10, "src_mac": "aa:bb:cc:dd:ee:01"}
        )
        assert hop.packet_state["vlan_id"] == 10
