"""Unit tests for SwitchEngine."""

import pytest

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.simulation.switch.engine import SwitchEngine
from home_net_analyzer.simulation.switch.models import (
    ForwardingDecision,
    SwitchFrame,
    VLANAction,
)
from home_net_analyzer.topology.models import SwitchPort, VirtualSwitch


@pytest.fixture
def simple_switch() -> VirtualSwitch:
    """Create a simple switch with 4 access ports in VLAN 10."""
    return VirtualSwitch(
        name="test-sw",
        ports=[
            SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
            SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=10),
            SwitchPort(id=3, name="Gi1/0/3", mode="access", access_vlan=10),
            SwitchPort(id=4, name="Gi1/0/4", mode="access", access_vlan=10),
        ],
        vlans=[10]
    )


@pytest.fixture
def trunk_switch() -> VirtualSwitch:
    """Create a switch with access ports and a trunk port."""
    return VirtualSwitch(
        name="trunk-sw",
        ports=[
            SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
            SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=20),
            SwitchPort(id=3, name="Gi1/0/3", mode="access", access_vlan=10),
            SwitchPort(
                id=24,
                name="Gi1/0/24",
                mode="trunk",
                allowed_vlans=[10, 20, 30]
            ),
        ],
        vlans=[10, 20, 30]
    )


class TestSwitchEngineBasic:
    """Basic tests for SwitchEngine."""

    def test_engine_creation(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)
        assert engine.switch.name == "test-sw"
        assert engine.native_vlan == 1
        assert engine.stats.frames_received == 0

    def test_process_frame_unknown_unicast(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        # Frame from port 1 to unknown destination
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:02",
            vlan_id=None  # Untagged
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=1,
            ingress_switch="test-sw"
        )

        decisions = engine.process_frame(frame)

        # Should flood to all other ports in VLAN
        assert len(decisions) == 3
        ports = {d.port_id for d in decisions}
        assert ports == {2, 3, 4}

        # MAC should be learned
        assert engine.mac_table.lookup("aa:bb:cc:dd:ee:01", 10) == 1

    def test_process_frame_known_unicast(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        # Learn a MAC first
        engine.mac_table.learn("aa:bb:cc:dd:ee:02", vlan_id=10, port_id=2)

        # Now send to that known MAC
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:02",
            vlan_id=None
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=1,
            ingress_switch="test-sw"
        )

        decisions = engine.process_frame(frame)

        # Should forward only to port 2
        assert len(decisions) == 1
        assert decisions[0].port_id == 2

    def test_process_frame_broadcast(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            vlan_id=None
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=1,
            ingress_switch="test-sw"
        )

        decisions = engine.process_frame(frame)

        # Should flood to all other ports
        assert len(decisions) == 3

    def test_process_frame_multicast(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="01:00:5e:00:00:01",  # IPv4 multicast
            vlan_id=None
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=1,
            ingress_switch="test-sw"
        )

        decisions = engine.process_frame(frame)

        # Should flood to all other ports
        assert len(decisions) == 3

    def test_same_port_not_forwarded(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        # Learn MAC on port 1
        engine.mac_table.learn("aa:bb:cc:dd:ee:02", vlan_id=10, port_id=1)

        # Send from port 2 to that MAC (also on port 1)
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:03",
            dst_mac="aa:bb:cc:dd:ee:02",
            vlan_id=None
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=2,
            ingress_switch="test-sw"
        )

        decisions = engine.process_frame(frame)

        # Should forward to port 1
        assert len(decisions) == 1
        assert decisions[0].port_id == 1

    def test_invalid_ingress_port(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:02"
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=99,  # Invalid port
            ingress_switch="test-sw"
        )

        decisions = engine.process_frame(frame)

        assert len(decisions) == 0
        assert engine.stats.port_errors == 1
        assert engine.stats.frames_dropped == 1

    def test_mac_learning(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        # Send frame from port 1
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            vlan_id=None
        )
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        engine.process_frame(frame)

        # MAC should be learned
        assert engine.mac_table.lookup("aa:bb:cc:dd:ee:01", 10) == 1

        # Send from port 2 to that MAC
        packet2 = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:02",
            dst_mac="aa:bb:cc:dd:ee:01",
            vlan_id=None
        )
        frame2 = SwitchFrame(packet=packet2, ingress_port=2, ingress_switch="test-sw")
        decisions = engine.process_frame(frame2)

        # Should forward to port 1
        assert len(decisions) == 1
        assert decisions[0].port_id == 1


class TestSwitchEngineTrunk:
    """Tests for trunk port handling."""

    def test_trunk_ingress_tagged(self, trunk_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(trunk_switch)

        # Tagged frame entering trunk port
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            vlan_id=20  # Tagged with VLAN 20
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=24,  # Trunk port
            ingress_switch="trunk-sw"
        )

        decisions = engine.process_frame(frame)

        # Should flood to ports in VLAN 20 (port 2)
        port_20 = [d for d in decisions if d.port_id == 2]
        assert len(port_20) == 1
        # Should strip tag for access port
        assert port_20[0].vlan_action == VLANAction.STRIP

    def test_trunk_ingress_untagged(self, trunk_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(trunk_switch)

        # Untagged frame entering trunk port (uses native VLAN)
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            vlan_id=None
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=24,
            ingress_switch="trunk-sw",
            native_vlan=10
        )

        decisions = engine.process_frame(frame)

        # Should flood to ports in native VLAN 10 (ports 1, 3)
        ports = {d.port_id for d in decisions}
        assert ports == {1, 3}

    def test_trunk_vlan_not_allowed(self, trunk_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(trunk_switch)

        # Tagged frame with VLAN not allowed on trunk
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            vlan_id=99  # Not in allowed list
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=24,
            ingress_switch="trunk-sw"
        )

        decisions = engine.process_frame(frame)

        # Should drop
        assert len(decisions) == 0
        assert engine.stats.vlan_errors == 1

    def test_egress_to_trunk_adds_tag(self, trunk_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(trunk_switch)

        # Learn MAC on trunk port
        engine.mac_table.learn("aa:bb:cc:dd:ee:02", vlan_id=10, port_id=24)

        # Send from access port to that MAC
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:02",
            vlan_id=None
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=1,
            ingress_switch="trunk-sw"
        )

        decisions = engine.process_frame(frame)

        assert len(decisions) == 1
        assert decisions[0].port_id == 24
        assert decisions[0].vlan_action == VLANAction.TAG
        assert decisions[0].egress_vlan == 10

    def test_access_port_with_tagged_frame(self, trunk_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(trunk_switch)

        # Tagged frame on access port should be dropped
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            vlan_id=10
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=1,  # Access port
            ingress_switch="trunk-sw"
        )

        decisions = engine.process_frame(frame)

        # Should drop
        assert len(decisions) == 0
        assert engine.stats.vlan_errors == 1


class TestSwitchEngineStats:
    """Tests for statistics tracking."""

    def test_stats_tracking(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        # Unknown unicast
        packet1 = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:02",
            vlan_id=None
        )
        engine.process_frame(SwitchFrame(packet=packet1, ingress_port=1, ingress_switch="test-sw"))

        # Broadcast
        packet2 = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:03",
            dst_mac="ff:ff:ff:ff:ff:ff",
            vlan_id=None
        )
        engine.process_frame(SwitchFrame(packet=packet2, ingress_port=2, ingress_switch="test-sw"))

        # Known unicast (after learning)
        engine.mac_table.learn("aa:bb:cc:dd:ee:05", vlan_id=10, port_id=3)
        packet3 = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:04",
            dst_mac="aa:bb:cc:dd:ee:05",
            vlan_id=None
        )
        engine.process_frame(SwitchFrame(packet=packet3, ingress_port=1, ingress_switch="test-sw"))

        stats = engine.get_stats()
        assert stats["frames_received"] == 3
        assert stats["unicast_unknown"] == 1
        assert stats["broadcast_received"] == 1
        assert stats["unicast_known"] == 1
        assert stats["frames_flooded"] == 2  # Unknown unicast + broadcast
        assert stats["frames_forwarded"] == 1  # Known unicast


class TestSwitchEngineLogs:
    """Tests for logging functionality."""

    def test_logs_are_generated(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch, log_level="debug")

        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:02",
            vlan_id=None
        )
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        engine.process_frame(frame)

        logs = engine.get_logs()
        assert len(logs) > 0

    def test_log_filtering(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch, log_level="info")

        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:02",
            vlan_id=None
        )
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        engine.process_frame(frame)

        # Should not have debug logs with info level
        debug_logs = engine.get_logs("debug")
        assert len(debug_logs) == 0

    def test_clear_logs(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch, log_level="debug")

        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="aa:bb:cc:dd:ee:02",
            vlan_id=None
        )
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        engine.process_frame(frame)

        assert len(engine.get_logs()) > 0
        engine.clear_logs()
        assert len(engine.get_logs()) == 0


class TestSwitchEngineMACDisplay:
    """Tests for MAC table display methods."""

    def test_get_mac_table_entries(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        engine.mac_table.learn("aa:bb:cc:dd:ee:01", vlan_id=10, port_id=1)
        engine.mac_table.learn("aa:bb:cc:dd:ee:02", vlan_id=10, port_id=2)

        entries = engine.get_mac_table_entries()
        assert len(entries) == 2

        macs = {e["mac"] for e in entries}
        assert macs == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}

    def test_clear_mac_table(self, simple_switch: VirtualSwitch) -> None:
        engine = SwitchEngine(simple_switch)

        engine.mac_table.learn("aa:bb:cc:dd:ee:01", vlan_id=10, port_id=1)
        cleared = engine.clear_mac_table()

        assert cleared == 1
        assert engine.mac_table.get_entry_count() == 0
