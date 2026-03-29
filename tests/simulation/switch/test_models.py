"""Unit tests for switch simulator models: MACTable, MACTableEntry, SwitchFrame."""

import time

import pytest

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.simulation.switch.models import (
    ForwardingDecision,
    MACTable,
    MACTableEntry,
    SwitchFrame,
    VLANAction,
)


class TestMACTableEntry:
    """Tests for MACTableEntry model."""

    def test_basic_creation(self) -> None:
        entry = MACTableEntry(
            mac="aa:bb:cc:dd:ee:ff",
            vlan_id=10,
            port_id=1,
            entry_type="dynamic"
        )
        assert entry.mac == "aa:bb:cc:dd:ee:ff"
        assert entry.vlan_id == 10
        assert entry.port_id == 1
        assert entry.entry_type == "dynamic"
        assert entry.ttl == 300

    def test_mac_normalization(self) -> None:
        entry = MACTableEntry(
            mac="AA:BB:CC:DD:EE:FF",
            vlan_id=10,
            port_id=1
        )
        assert entry.mac == "AA:BB:CC:DD:EE:FF"  # Preserved as-is

    def test_is_expired(self) -> None:
        entry = MACTableEntry(
            mac="aa:bb:cc:dd:ee:ff",
            vlan_id=10,
            port_id=1,
            ttl=1  # 1 second TTL
        )
        assert not entry.is_expired()
        time.sleep(1.1)
        assert entry.is_expired()

    def test_is_expired_static(self) -> None:
        entry = MACTableEntry(
            mac="aa:bb:cc:dd:ee:ff",
            vlan_id=10,
            port_id=1,
            entry_type="static",
            ttl=0  # Static entries don't expire
        )
        time.sleep(0.1)
        # Static entries with ttl=0 should not be considered expired
        # (the check is elapsed > ttl, so 0 > 0 is False)
        assert not entry.is_expired()

    def test_touch_updates_timestamp(self) -> None:
        entry = MACTableEntry(
            mac="aa:bb:cc:dd:ee:ff",
            vlan_id=10,
            port_id=1,
            ttl=1
        )
        time.sleep(0.1)
        entry.touch()
        time.sleep(0.1)
        # Should not be expired because touch() updated last_seen
        assert not entry.is_expired()

    def test_hash_and_equality(self) -> None:
        entry1 = MACTableEntry(mac="aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
        entry2 = MACTableEntry(mac="AA:BB:CC:DD:EE:FF", vlan_id=10, port_id=2)
        entry3 = MACTableEntry(mac="aa:bb:cc:dd:ee:ff", vlan_id=20, port_id=1)

        # Same MAC (case insensitive) and VLAN should be equal
        assert entry1 == entry2
        assert hash(entry1) == hash(entry2)

        # Different VLAN should not be equal
        assert entry1 != entry3

    def test_invalid_vlan(self) -> None:
        with pytest.raises(ValueError):
            MACTableEntry(mac="aa:bb:cc:dd:ee:ff", vlan_id=0, port_id=1)

        with pytest.raises(ValueError):
            MACTableEntry(mac="aa:bb:cc:dd:ee:ff", vlan_id=4095, port_id=1)


class TestMACTable:
    """Tests for MACTable class."""

    def test_learn_new_entry(self) -> None:
        table = MACTable()
        entry = table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)

        assert entry.mac == "aa:bb:cc:dd:ee:ff"
        assert entry.vlan_id == 10
        assert entry.port_id == 1
        assert table.get_entry_count() == 1
        assert table.get_stats()["learned"] == 1

    def test_learn_updates_existing(self) -> None:
        table = MACTable()
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
        entry = table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=2)

        # Should update port, not create new entry
        assert entry.port_id == 2
        assert table.get_entry_count() == 1

    def test_learn_case_insensitive(self) -> None:
        table = MACTable()
        table.learn("AA:BB:CC:DD:EE:FF", vlan_id=10, port_id=1)
        entry = table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=2)

        # Should treat as same MAC
        assert table.get_entry_count() == 1
        assert entry.port_id == 2

    def test_lookup_found(self) -> None:
        table = MACTable()
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=5)

        port = table.lookup("aa:bb:cc:dd:ee:ff", vlan_id=10)
        assert port == 5

    def test_lookup_not_found(self) -> None:
        table = MACTable()
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=5)

        port = table.lookup("11:22:33:44:55:66", vlan_id=10)
        assert port is None

    def test_lookup_wrong_vlan(self) -> None:
        table = MACTable()
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=5)

        # Same MAC, different VLAN should not match
        port = table.lookup("aa:bb:cc:dd:ee:ff", vlan_id=20)
        assert port is None

    def test_lookup_updates_last_seen(self) -> None:
        table = MACTable(default_ttl=1)
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)

        time.sleep(0.6)
        port = table.lookup("aa:bb:cc:dd:ee:ff", vlan_id=10)  # Should touch
        assert port == 1

        time.sleep(0.6)
        # Should still be found because lookup touched it
        port = table.lookup("aa:bb:cc:dd:ee:ff", vlan_id=10)
        assert port == 1

    def test_lookup_expired(self) -> None:
        table = MACTable(default_ttl=1)
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)

        time.sleep(1.1)
        port = table.lookup("aa:bb:cc:dd:ee:ff", vlan_id=10)
        assert port is None
        assert table.get_entry_count() == 0  # Should be removed

    def test_lookup_static_not_expired(self) -> None:
        table = MACTable()
        table.add_static("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)

        time.sleep(0.1)
        port = table.lookup("aa:bb:cc:dd:ee:ff", vlan_id=10)
        assert port == 1

    def test_age_out(self) -> None:
        table = MACTable(default_ttl=1)
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
        table.learn("11:22:33:44:55:66", vlan_id=10, port_id=2)

        time.sleep(1.1)
        expired = table.age_out()

        assert len(expired) == 2
        assert table.get_entry_count() == 0

    def test_flush_port(self) -> None:
        table = MACTable()
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
        table.learn("11:22:33:44:55:66", vlan_id=10, port_id=2)
        table.learn("22:33:44:55:66:77", vlan_id=10, port_id=1)

        removed = table.flush_port(1)
        assert removed == 2
        assert table.get_entry_count() == 1

    def test_flush_vlan(self) -> None:
        table = MACTable()
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
        table.learn("11:22:33:44:55:66", vlan_id=20, port_id=2)
        table.learn("22:33:44:55:66:77", vlan_id=10, port_id=3)

        removed = table.flush_vlan(10)
        assert removed == 2
        assert table.get_entry_count() == 1

    def test_max_entries_overflow(self) -> None:
        table = MACTable(max_entries=3)
        table.learn("aa:bb:cc:dd:ee:01", vlan_id=10, port_id=1)
        table.learn("aa:bb:cc:dd:ee:02", vlan_id=10, port_id=1)
        table.learn("aa:bb:cc:dd:ee:03", vlan_id=10, port_id=1)

        # Fourth entry should trigger overflow
        table.learn("aa:bb:cc:dd:ee:04", vlan_id=10, port_id=1)

        assert table.get_entry_count() == 3
        assert table.get_stats()["overflow"] == 1

    def test_clear(self) -> None:
        table = MACTable()
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
        table.learn("11:22:33:44:55:66", vlan_id=10, port_id=2)

        cleared = table.clear()
        assert cleared == 2
        assert table.get_entry_count() == 0

    def test_get_entries(self) -> None:
        table = MACTable()
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
        table.learn("11:22:33:44:55:66", vlan_id=20, port_id=2)

        entries = table.get_entries()
        assert len(entries) == 2
        macs = {e.mac for e in entries}
        assert macs == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}

    def test_stats_tracking(self) -> None:
        table = MACTable()
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
        table.lookup("aa:bb:cc:dd:ee:ff", vlan_id=10)  # Hit
        table.lookup("11:22:33:44:55:66", vlan_id=10)  # Miss

        stats = table.get_stats()
        assert stats["learned"] == 1
        assert stats["lookups"] == 2
        assert stats["hits"] == 1
        assert stats["misses"] == 1


class TestSwitchFrame:
    """Tests for SwitchFrame model."""

    def test_basic_creation(self) -> None:
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:ff",
            dst_mac="11:22:33:44:55:66",
            vlan_id=10
        )
        frame = SwitchFrame(
            packet=packet,
            ingress_port=1,
            ingress_switch="test-sw"
        )

        assert frame.ingress_port == 1
        assert frame.ingress_switch == "test-sw"
        assert frame.native_vlan == 1

    def test_get_vlan_tagged(self) -> None:
        packet = CapturedPacket(vlan_id=20)
        frame = SwitchFrame(
            packet=packet,
            ingress_port=1,
            ingress_switch="test-sw"
        )
        assert frame.get_vlan() == 20

    def test_get_vlan_untagged(self) -> None:
        packet = CapturedPacket()  # No VLAN
        frame = SwitchFrame(
            packet=packet,
            ingress_port=1,
            ingress_switch="test-sw",
            native_vlan=10
        )
        assert frame.get_vlan() == 10

    def test_is_broadcast(self) -> None:
        packet = CapturedPacket(dst_mac="ff:ff:ff:ff:ff:ff")
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        assert frame.is_broadcast()

    def test_is_not_broadcast(self) -> None:
        packet = CapturedPacket(dst_mac="11:22:33:44:55:66")
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        assert not frame.is_broadcast()

    def test_is_multicast(self) -> None:
        # Multicast MACs: first octet's LSB is 1
        packet = CapturedPacket(dst_mac="01:00:5e:00:00:01")  # IPv4 multicast
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        assert frame.is_multicast()

    def test_is_not_multicast(self) -> None:
        packet = CapturedPacket(dst_mac="00:11:22:33:44:55")
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        assert not frame.is_multicast()

    def test_is_unknown_unicast(self) -> None:
        packet = CapturedPacket(dst_mac="00:11:22:33:44:55")
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        assert frame.is_unknown_unicast()

    def test_is_not_unknown_unicast_broadcast(self) -> None:
        packet = CapturedPacket(dst_mac="ff:ff:ff:ff:ff:ff")
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        assert not frame.is_unknown_unicast()

    def test_is_not_unknown_unicast_multicast(self) -> None:
        packet = CapturedPacket(dst_mac="01:00:5e:00:00:01")
        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="test-sw")
        assert not frame.is_unknown_unicast()


class TestForwardingDecision:
    """Tests for ForwardingDecision model."""

    def test_basic_creation(self) -> None:
        decision = ForwardingDecision(
            port_id=5,
            vlan_action=VLANAction.TAG,
            egress_vlan=10
        )
        assert decision.port_id == 5
        assert decision.vlan_action == VLANAction.TAG
        assert decision.egress_vlan == 10

    def test_apply_tag(self) -> None:
        packet = CapturedPacket(vlan_id=None)
        decision = ForwardingDecision(
            port_id=1,
            vlan_action=VLANAction.TAG,
            egress_vlan=20
        )
        result = decision.apply_to_packet(packet)
        assert result.vlan_id == 20

    def test_apply_strip(self) -> None:
        packet = CapturedPacket(vlan_id=10)
        decision = ForwardingDecision(
            port_id=1,
            vlan_action=VLANAction.STRIP
        )
        result = decision.apply_to_packet(packet)
        assert result.vlan_id is None

    def test_apply_preserves_other_fields(self) -> None:
        packet = CapturedPacket(
            src_mac="aa:bb:cc:dd:ee:ff",
            dst_mac="11:22:33:44:55:66",
            src_ip="192.168.1.1",
            vlan_id=10
        )
        decision = ForwardingDecision(
            port_id=1,
            vlan_action=VLANAction.STRIP
        )
        result = decision.apply_to_packet(packet)
        assert result.src_mac == "aa:bb:cc:dd:ee:ff"
        assert result.dst_mac == "11:22:33:44:55:66"
        assert result.src_ip == "192.168.1.1"

    def test_str_representation(self) -> None:
        decision = ForwardingDecision(
            port_id=5,
            vlan_action=VLANAction.TAG,
            egress_vlan=10
        )
        str_repr = str(decision)
        assert "Port 5" in str_repr
        assert "tag" in str_repr
        assert "VLAN:10" in str_repr
