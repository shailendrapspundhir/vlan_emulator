"""Unit tests for 802.1Q VLAN support in CapturedPacket."""

import pytest

from home_net_analyzer.capture.models import CapturedPacket


class TestVLANFields:
    """Basic VLAN field storage and defaults."""

    def test_default_untagged(self) -> None:
        cp = CapturedPacket()
        assert cp.vlan_id is None
        assert cp.vlan_prio is None
        assert cp.vlan_dei is False
        assert cp.is_vlan_tagged() is False

    def test_tagged_packet(self) -> None:
        cp = CapturedPacket(vlan_id=100, vlan_prio=5, vlan_dei=True)
        assert cp.vlan_id == 100
        assert cp.vlan_prio == 5
        assert cp.vlan_dei is True
        assert cp.is_vlan_tagged() is True

    def test_vlan_tag_helper(self) -> None:
        cp = CapturedPacket(vlan_id=50, vlan_prio=3, vlan_dei=False)
        tag = cp.vlan_tag()
        assert tag == {"vlan_id": 50, "priority": 3, "dei": False}

    def test_vlan_tag_untagged(self) -> None:
        cp = CapturedPacket()
        assert cp.vlan_tag() is None

    def test_vlan_prio_default_zero(self) -> None:
        cp = CapturedPacket(vlan_id=10)
        tag = cp.vlan_tag()
        assert tag["priority"] == 0  # vlan_tag returns 0 if prio is None


class TestVLANValidation:
    """Field validators for VLAN fields."""

    def test_vlan_id_low_invalid(self) -> None:
        with pytest.raises(ValueError):
            CapturedPacket(vlan_id=0)

    def test_vlan_id_high_invalid(self) -> None:
        with pytest.raises(ValueError):
            CapturedPacket(vlan_id=4095)

    def test_vlan_id_min_valid(self) -> None:
        cp = CapturedPacket(vlan_id=1)
        assert cp.vlan_id == 1

    def test_vlan_id_max_valid(self) -> None:
        cp = CapturedPacket(vlan_id=4094)
        assert cp.vlan_id == 4094

    def test_vlan_prio_low_invalid(self) -> None:
        with pytest.raises(ValueError):
            CapturedPacket(vlan_prio=-1)

    def test_vlan_prio_high_invalid(self) -> None:
        with pytest.raises(ValueError):
            CapturedPacket(vlan_prio=8)

    def test_vlan_prio_valid_range(self) -> None:
        for p in range(8):
            cp = CapturedPacket(vlan_prio=p)
            assert cp.vlan_prio == p


class TestVLANToDict:
    """to_dict includes VLAN fields."""

    def test_to_dict_includes_vlan(self) -> None:
        cp = CapturedPacket(vlan_id=200, vlan_prio=2, vlan_dei=True)
        d = cp.to_dict()
        assert d["vlan_id"] == 200
        assert d["vlan_prio"] == 2
        assert d["vlan_dei"] is True

    def test_to_dict_untagged(self) -> None:
        cp = CapturedPacket(src_ip="10.0.0.1")
        d = cp.to_dict()
        assert d["vlan_id"] is None
        assert d["vlan_prio"] is None
        assert d["vlan_dei"] is False


class TestVLANWithOtherFields:
    """VLAN fields coexist with existing packet fields."""

    def test_full_packet_with_vlan(self) -> None:
        cp = CapturedPacket(
            src_mac="aa:bb:cc:01:00:01",
            dst_mac="11:22:33:44:55:01",
            eth_type=0x8100,  # 802.1Q
            vlan_id=42,
            vlan_prio=1,
            vlan_dei=False,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            transport_protocol="TCP",
            src_port=54321,
            dst_port=443,
            length=1500,
        )
        assert cp.vlan_id == 42
        assert cp.eth_type == 0x8100
        assert cp.is_vlan_tagged() is True
        assert cp.is_tcp() is True
        d = cp.to_dict()
        assert d["vlan_id"] == 42
        assert d["src_ip"] == "192.168.1.10"
