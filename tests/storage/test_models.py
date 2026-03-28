"""Unit tests for storage models (PacketRecord)."""

import pytest
from datetime import datetime, timezone

from home_net_analyzer.storage.models import PacketRecord
from home_net_analyzer.capture.models import CapturedPacket


class TestPacketRecordBasics:
    """Basic construction and defaults."""

    def test_default_construction(self) -> None:
        rec = PacketRecord()
        assert rec.id is None
        assert rec.src_ip is None
        assert rec.dst_ip is None
        assert rec.transport_protocol is None
        assert rec.tcp_syn is False
        assert isinstance(rec.timestamp, datetime)

    def test_custom_values(self) -> None:
        rec = PacketRecord(
            id=42,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_protocol="TCP",
            tcp_syn=True,
            tcp_ack=True,
            length=500,
        )
        assert rec.id == 42
        assert rec.src_ip == "10.0.0.1"
        assert rec.dst_ip == "10.0.0.2"
        assert rec.transport_protocol == "TCP"
        assert rec.tcp_syn is True
        assert rec.tcp_ack is True
        assert rec.length == 500


class TestPacketRecordFromCapturedPacket:
    """Conversion from CapturedPacket."""

    def test_from_captured_packet_basic(self) -> None:
        cp = CapturedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol="UDP",
            src_port=1234,
            dst_port=53,
            length=80,
            application_protocol="DNS",
        )
        rec = PacketRecord.from_captured_packet(cp)
        assert rec.src_ip == "192.168.1.1"
        assert rec.dst_ip == "192.168.1.2"
        assert rec.transport_protocol == "UDP"
        assert rec.src_port == 1234
        assert rec.dst_port == 53
        assert rec.length == 80
        assert rec.application_protocol == "DNS"
        assert rec.id is None  # not set until DB insert

    def test_from_captured_packet_tcp_flags(self) -> None:
        cp = CapturedPacket(
            transport_protocol="TCP",
            tcp_syn=True,
            tcp_ack=True,
            tcp_fin=False,
            tcp_rst=False,
            tcp_psh=True,
            tcp_urg=False,
        )
        rec = PacketRecord.from_captured_packet(cp)
        assert rec.tcp_syn is True
        assert rec.tcp_ack is True
        assert rec.tcp_fin is False
        assert rec.tcp_rst is False
        assert rec.tcp_psh is True
        assert rec.tcp_urg is False


class TestPacketRecordToTuple:
    """Serialization for DB insert."""

    def test_to_tuple_length_and_types(self) -> None:
        rec = PacketRecord(
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            transport_protocol="TCP",
            tcp_syn=True,
            tcp_ack=False,
            length=100,
            captured_by="scapy",
        )
        tup = rec.to_tuple()
        assert isinstance(tup, tuple)
        assert len(tup) == 24  # matches INSERT columns
        assert tup[4] == "1.2.3.4"  # src_ip position
        assert tup[5] == "5.6.7.8"  # dst_ip position
        assert tup[13] == 1  # tcp_syn as int (index 13)
        assert tup[14] == 0  # tcp_ack as int (index 14)

    def test_to_tuple_excludes_id(self) -> None:
        rec = PacketRecord(id=999)
        tup = rec.to_tuple()
        # id should not be in tuple
        assert 999 not in tup
