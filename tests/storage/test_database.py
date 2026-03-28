"""Integration tests for Database class (SQLite backend)."""

import pytest
import tempfile
from pathlib import Path

from home_net_analyzer.storage.database import Database
from home_net_analyzer.storage.models import PacketRecord


@pytest.fixture()
def tmp_db_path() -> Path:
    with tempfile.TemporaryDirectory() as d:
        yield Path(d) / "test.db"


@pytest.fixture()
def db(tmp_db_path: Path) -> Database:
    d = Database(tmp_db_path, backend="sqlite")
    d.connect()
    yield d
    d.close()


class TestDatabaseSchema:
    """Schema creation and basic connectivity."""

    def test_connect_creates_file(self, tmp_db_path: Path) -> None:
        d = Database(tmp_db_path, backend="sqlite")
        assert not tmp_db_path.exists()
        d.connect()
        assert tmp_db_path.exists()
        d.close()

    def test_schema_has_packets_table(self, db: Database) -> None:
        cur = db._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        names = [r[0] for r in cur.fetchall()]
        assert "packets" in names

    def test_schema_has_indexes(self, db: Database) -> None:
        cur = db._conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        names = [r[0] for r in cur.fetchall()]
        assert any("idx_packets" in n for n in names)


class TestDatabaseInsert:
    """Insert single and multiple packets."""

    def test_insert_single_packet(self, db: Database) -> None:
        rec = PacketRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2", transport_protocol="TCP")
        new_id = db.insert_packet(rec)
        assert isinstance(new_id, int)
        assert new_id >= 1

    def test_insert_many_packets(self, db: Database) -> None:
        records = [
            PacketRecord(src_ip=f"10.0.0.{i}", dst_ip="8.8.8.8", transport_protocol="UDP")
            for i in range(1, 6)
        ]
        ids = db.insert_packets(records)
        assert len(ids) == 5
        assert all(isinstance(i, int) for i in ids)

    def test_insert_preserves_fields(self, db: Database) -> None:
        rec = PacketRecord(
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            transport_protocol="TCP",
            src_port=54321,
            dst_port=22,
            tcp_syn=True,
            tcp_ack=False,
            length=120,
            application_protocol="SSH",
            interface="eth0",
        )
        db.insert_packet(rec)
        fetched = db.get_recent_packets(limit=1)
        assert len(fetched) == 1
        f = fetched[0]
        assert f.src_ip == "192.168.1.50"
        assert f.dst_ip == "10.0.0.1"
        assert f.transport_protocol == "TCP"
        assert f.src_port == 54321
        assert f.dst_port == 22
        assert f.tcp_syn is True
        assert f.tcp_ack is False
        assert f.length == 120
        assert f.application_protocol == "SSH"
        assert f.interface == "eth0"


class TestDatabaseQuery:
    """Query and filter operations."""

    def test_count_starts_zero(self, db: Database) -> None:
        assert db.count_packets() == 0

    def test_count_after_inserts(self, db: Database) -> None:
        db.insert_packets([
            PacketRecord(src_ip="a", dst_ip="b"),
            PacketRecord(src_ip="c", dst_ip="d"),
            PacketRecord(src_ip="e", dst_ip="f"),
        ])
        assert db.count_packets() == 3

    def test_recent_returns_newest_first(self, db: Database) -> None:
        db.insert_packet(PacketRecord(src_ip="old", dst_ip="x"))
        db.insert_packet(PacketRecord(src_ip="newer", dst_ip="y"))
        recent = db.get_recent_packets(limit=1)
        assert len(recent) == 1
        assert recent[0].src_ip == "newer"

    def test_query_by_src_ip(self, db: Database) -> None:
        db.insert_packets([
            PacketRecord(src_ip="10.0.0.1", dst_ip="x"),
            PacketRecord(src_ip="10.0.0.2", dst_ip="x"),
            PacketRecord(src_ip="10.0.0.1", dst_ip="y"),
        ])
        results = db.query(src_ip="10.0.0.1")
        assert len(results) == 2
        assert all(r.src_ip == "10.0.0.1" for r in results)

    def test_query_by_dst_ip(self, db: Database) -> None:
        db.insert_packets([
            PacketRecord(src_ip="a", dst_ip="target"),
            PacketRecord(src_ip="b", dst_ip="other"),
        ])
        results = db.query(dst_ip="target")
        assert len(results) == 1
        assert results[0].dst_ip == "target"

    def test_query_by_transport_protocol(self, db: Database) -> None:
        db.insert_packets([
            PacketRecord(transport_protocol="TCP"),
            PacketRecord(transport_protocol="UDP"),
            PacketRecord(transport_protocol="TCP"),
        ])
        results = db.query(transport_protocol="UDP")
        assert len(results) == 1
        assert results[0].transport_protocol == "UDP"

    def test_query_by_application_protocol(self, db: Database) -> None:
        db.insert_packets([
            PacketRecord(application_protocol="DNS"),
            PacketRecord(application_protocol="HTTP"),
            PacketRecord(application_protocol="DNS"),
        ])
        results = db.query(application_protocol="DNS")
        assert len(results) == 2

    def test_query_limit_and_offset(self, db: Database) -> None:
        for i in range(10):
            db.insert_packet(PacketRecord(src_ip=f"ip{i}"))
        page1 = db.query(limit=3, offset=0)
        page2 = db.query(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        # Different records
        assert page1[0].src_ip != page2[0].src_ip


class TestDatabaseEdgeCases:
    """Edge cases and robustness."""

    def test_insert_packet_with_nulls(self, db: Database) -> None:
        rec = PacketRecord()  # all defaults
        new_id = db.insert_packet(rec)
        assert new_id >= 1
        fetched = db.get_recent_packets(limit=1)[0]
        assert fetched.src_ip is None
        assert fetched.transport_protocol is None

    def test_reopen_existing_db(self, tmp_db_path: Path) -> None:
        # Insert, close, reopen
        d1 = Database(tmp_db_path)
        d1.connect()
        d1.insert_packet(PacketRecord(src_ip="persist"))
        d1.close()
        d2 = Database(tmp_db_path)
        d2.connect()
        assert d2.count_packets() == 1
        d2.close()

    def test_row_to_record_roundtrip(self, db: Database) -> None:
        rec = PacketRecord(
            src_ip="a.b.c.d",
            dst_ip="w.x.y.z",
            transport_protocol="ICMP",
            tcp_syn=True,
            tcp_ack=True,
            tcp_fin=True,
            tcp_rst=False,
            tcp_psh=False,
            tcp_urg=True,
            length=42,
        )
        db.insert_packet(rec)
        fetched = db.get_recent_packets(limit=1)[0]
        assert fetched.src_ip == rec.src_ip
        assert fetched.dst_ip == rec.dst_ip
        assert fetched.transport_protocol == rec.transport_protocol
        assert fetched.tcp_syn == rec.tcp_syn
        assert fetched.tcp_ack == rec.tcp_ack
        assert fetched.tcp_fin == rec.tcp_fin
        assert fetched.tcp_urg == rec.tcp_urg
        assert fetched.length == rec.length
