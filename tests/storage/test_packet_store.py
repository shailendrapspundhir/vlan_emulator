"""Integration tests for PacketStore high-level API."""

import pytest
import tempfile
from pathlib import Path

from home_net_analyzer.storage.packet_store import PacketStore
from home_net_analyzer.capture.models import CapturedPacket


@pytest.fixture()
def tmp_path() -> Path:
    with tempfile.TemporaryDirectory() as d:
        yield Path(d) / "store.db"


@pytest.fixture()
def store(tmp_path: Path) -> PacketStore:
    s = PacketStore(tmp_path, backend="sqlite")
    s.open()
    yield s
    s.close()


class TestPacketStoreBasics:
    """Basic open/close and empty state."""

    def test_open_creates_file(self, tmp_path: Path) -> None:
        s = PacketStore(tmp_path)
        assert not tmp_path.exists()
        s.open()
        assert tmp_path.exists()
        s.close()

    def test_context_manager(self, tmp_path: Path) -> None:
        with PacketStore(tmp_path) as s:
            assert s.count() == 0

    def test_count_empty(self, store: PacketStore) -> None:
        assert store.count() == 0


class TestPacketStoreStore:
    """Storing CapturedPacket objects."""

    def test_store_single(self, store: PacketStore) -> None:
        cp = CapturedPacket(src_ip="1.1.1.1", dst_ip="2.2.2.2", transport_protocol="TCP")
        new_id = store.store(cp)
        assert isinstance(new_id, int)
        assert new_id >= 1
        assert store.count() == 1

    def test_store_many(self, store: PacketStore) -> None:
        packets = [
            CapturedPacket(src_ip=f"10.0.{i}.1", dst_ip="8.8.8.8", transport_protocol="UDP")
            for i in range(5)
        ]
        ids = store.store_many(packets)
        assert len(ids) == 5
        assert store.count() == 5

    def test_store_preserves_fields(self, store: PacketStore) -> None:
        cp = CapturedPacket(
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            transport_protocol="TCP",
            src_port=54321,
            dst_port=443,
            tcp_syn=True,
            application_protocol="TLS",
            length=1500,
            interface="wlan0",
        )
        store.store(cp)
        recs = store.recent(limit=1)
        assert len(recs) == 1
        r = recs[0]
        assert r.src_ip == "192.168.1.100"
        assert r.dst_ip == "93.184.216.34"
        assert r.transport_protocol == "TCP"
        assert r.dst_port == 443
        assert r.tcp_syn is True
        assert r.application_protocol == "TLS"
        assert r.length == 1500
        assert r.interface == "wlan0"


class TestPacketStoreQueries:
    """Query convenience methods."""

    def test_recent(self, store: PacketStore) -> None:
        for i in range(3):
            store.store(CapturedPacket(src_ip=f"ip{i}"))
        recs = store.recent(limit=2)
        assert len(recs) == 2
        # Newest first
        assert recs[0].src_ip == "ip2"

    def test_by_source(self, store: PacketStore) -> None:
        store.store_many([
            CapturedPacket(src_ip="10.0.0.1", dst_ip="a"),
            CapturedPacket(src_ip="10.0.0.2", dst_ip="b"),
            CapturedPacket(src_ip="10.0.0.1", dst_ip="c"),
        ])
        results = store.by_source("10.0.0.1")
        assert len(results) == 2
        assert all(r.src_ip == "10.0.0.1" for r in results)

    def test_by_destination(self, store: PacketStore) -> None:
        store.store_many([
            CapturedPacket(src_ip="a", dst_ip="target"),
            CapturedPacket(src_ip="b", dst_ip="other"),
        ])
        results = store.by_destination("target")
        assert len(results) == 1
        assert results[0].dst_ip == "target"

    def test_by_protocol(self, store: PacketStore) -> None:
        store.store_many([
            CapturedPacket(transport_protocol="TCP"),
            CapturedPacket(transport_protocol="UDP"),
            CapturedPacket(transport_protocol="TCP"),
        ])
        results = store.by_protocol("UDP")
        assert len(results) == 1
        assert results[0].transport_protocol == "UDP"

    def test_by_app_protocol(self, store: PacketStore) -> None:
        store.store_many([
            CapturedPacket(application_protocol="DNS"),
            CapturedPacket(application_protocol="HTTP"),
            CapturedPacket(application_protocol="DNS"),
        ])
        results = store.by_app_protocol("DNS")
        assert len(results) == 2


class TestPacketStoreEdgeCases:
    """Edge cases and robustness."""

    def test_store_packet_with_minimal_fields(self, store: PacketStore) -> None:
        cp = CapturedPacket()  # all defaults
        new_id = store.store(cp)
        assert new_id >= 1
        recs = store.recent(limit=1)
        assert recs[0].src_ip is None

    def test_reopen_and_query(self, tmp_path: Path) -> None:
        s1 = PacketStore(tmp_path)
        s1.open()
        s1.store(CapturedPacket(src_ip="persist"))
        s1.close()

        s2 = PacketStore(tmp_path)
        s2.open()
        assert s2.count() == 1
        assert s2.by_source("persist")
        s2.close()
