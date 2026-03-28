"""PacketStore: high-level API to store and query captured packets."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.storage.database import Database
from home_net_analyzer.storage.models import PacketRecord


class PacketStore:
    """High-level store for captured packets.

    Wraps Database and provides methods to store CapturedPacket objects
    and run common queries.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        backend: Literal["sqlite", "duckdb"] = "sqlite",
    ) -> None:
        self.db = Database(path, backend=backend)

    def open(self) -> None:
        self.db.connect()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "PacketStore":
        self.open()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def store(self, packet: CapturedPacket) -> int:
        """Store a single CapturedPacket. Returns DB id."""
        rec = PacketRecord.from_captured_packet(packet)
        return self.db.insert_packet(rec)

    def store_many(self, packets: list[CapturedPacket]) -> list[int]:
        """Store multiple packets. Returns list of DB ids."""
        records = [PacketRecord.from_captured_packet(p) for p in packets]
        return self.db.insert_packets(records)

    def count(self) -> int:
        return self.db.count_packets()

    def recent(self, limit: int = 100) -> list[PacketRecord]:
        return self.db.get_recent_packets(limit=limit)

    def by_source(self, ip: str, limit: int = 100) -> list[PacketRecord]:
        return self.db.query(src_ip=ip, limit=limit)

    def by_destination(self, ip: str, limit: int = 100) -> list[PacketRecord]:
        return self.db.query(dst_ip=ip, limit=limit)

    def by_protocol(self, protocol: str, limit: int = 100) -> list[PacketRecord]:
        return self.db.query(transport_protocol=protocol, limit=limit)

    def by_app_protocol(self, protocol: str, limit: int = 100) -> list[PacketRecord]:
        return self.db.query(application_protocol=protocol, limit=limit)
