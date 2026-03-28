"""Database abstraction for SQLite/DuckDB storage of packets."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from home_net_analyzer.storage.models import PacketRecord


class Database:
    """Simple database wrapper supporting SQLite and DuckDB backends.

    For now, implements SQLite fully; DuckDB is a thin wrapper over sqlite3-like API
    where supported. DuckDB can be enabled for analytics workloads.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        backend: Literal["sqlite", "duckdb"] = "sqlite",
    ) -> None:
        self.path = Path(path)
        self.backend = backend
        self._conn: Any = None

    def connect(self) -> None:
        """Open the database connection and ensure schema exists."""
        if self.backend == "duckdb":
            import duckdb  # type: ignore

            self._conn = duckdb.connect(str(self.path))
        else:
            self._conn = sqlite3.connect(str(self.path))
            self._conn.row_factory = sqlite3.Row

        self._ensure_schema()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Database":
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _ensure_schema(self) -> None:
        """Create tables if they don't exist."""
        sql = """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_mac TEXT,
            dst_mac TEXT,
            eth_type INTEGER,
            src_ip TEXT,
            dst_ip TEXT,
            ip_version INTEGER,
            ip_ttl INTEGER,
            ip_protocol INTEGER,
            src_port INTEGER,
            dst_port INTEGER,
            transport_protocol TEXT,
            tcp_flags INTEGER,
            tcp_syn INTEGER DEFAULT 0,
            tcp_ack INTEGER DEFAULT 0,
            tcp_fin INTEGER DEFAULT 0,
            tcp_rst INTEGER DEFAULT 0,
            tcp_psh INTEGER DEFAULT 0,
            tcp_urg INTEGER DEFAULT 0,
            length INTEGER DEFAULT 0,
            payload_len INTEGER DEFAULT 0,
            application_protocol TEXT,
            interface TEXT,
            captured_by TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
        CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
        CREATE INDEX IF NOT EXISTS idx_packets_transport ON packets(transport_protocol);
        """
        if self.backend == "duckdb":
            # DuckDB supports most SQLite syntax; run each statement
            for stmt in sql.split(";"):
                s = stmt.strip()
                if s:
                    self._conn.execute(s)
        else:
            self._conn.executescript(sql)
        self._conn.commit()

    def insert_packet(self, rec: PacketRecord) -> int:
        """Insert a packet record and return its new id."""
        sql = """
        INSERT INTO packets (
            timestamp, src_mac, dst_mac, eth_type, src_ip, dst_ip,
            ip_version, ip_ttl, ip_protocol, src_port, dst_port,
            transport_protocol, tcp_flags, tcp_syn, tcp_ack, tcp_fin,
            tcp_rst, tcp_psh, tcp_urg, length, payload_len,
            application_protocol, interface, captured_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        cur = self._conn.execute(sql, rec.to_tuple())
        self._conn.commit()
        return cur.lastrowid

    def insert_packets(self, records: list[PacketRecord]) -> list[int]:
        """Bulk insert multiple records. Returns list of new ids."""
        ids: list[int] = []
        for r in records:
            ids.append(self.insert_packet(r))
        return ids

    def count_packets(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM packets")
        row = cur.fetchone()
        return int(row[0] if not isinstance(row, sqlite3.Row) else row[0])

    def get_recent_packets(self, limit: int = 100) -> list[PacketRecord]:
        """Fetch most recent packets."""
        sql = "SELECT * FROM packets ORDER BY id DESC LIMIT ?"
        cur = self._conn.execute(sql, (limit,))
        return [self._row_to_record(r) for r in cur.fetchall()]

    def query(
        self,
        *,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        transport_protocol: str | None = None,
        application_protocol: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[PacketRecord]:
        """Simple filtered query."""
        where: list[str] = []
        params: list[Any] = []

        if src_ip is not None:
            where.append("src_ip = ?")
            params.append(src_ip)
        if dst_ip is not None:
            where.append("dst_ip = ?")
            params.append(dst_ip)
        if transport_protocol is not None:
            where.append("transport_protocol = ?")
            params.append(transport_protocol)
        if application_protocol is not None:
            where.append("application_protocol = ?")
            params.append(application_protocol)

        where_clause = ("WHERE " + " AND ".join(where)) if where else ""
        params.extend([limit, offset])
        sql = f"SELECT * FROM packets {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
        cur = self._conn.execute(sql, params)
        return [self._row_to_record(r) for r in cur.fetchall()]

    def _row_to_record(self, row: Any) -> PacketRecord:
        """Convert a DB row to PacketRecord."""
        if isinstance(row, sqlite3.Row):
            d = dict(row)
        else:
            # DuckDB or tuple
            cols = [
                "id",
                "timestamp",
                "src_mac",
                "dst_mac",
                "eth_type",
                "src_ip",
                "dst_ip",
                "ip_version",
                "ip_ttl",
                "ip_protocol",
                "src_port",
                "dst_port",
                "transport_protocol",
                "tcp_flags",
                "tcp_syn",
                "tcp_ack",
                "tcp_fin",
                "tcp_rst",
                "tcp_psh",
                "tcp_urg",
                "length",
                "payload_len",
                "application_protocol",
                "interface",
                "captured_by",
            ]
            d = dict(zip(cols, row))
        # Convert boolean ints back
        return PacketRecord(
            id=d.get("id"),
            timestamp=datetime.fromisoformat(d["timestamp"]),
            src_mac=d.get("src_mac"),
            dst_mac=d.get("dst_mac"),
            eth_type=d.get("eth_type"),
            src_ip=d.get("src_ip"),
            dst_ip=d.get("dst_ip"),
            ip_version=d.get("ip_version"),
            ip_ttl=d.get("ip_ttl"),
            ip_protocol=d.get("ip_protocol"),
            src_port=d.get("src_port"),
            dst_port=d.get("dst_port"),
            transport_protocol=d.get("transport_protocol"),
            tcp_flags=d.get("tcp_flags"),
            tcp_syn=bool(d.get("tcp_syn", 0)),
            tcp_ack=bool(d.get("tcp_ack", 0)),
            tcp_fin=bool(d.get("tcp_fin", 0)),
            tcp_rst=bool(d.get("tcp_rst", 0)),
            tcp_psh=bool(d.get("tcp_psh", 0)),
            tcp_urg=bool(d.get("tcp_urg", 0)),
            length=d.get("length", 0) or 0,
            payload_len=d.get("payload_len", 0) or 0,
            application_protocol=d.get("application_protocol"),
            interface=d.get("interface"),
            captured_by=d.get("captured_by", "scapy"),
        )
