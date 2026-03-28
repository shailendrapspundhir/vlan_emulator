"""End-to-end integration tests for capture -> parse -> store -> query pipeline."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from home_net_analyzer.capture.sniffer import PacketSniffer
from home_net_analyzer.capture.parser import PacketParser
from home_net_analyzer.storage.packet_store import PacketStore
from home_net_analyzer.capture.models import CapturedPacket


class TestCaptureParseStoreQuery:
    """Full pipeline: sniff -> parse -> store -> query."""

    def test_mock_sniff_parse_store_query(self) -> None:
        """Simulate sniffing packets, parsing, storing, and querying."""
        # 1. Create parser and sniffer with mocked scapy
        parser = PacketParser()
        sniffer = PacketSniffer(interface="eth0", parser=parser)

        # 2. Mock scapy.sniff to return sample packets
        def make_pkt(src_ip: str, dst_ip: str, proto: str, dport: int | None = None) -> MagicMock:
            pkt = MagicMock()
            # haslayer returns True for Ether, IP, and the proto (TCP/UDP/ICMP)
            def haslayer(L: type) -> bool:
                return L.__name__ in ("Ether", "IP", proto)
            pkt.haslayer = haslayer

            def getitem(self: MagicMock, L: type) -> MagicMock:
                name = L.__name__
                if name == "Ether":
                    return MagicMock(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:01", type=0x0800)
                if name == "IP":
                    return MagicMock(src=src_ip, dst=dst_ip, ttl=64, proto={"TCP": 6, "UDP": 17, "ICMP": 1}[proto], len=100)
                if name == proto:
                    if proto == "TCP":
                        return MagicMock(sport=54321, dport=dport or 80, flags=0x02)
                    if proto == "UDP":
                        return MagicMock(sport=54321, dport=dport or 53)
                    return MagicMock()
                return MagicMock()
            pkt.__getitem__ = getitem
            pkt.time = 1700000000.0
            pkt.__len__ = lambda s: 100
            return pkt

        mock_pkts = [
            make_pkt("192.168.1.10", "93.184.216.34", "TCP", 443),   # TLS
            make_pkt("10.0.0.5", "8.8.8.8", "UDP", 53),              # DNS
            make_pkt("192.168.1.10", "192.168.1.1", "ICMP"),         # Ping-like
        ]

        with patch("scapy.all.sniff", return_value=mock_pkts):
            captured = sniffer.sniff_once(count=3)
            assert len(captured) == 3

        # 3. Store all captured packets
        with tempfile.TemporaryDirectory() as d:
            store = PacketStore(Path(d) / "packets.db")
            store.open()
            ids = store.store_many(captured)
            assert len(ids) == 3
            assert store.count() == 3

            # 4. Query by source
            results = store.by_source("192.168.1.10")
            assert len(results) == 2

            # 5. Query by protocol
            tcp_recs = store.by_protocol("TCP")
            assert len(tcp_recs) == 1
            assert tcp_recs[0].application_protocol == "TLS"

            # 6. Query by app protocol
            dns_recs = store.by_app_protocol("DNS")
            assert len(dns_recs) == 1

            store.close()


class TestSuspiciousPatternUseCase:
    """Use case: detect suspicious SYN-without-ACK packets."""

    def test_detect_port_scan_like_packets(self) -> None:
        # Create packets that look like port scan (SYN, no ACK)
        packets = [
            CapturedPacket(tcp_syn=True, tcp_ack=False, src_ip="10.0.0.1", dst_ip="10.0.0.5", dst_port=p)
            for p in range(20, 30)
        ]
        # Check the heuristic method
        for p in packets:
            assert p.is_suspicious_port_scan() is True

        # Store and later query could flag these; here we just verify model method
        assert all(p.is_suspicious_port_scan() for p in packets)


class TestPersistenceUseCase:
    """Use case: data persists across sessions."""

    def test_persist_and_reload(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            db_path = Path(d) / "persist.db"

            # Session 1: capture and store
            store1 = PacketStore(db_path)
            store1.open()
            store1.store(CapturedPacket(src_ip="persist.test", transport_protocol="TCP"))
            store1.store(CapturedPacket(src_ip="persist.test", transport_protocol="UDP"))
            assert store1.count() == 2
            store1.close()

            # Session 2: reopen and verify
            store2 = PacketStore(db_path)
            store2.open()
            assert store2.count() == 2
            recs = store2.by_source("persist.test")
            assert len(recs) == 2
            protos = {r.transport_protocol for r in recs}
            assert protos == {"TCP", "UDP"}
            store2.close()
