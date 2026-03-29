"""Unit tests for SimulatedPacketCapture (generate + store)."""

import pytest
import tempfile
from pathlib import Path

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.simulation import (
    SimulatedPacketCapture,
    TrafficFlow,
    TrafficScenario,
)


class TestSimulatedPacketCaptureGenerate:
    """Test generation methods of SimulatedPacketCapture."""

    def test_generate_flow(self) -> None:
        cap = SimulatedPacketCapture()
        flow = TrafficFlow(src="a", dst="b", protocol="tcp", dst_port=80, count=3)
        pkts = cap.generate_flow(flow)
        assert len(pkts) == 3
        assert all(isinstance(p, CapturedPacket) for p in pkts)

    def test_generate_scenario_by_name(self) -> None:
        cap = SimulatedPacketCapture()
        pkts = cap.generate_scenario("dns_resolution")
        assert len(pkts) == 2
        assert all(p.application_protocol == "DNS" for p in pkts)

    def test_generate_scenario_by_object(self) -> None:
        cap = SimulatedPacketCapture()
        s = TrafficScenario(name="mini", flows=[TrafficFlow(src="x", dst="y", count=1)])
        pkts = cap.generate_scenario(s)
        assert len(pkts) == 1

    def test_generate_convenience(self) -> None:
        cap = SimulatedPacketCapture()
        pkts = cap.generate(src="c", dst="s", protocol="icmp", count=5)
        assert len(pkts) == 5
        assert all(p.transport_protocol == "ICMP" for p in pkts)


class TestSimulatedPacketCaptureStore:
    """Test storage via SimulatedPacketCapture."""

    def test_store_returns_stats(self) -> None:
        cap = SimulatedPacketCapture()
        flow = TrafficFlow(src="a", dst="b", count=4)
        pkts = cap.generate_flow(flow)
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "test.db"
            stats = cap.store(pkts, db_path=db)
            assert stats["generated"] == 4
            assert stats["stored"] == 4
            assert stats["db_count"] == 4

    def test_generate_and_store(self) -> None:
        cap = SimulatedPacketCapture()
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "sim.db"
            stats = cap.generate_and_store("port_scan", db_path=db)
            assert stats["generated"] == 6  # 6 ports in port_scan
            assert stats["stored"] == 6
            assert stats["db_count"] == 6

    def test_store_appends(self) -> None:
        cap = SimulatedPacketCapture()
        flow = TrafficFlow(src="a", dst="b", count=2)
        pkts1 = cap.generate_flow(flow)
        pkts2 = cap.generate_flow(flow)
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "append.db"
            s1 = cap.store(pkts1, db_path=db)
            assert s1["db_count"] == 2
            s2 = cap.store(pkts2, db_path=db)
            assert s2["db_count"] == 4  # 2 + 2


class TestSimulatedPacketCaptureVLAN:
    """VLAN-tagged generation via SimulatedPacketCapture."""

    def test_generate_vlan_flow(self) -> None:
        cap = SimulatedPacketCapture()
        flow = TrafficFlow(src="a", dst="b", vlan_id=99, count=1)
        pkts = cap.generate_flow(flow)
        assert pkts[0].vlan_id == 99
        assert pkts[0].is_vlan_tagged() is True

    def test_generate_inter_vlan_scenario(self) -> None:
        cap = SimulatedPacketCapture()
        pkts = cap.generate_scenario("inter_vlan_ping")
        vlans = {p.vlan_id for p in pkts}
        assert 10 in vlans
        assert 20 in vlans
