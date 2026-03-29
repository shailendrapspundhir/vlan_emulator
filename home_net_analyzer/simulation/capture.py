"""Simulated packet capture: generate and optionally store synthetic traffic.

This module provides SimulatedPacketCapture, which acts like a virtual sniffer
that produces CapturedPacket objects from TrafficScenario/TrafficFlow definitions
and can store them via PacketStore.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.simulation.traffic import TrafficFlow, TrafficGenerator, TrafficScenario
from home_net_analyzer.storage.packet_store import PacketStore


class SimulatedPacketCapture:
    """A virtual packet capture that generates synthetic traffic.

    Use this to:
    - Generate packets for a scenario or flow
    - Optionally store them into a database via PacketStore
    - Get stats about generated/stored packets

    Example:
        cap = SimulatedPacketCapture()
        packets = cap.generate_scenario("web_browsing")
        stats = cap.store(packets, db_path="data/sim.db")
        print(stats)  # {'generated': 10, 'stored': 10, 'db_count': 10}
    """

    def __init__(self, *, generator: TrafficGenerator | None = None) -> None:
        self.generator = generator or TrafficGenerator()

    def generate_flow(self, flow: TrafficFlow) -> list[CapturedPacket]:
        """Generate packets for a single flow."""
        return self.generator.generate_flow(flow)

    def generate_scenario(self, scenario: TrafficScenario | str) -> list[CapturedPacket]:
        """Generate packets for a scenario (by name or object)."""
        if isinstance(scenario, str):
            from home_net_analyzer.simulation.scenarios import get_scenario

            scenario = get_scenario(scenario)
        return self.generator.generate_scenario(scenario)

    def generate(
        self,
        *,
        src: str | None = None,
        dst: str | None = None,
        protocol: Literal["tcp", "udp", "icmp"] = "tcp",
        dst_port: int | None = None,
        count: int = 1,
        app: str | None = None,
        vlan_id: int | None = None,
    ) -> list[CapturedPacket]:
        """Generate packets from simple parameters."""
        return self.generator.generate(
            src=src,
            dst=dst,
            protocol=protocol,
            dst_port=dst_port,
            count=count,
            app=app,
            vlan_id=vlan_id,
        )

    def store(
        self,
        packets: list[CapturedPacket],
        *,
        db_path: Path | str = "data/sim_packets.db",
    ) -> dict:
        """Store packets into a database. Returns stats dict."""
        with PacketStore(db_path) as store:
            ids = store.store_many(packets)
            return {
                "generated": len(packets),
                "stored": len(ids),
                "db_count": store.count(),
            }

    def generate_and_store(
        self,
        scenario: TrafficScenario | str,
        *,
        db_path: Path | str = "data/sim_packets.db",
    ) -> dict:
        """Generate a scenario and store all packets. Returns stats."""
        packets = self.generate_scenario(scenario)
        return self.store(packets, db_path=db_path)
