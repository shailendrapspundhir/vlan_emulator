"""Simulation module: traffic generation, scenarios, and simulated capture.

This module provides:
- TrafficScenario, TrafficFlow, TrafficGenerator for defining and generating synthetic packets
- Pre-built scenarios for common network activities
- SimulatedPacketCapture for "capturing" generated packets and storing them

Example:
    from home_net_analyzer.simulation import TrafficGenerator, SCENARIOS, SimulatedPacketCapture

    cap = SimulatedPacketCapture()
    packets = cap.generate_scenario("web_browsing")
    stats = cap.store(packets, db_path="data/sim.db")
    print(stats)  # {'generated': N, 'stored': N, 'db_count': N}
"""

from home_net_analyzer.simulation.capture import SimulatedPacketCapture
from home_net_analyzer.simulation.traffic import (
    TrafficFlow,
    TrafficGenerator,
    TrafficScenario,
)
from home_net_analyzer.simulation.scenarios import SCENARIOS, get_scenario, list_scenarios

__all__ = [
    "TrafficFlow",
    "TrafficScenario",
    "TrafficGenerator",
    "SimulatedPacketCapture",
    "SCENARIOS",
    "get_scenario",
    "list_scenarios",
]
