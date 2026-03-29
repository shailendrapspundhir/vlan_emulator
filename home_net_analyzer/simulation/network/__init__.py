"""Network simulation engine for multi-device packet flow orchestration.

This module provides:
- Network topology management
- Multi-hop packet tracing
- Device interconnection (switches, routers, hosts)
- Complex scenario execution
- Protocol simulation (DHCP, DNS, ICMP, HTTP)
"""

from home_net_analyzer.simulation.network.engine import NetworkSimulationEngine
from home_net_analyzer.simulation.network.models import (
    DeviceType,
    HopLog,
    NetworkDevice,
    NetworkLink,
    NetworkTopology,
    PacketFlow,
    SimulationHost,
)
from home_net_analyzer.simulation.network.protocols import (
    DHCPTransaction,
    DNSEntry,
    DNSQuery,
    DNSResolver,
    HTTPEndpoint,
    HTTPServer,
    ICMPPing,
    ProtocolSimulator,
)
from home_net_analyzer.simulation.network.scenarios import ScenarioBuilder

__all__ = [
    "DHCPTransaction",
    "DeviceType",
    "DNSEntry",
    "DNSQuery",
    "DNSResolver",
    "HopLog",
    "HTTPEndpoint",
    "HTTPServer",
    "ICMPPing",
    "NetworkDevice",
    "NetworkLink",
    "NetworkSimulationEngine",
    "NetworkTopology",
    "PacketFlow",
    "ProtocolSimulator",
    "ScenarioBuilder",
    "SimulationHost",
]
