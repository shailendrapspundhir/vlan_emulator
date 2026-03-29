"""Router simulator for Layer 3 routing with ARP, SVI, and routing table.

This module provides router simulation capabilities including:
- ARP table management with aging
- Routing table with longest prefix match
- SVI (Switched Virtual Interface) for VLAN routing
- Packet forwarding between subnets
"""

from home_net_analyzer.simulation.router.engine import RouterEngine
from home_net_analyzer.simulation.router.models import (
    ARPEntry,
    ARPTable,
    RouteEntry,
    RouteType,
    RouterInterface,
    RoutingTable,
    SVI,
)

__all__ = [
    "ARPEntry",
    "ARPTable",
    "RouteEntry",
    "RouteType",
    "RouterEngine",
    "RouterInterface",
    "RoutingTable",
    "SVI",
]
