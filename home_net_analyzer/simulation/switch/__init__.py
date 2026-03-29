"""Switch simulator for VLAN-aware Layer 2 switching.

This module provides MAC learning, forwarding, flooding, and trunk handling
for virtual network switches.
"""

from home_net_analyzer.simulation.switch.models import (
    ForwardingDecision,
    MACTable,
    MACTableEntry,
    SwitchFrame,
    VLANAction,
)
from home_net_analyzer.simulation.switch.engine import SwitchEngine

__all__ = [
    "MACTable",
    "MACTableEntry",
    "SwitchFrame",
    "ForwardingDecision",
    "VLANAction",
    "SwitchEngine",
]
