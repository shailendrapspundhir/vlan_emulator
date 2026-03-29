"""Topology module: models and loaders for VLAN network simulation.

This module provides:
- Data models for VLANs, hosts, switches, routers, and full topologies
- Loaders to read/write topologies from YAML or JSON files

Example:
    from home_net_analyzer.topology import load_topology, Topology, VLAN

    topo = load_topology("data/topologies/office.json")
    print(topo.name)
    for vlan in topo.vlans:
        print(f"VLAN {vlan.id}: {vlan.name}")
"""

from home_net_analyzer.topology.loader import load_topology, save_topology, validate_topology_file
from home_net_analyzer.topology.models import (
    RouteEntry,
    Router,
    RouterInterface,
    SwitchPort,
    Topology,
    VirtualHost,
    VirtualSwitch,
    VLAN,
)

__all__ = [
    # Models
    "VLAN",
    "VirtualHost",
    "SwitchPort",
    "VirtualSwitch",
    "RouterInterface",
    "RouteEntry",
    "Router",
    "Topology",
    # Loader functions
    "load_topology",
    "save_topology",
    "validate_topology_file",
]
