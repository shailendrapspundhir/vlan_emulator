"""Load and save network topologies from YAML or JSON files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from home_net_analyzer.topology.models import (
    Router,
    RouterInterface,
    RouteEntry,
    SwitchPort,
    Topology,
    VirtualHost,
    VirtualSwitch,
    VLAN,
)


def _try_import_yaml() -> Any:
    """Try to import yaml module; return None if unavailable."""
    try:
        import yaml  # type: ignore

        return yaml
    except ImportError:
        return None


def _load_raw(path: Path) -> dict:
    """Load raw data from a YAML or JSON file."""
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        yaml = _try_import_yaml()
        if yaml is None:
            raise ImportError(
                "PyYAML is required to load .yaml/.yml files. "
                "Install it with: pip install pyyaml"
            )
        data = yaml.safe_load(path.read_text())
    elif suffix == ".json":
        data = json.loads(path.read_text())
    else:
        raise ValueError(f"Unsupported file format: {suffix} (use .yaml, .yml, or .json)")
    if not isinstance(data, dict):
        raise ValueError("Topology file must contain a JSON/YAML object at the top level")
    return data


def _parse_vlan(item: dict) -> VLAN:
    return VLAN(**item)


def _parse_host(item: dict) -> VirtualHost:
    return VirtualHost(**item)


def _parse_switch_port(item: dict) -> SwitchPort:
    return SwitchPort(**item)


def _parse_switch(item: dict) -> VirtualSwitch:
    ports = [_parse_switch_port(p) for p in item.get("ports", [])]
    return VirtualSwitch(
        name=item["name"],
        ports=ports,
        vlans=item.get("vlans", []),
        description=item.get("description"),
    )


def _parse_router_interface(item: dict) -> RouterInterface:
    return RouterInterface(**item)


def _parse_route(item: dict) -> RouteEntry:
    return RouteEntry(**item)


def _parse_router(item: dict) -> Router:
    interfaces = [_parse_router_interface(i) for i in item.get("interfaces", [])]
    routes = [_parse_route(r) for r in item.get("routing_table", [])]
    return Router(
        name=item["name"],
        interfaces=interfaces,
        routing_table=routes,
        description=item.get("description"),
    )


def load_topology(path: str | Path) -> Topology:
    """Load a Topology from a YAML or JSON file.

    Args:
        path: Path to .yaml, .yml, or .json file.

    Returns:
        Topology model instance.

    Raises:
        FileNotFoundError: If file does not exist.
        ValueError: If file format or contents are invalid.
        ImportError: If YAML file is given but PyYAML is not installed.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Topology file not found: {path}")

    data = _load_raw(path)

    vlans = [_parse_vlan(v) for v in data.get("vlans", [])]
    hosts = [_parse_host(h) for h in data.get("hosts", [])]
    switches = [_parse_switch(s) for s in data.get("switches", [])]
    routers = [_parse_router(r) for r in data.get("routers", [])]

    return Topology(
        name=data.get("name", path.stem),
        vlans=vlans,
        hosts=hosts,
        switches=switches,
        routers=routers,
        description=data.get("description"),
    )


def save_topology(topology: Topology, path: str | Path) -> None:
    """Save a Topology to a YAML or JSON file.

    Args:
        topology: The Topology to save.
        path: Destination path (.yaml, .yml, or .json).

    Raises:
        ImportError: If YAML format requested but PyYAML not installed.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    data = topology.to_dict()

    if suffix in (".yaml", ".yml"):
        yaml = _try_import_yaml()
        if yaml is None:
            raise ImportError(
                "PyYAML is required to save .yaml/.yml files. "
                "Install it with: pip install pyyaml"
            )
        path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    elif suffix == ".json":
        path.write_text(json.dumps(data, indent=2))
    else:
        raise ValueError(f"Unsupported file format: {suffix} (use .yaml, .yml, or .json)")


def validate_topology_file(path: str | Path) -> bool:
    """Validate a topology file can be parsed without errors.

    Returns True if valid, raises on errors.
    """
    _ = load_topology(path)
    return True
