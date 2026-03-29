"""Unit tests for topology loader (load/save/validate)."""

import json
import pytest
import tempfile
from pathlib import Path

from home_net_analyzer.topology import (
    Topology,
    VLAN,
    VirtualHost,
    VirtualSwitch,
    SwitchPort,
    Router,
    RouterInterface,
    load_topology,
    save_topology,
    validate_topology_file,
)


def _sample_topology_dict() -> dict:
    return {
        "name": "TestNet",
        "description": "A test topology",
        "vlans": [
            {"id": 10, "name": "Mgmt", "subnet": "10.0.10.0/24", "gateway": "10.0.10.1"},
            {"id": 20, "name": "Eng", "subnet": "10.0.20.0/24", "gateway": "10.0.20.1", "description": "Engineering"},
        ],
        "hosts": [
            {"name": "pc-01", "mac": "aa:bb:cc:01:00:01", "ip": "10.0.10.101", "vlan_id": 10},
            {"name": "srv-01", "mac": "aa:bb:cc:02:00:01", "ip": "10.0.20.10", "vlan_id": 20, "role": "server"},
        ],
        "switches": [
            {
                "name": "sw-01",
                "vlans": [10, 20],
                "ports": [
                    {"id": 1, "name": "Gi1/0/1", "mode": "access", "access_vlan": 10, "connected_to": "pc-01"},
                    {"id": 2, "name": "Gi1/0/2", "mode": "trunk", "allowed_vlans": [10, 20]},
                ],
            }
        ],
        "routers": [
            {
                "name": "gw-01",
                "interfaces": [
                    {"name": "vlan10", "ip": "10.0.10.1", "subnet": "10.0.10.0/24", "vlan_id": 10},
                    {"name": "vlan20", "ip": "10.0.20.1", "subnet": "10.0.20.0/24", "vlan_id": 20},
                ],
                "routing_table": [
                    {"destination": "0.0.0.0/0", "next_hop": "10.0.10.254", "interface": "vlan10"},
                ],
            }
        ],
    }


class TestLoadJSON:
    """Load topology from JSON files."""

    def test_load_valid_json(self) -> None:
        data = _sample_topology_dict()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            topo = load_topology(path)
            assert topo.name == "TestNet"
            assert len(topo.vlans) == 2
            assert topo.get_vlan(10).name == "Mgmt"
            assert len(topo.hosts) == 2
            assert topo.get_host("pc-01").vlan_id == 10
            assert len(topo.switches) == 1
            assert topo.get_switch("sw-01").get_port(1).access_vlan == 10
            assert len(topo.routers) == 1
            assert topo.get_router("gw-01").get_interface("vlan10").vlan_id == 10
        finally:
            Path(path).unlink()

    def test_load_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_topology("/nonexistent/path/topo.json")

    def test_load_invalid_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{ not valid json }")
            path = f.name
        try:
            with pytest.raises(json.JSONDecodeError):
                load_topology(path)
        finally:
            Path(path).unlink()

    def test_load_json_with_defaults(self) -> None:
        # Minimal valid JSON
        data = {"name": "Mini"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            topo = load_topology(path)
            assert topo.name == "Mini"
            assert topo.vlans == []
            assert topo.hosts == []
            assert topo.switches == []
            assert topo.routers == []
        finally:
            Path(path).unlink()


class TestSaveJSON:
    """Save topology to JSON files."""

    def test_save_and_reload(self) -> None:
        topo = Topology(
            name="RoundTrip",
            vlans=[VLAN(id=5, name="V5", subnet="5.5.5.0/24", gateway="5.5.5.1")],
            hosts=[VirtualHost(name="h", mac="aa:bb:cc:01:00:01", ip="5.5.5.10", vlan_id=5)],
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_topology(topo, path)
            reloaded = load_topology(path)
            assert reloaded.name == "RoundTrip"
            assert len(reloaded.vlans) == 1
            assert reloaded.get_vlan(5).gateway == "5.5.5.1"
            assert reloaded.get_host("h").ip == "5.5.5.10"
        finally:
            Path(path).unlink()


class TestYAMLSupport:
    """YAML loading (if pyyaml installed) or graceful error."""

    def test_yaml_without_pyyaml_raises(self) -> None:
        # Create a fake .yaml file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("name: Test\nvlans: []\n")
            path = f.name
        try:
            # If pyyaml not installed, should raise ImportError
            try:
                import yaml  # noqa: F401
                # If yaml is present, loading should work
                topo = load_topology(path)
                assert topo.name == "Test"
            except ImportError:
                with pytest.raises(ImportError):
                    load_topology(path)
        finally:
            Path(path).unlink()


class TestValidate:
    """validate_topology_file function."""

    def test_validate_good_file(self) -> None:
        data = _sample_topology_dict()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            ok = validate_topology_file(path)
            assert ok is True
        finally:
            Path(path).unlink()

    def test_validate_bad_file(self) -> None:
        # Missing required fields for VLAN (subnet without slash)
        data = {"name": "Bad", "vlans": [{"id": 1, "name": "X", "subnet": "bad", "gateway": "1.1.1.1"}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            with pytest.raises(Exception):
                validate_topology_file(path)
        finally:
            Path(path).unlink()
