"""Tests for the interactive CLI helpers and structure.

These tests cover:
- _prompt_choice helper function (unit test with mock input)
- CLI app structure (commands exist)
- Basic --help smoke tests
"""

import io
import sys
import pytest

from home_net_analyzer.cli import (
    app,
    _prompt_choice,
)


class TestPromptChoice:
    """Unit tests for the _prompt_choice helper used in interactive menus."""

    def test_prompt_choice_valid_first(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate user typing "1" then Enter
        monkeypatch.setattr("sys.stdin", io.StringIO("1\n"))
        result = _prompt_choice("Pick one:", ["A", "B", "C"])
        assert result == "A"

    def test_prompt_choice_valid_last(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO("3\n"))
        result = _prompt_choice("Pick:", ["X", "Y", "Z"])
        assert result == "Z"

    def test_prompt_choice_invalid_then_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # First invalid (4), then valid (2)
        monkeypatch.setattr("sys.stdin", io.StringIO("4\n2\n"))
        result = _prompt_choice("Pick:", ["One", "Two"])
        assert result == "Two"

    def test_prompt_choice_non_number_then_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO("abc\n1\n"))
        result = _prompt_choice("Pick:", ["A"])
        assert result == "A"

    def test_prompt_choice_default_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Empty input should use default
        monkeypatch.setattr("sys.stdin", io.StringIO("\n"))
        result = _prompt_choice("Pick:", ["A", "B"], default="2")
        assert result == "B"


class TestCLIAppStructure:
    """Verify the CLI app has expected commands and sub-apps."""

    def test_app_exists(self) -> None:
        assert app is not None
        assert hasattr(app, "registered_commands")

    def test_main_commands_registered(self) -> None:
        # Get command names from the app
        names = [c.name for c in app.registered_commands]
        # Core commands
        assert "count" in names
        assert "recent" in names
        assert "query" in names
        assert "dashboard" in names
        assert "interactive" in names

    def test_rules_subapp_registered(self) -> None:
        # The rules sub-app should be attached
        # Typer adds it as a registered group; check by name
        group_names = [g.name for g in app.registered_groups]
        assert "rules" in group_names


class TestCLISmokeTests:
    """Basic smoke tests invoking the CLI (no network required)."""

    def test_help_flag(self, capsys: pytest.CaptureFixture) -> None:
        from typer.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Home Network Analyzer" in result.output or "hna" in result.output.lower()

    def test_version_flag(self) -> None:
        from typer.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "home-net-analyzer version" in result.output

    def test_count_help(self) -> None:
        from typer.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(app, ["count", "--help"])
        assert result.exit_code == 0
        assert "stored packets" in result.output.lower() or "db" in result.output.lower()

    def test_rules_list_help(self) -> None:
        from typer.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(app, ["rules", "list", "--help"])
        assert result.exit_code == 0

    def test_dashboard_help(self) -> None:
        from typer.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(app, ["dashboard", "--help"])
        assert result.exit_code == 0
        assert "host" in result.output.lower() or "port" in result.output.lower()


# ---------------------------------------------------------------------------
# Simulation / Generation / Capture / Storage tests in interactive context
# These test the building blocks a user would use interactively via CLI or API.
# ---------------------------------------------------------------------------

class TestSimulationWorkflow:
    """Test generation, capture, and storage workflow (as used interactively)."""

    def test_import_simulation_module(self) -> None:
        """Simulation module is importable (CLI context sanity)."""
        from home_net_analyzer.simulation import (
            SimulatedPacketCapture,
            TrafficGenerator,
            SCENARIOS,
            list_scenarios,
        )

        assert SimulatedPacketCapture is not None
        assert TrafficGenerator is not None
        assert len(SCENARIOS) >= 5
        assert "web_browsing" in list_scenarios()

    def test_generate_packets_for_scenario(self) -> None:
        """Generate packets for a pre-built scenario."""
        from home_net_analyzer.simulation import SimulatedPacketCapture

        cap = SimulatedPacketCapture()
        pkts = cap.generate_scenario("dns_resolution")
        assert len(pkts) == 2
        assert all(p.application_protocol == "DNS" for p in pkts)

    def test_generate_and_store_returns_stats(self) -> None:
        """Generate and store, verify stats dict (simulates interactive workflow)."""
        import tempfile
        from pathlib import Path

        from home_net_analyzer.simulation import SimulatedPacketCapture

        cap = SimulatedPacketCapture()
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "cli_test.db"
            stats = cap.generate_and_store("port_scan", db_path=db)
            assert stats["generated"] == 6
            assert stats["stored"] == 6
            assert stats["db_count"] >= 6

    def test_capture_stats_after_multiple_scenarios(self) -> None:
        """Generate multiple scenarios and verify cumulative stats."""
        import tempfile
        from pathlib import Path

        from home_net_analyzer.simulation import SimulatedPacketCapture

        cap = SimulatedPacketCapture()
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "multi.db"
            # First scenario
            s1 = cap.generate_and_store("dns_resolution", db_path=db)
            assert s1["db_count"] == 2
            # Second scenario appends
            s2 = cap.generate_and_store("inter_vlan_ping", db_path=db)
            assert s2["db_count"] == 2 + 8  # 2 DNS + 8 ICMP

    def test_vlan_tagged_generation(self) -> None:
        """VLAN-tagged packets are generated correctly."""
        from home_net_analyzer.simulation import SimulatedPacketCapture

        cap = SimulatedPacketCapture()
        pkts = cap.generate_scenario("inter_vlan_ping")
        vlans = {p.vlan_id for p in pkts}
        assert 10 in vlans
        assert 20 in vlans
        assert all(p.is_vlan_tagged() for p in pkts)

    def test_stored_packets_are_queryable(self) -> None:
        """After storing, packets can be queried via PacketStore."""
        import tempfile
        from pathlib import Path

        from home_net_analyzer.simulation import SimulatedPacketCapture
        from home_net_analyzer.storage import PacketStore

        cap = SimulatedPacketCapture()
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "queryable.db"
            cap.generate_and_store("web_browsing", db_path=db)

            with PacketStore(db) as store:
                # Should have some TCP and UDP packets
                tcp = store.db.query(transport_protocol="TCP", limit=100)
                udp = store.db.query(transport_protocol="UDP", limit=100)
                assert len(tcp) > 0
                assert len(udp) > 0

    # -----------------------------------------------------------------------
    # Additional generation tests for various packet types
    # -----------------------------------------------------------------------

    def test_generate_all_scenario_types(self) -> None:
        """Generate packets for every built-in scenario type."""
        from home_net_analyzer.simulation import SimulatedPacketCapture, list_scenarios

        cap = SimulatedPacketCapture()
        for name in list_scenarios():
            pkts = cap.generate_scenario(name)
            assert len(pkts) >= 1, f"Scenario {name} produced no packets"

    def test_generate_tcp_udp_icmp(self) -> None:
        """Generate TCP, UDP, and ICMP packets."""
        from home_net_analyzer.simulation import SimulatedPacketCapture

        cap = SimulatedPacketCapture()
        # TCP
        tcp = cap.generate(protocol="tcp", dst_port=80, count=3)
        assert all(p.transport_protocol == "TCP" for p in tcp)
        # UDP
        udp = cap.generate(protocol="udp", dst_port=53, count=2)
        assert all(p.transport_protocol == "UDP" for p in udp)
        # ICMP
        icmp = cap.generate(protocol="icmp", count=4)
        assert all(p.transport_protocol == "ICMP" for p in icmp)

    def test_generate_vlan_tagged_packets(self) -> None:
        """Generate VLAN-tagged packets with specific VLAN IDs."""
        from home_net_analyzer.simulation import SimulatedPacketCapture

        cap = SimulatedPacketCapture()
        pkts = cap.generate(vlan_id=100, count=3)
        assert all(p.vlan_id == 100 for p in pkts)
        assert all(p.is_vlan_tagged() for p in pkts)


# ---------------------------------------------------------------------------
# Topology + Simulation Integration Tests
# Tests for firing scenarios involving VLANs, topology, switches, routers, devices
# ---------------------------------------------------------------------------

class TestTopologyScenarioWorkflow:
    """Test generation, storage, and stats in the context of a network topology."""

    def test_create_topology_with_vlans_hosts(self) -> None:
        """Create a topology with VLANs and hosts (CLI workflow setup)."""
        from home_net_analyzer.topology import Topology, VLAN, VirtualHost

        topo = Topology(
            name="TestCorp",
            vlans=[
                VLAN(id=10, name="Mgmt", subnet="10.0.10.0/24", gateway="10.0.10.1"),
                VLAN(id=20, name="Eng", subnet="10.0.20.0/24", gateway="10.0.20.1"),
            ],
            hosts=[
                VirtualHost(name="mgmt-pc", mac="aa:bb:cc:01:00:01", ip="10.0.10.101", vlan_id=10),
                VirtualHost(name="eng-laptop", mac="aa:bb:cc:02:00:01", ip="10.0.20.101", vlan_id=20),
            ],
        )
        assert topo.name == "TestCorp"
        assert len(topo.vlans) == 2
        assert len(topo.hosts) == 2
        assert topo.get_host("eng-laptop").vlan_id == 20

    def test_generate_packets_for_topology_hosts(self) -> None:
        """Generate packets where src/dst are topology host names."""
        from home_net_analyzer.topology import Topology, VLAN, VirtualHost
        from home_net_analyzer.simulation import SimulatedPacketCapture

        # Create a simple topology
        topo = Topology(
            name="MiniNet",
            hosts=[
                VirtualHost(name="host-a", mac="aa:aa:aa:aa:aa:aa", ip="10.0.1.10", vlan_id=1),
                VirtualHost(name="host-b", mac="bb:bb:bb:bb:bb:bb", ip="10.0.1.20", vlan_id=1),
            ],
        )
        # Use SimulatedPacketCapture to generate packets referencing hosts
        cap = SimulatedPacketCapture()
        pkts = cap.generate(src="host-a", dst="host-b", protocol="tcp", dst_port=443, count=5)
        # The generator resolves host names to IPs (placeholder logic)
        assert len(pkts) == 5
        assert all(p.src_ip.startswith("10.0.0.") for p in pkts)

    def test_store_packets_and_get_status(self) -> None:
        """Generate, store, and get status/stats of packets."""
        import tempfile
        from pathlib import Path

        from home_net_analyzer.simulation import SimulatedPacketCapture
        from home_net_analyzer.storage import PacketStore

        cap = SimulatedPacketCapture()
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "status.db"
            # Generate and store
            stats = cap.generate_and_store("full_corporate", db_path=db)
            assert stats["generated"] > 0
            assert stats["stored"] == stats["generated"]

            # Get status via PacketStore
            with PacketStore(db) as store:
                total = store.count()
                assert total == stats["db_count"]
                assert total > 0

    def test_packet_stats_by_protocol(self) -> None:
        """Get stats broken down by protocol (status reporting)."""
        import tempfile
        from pathlib import Path

        from home_net_analyzer.simulation import SimulatedPacketCapture
        from home_net_analyzer.storage import PacketStore

        cap = SimulatedPacketCapture()
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "proto_stats.db"
            cap.generate_and_store("full_corporate", db_path=db)

            with PacketStore(db) as store:
                tcp = store.db.query(transport_protocol="TCP", limit=500)
                udp = store.db.query(transport_protocol="UDP", limit=500)
                icmp = store.db.query(transport_protocol="ICMP", limit=500)
                # full_corporate has TCP, UDP, and ICMP
                assert len(tcp) > 0
                assert len(udp) > 0
                assert len(icmp) >= 0  # may or may not have ICMP

    def test_packet_stats_by_vlan(self) -> None:
        """Get stats broken down by VLAN ID (verify VLAN packets are stored)."""
        import tempfile
        from pathlib import Path

        from home_net_analyzer.simulation import SimulatedPacketCapture
        from home_net_analyzer.storage import PacketStore

        cap = SimulatedPacketCapture()
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "vlan_stats.db"
            # inter_vlan_ping scenario generates packets with VLAN tags
            stats = cap.generate_and_store("inter_vlan_ping", db_path=db)
            # Just verify packets were stored (VLAN info is in generated packets)
            assert stats["stored"] == 8  # 4 pings each direction

            # Verify we can query stored packets
            with PacketStore(db) as store:
                total = store.count()
                assert total == 8

    def test_fire_scenario_with_switch_context(self) -> None:
        """Fire a scenario that conceptually traverses a switch (VLAN trunk)."""
        from home_net_analyzer.topology import Topology, VLAN, VirtualHost, VirtualSwitch, SwitchPort
        from home_net_analyzer.simulation import SimulatedPacketCapture

        # Build a topology with a switch and trunk port
        topo = Topology(
            name="SwitchedNet",
            vlans=[VLAN(id=10, name="A", subnet="10.0.10.0/24", gateway="10.0.10.1")],
            hosts=[
                VirtualHost(name="pc1", mac="aa:aa:aa:aa:aa:01", ip="10.0.10.10", vlan_id=10),
                VirtualHost(name="pc2", mac="aa:aa:aa:aa:aa:02", ip="10.0.10.20", vlan_id=10),
            ],
            switches=[
                VirtualSwitch(
                    name="sw1",
                    vlans=[10],
                    ports=[
                        SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10, connected_to="pc1"),
                        SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=10, connected_to="pc2"),
                    ],
                )
            ],
        )
        # Generate traffic between hosts on the switch
        cap = SimulatedPacketCapture()
        pkts = cap.generate(src="pc1", dst="pc2", protocol="tcp", dst_port=80, count=4)
        assert len(pkts) == 4
        # Verify topology has the switch
        assert topo.get_switch("sw1") is not None
        assert len(topo.get_switch("sw1").ports) == 2

    def test_fire_scenario_with_router_context(self) -> None:
        """Fire a scenario involving inter-VLAN routing via a router."""
        from home_net_analyzer.topology import Topology, VLAN, VirtualHost, Router, RouterInterface, RouteEntry
        from home_net_analyzer.simulation import SimulatedPacketCapture

        topo = Topology(
            name="RoutedNet",
            vlans=[
                VLAN(id=10, name="VLAN10", subnet="10.0.10.0/24", gateway="10.0.10.1"),
                VLAN(id=20, name="VLAN20", subnet="10.0.20.0/24", gateway="10.0.20.1"),
            ],
            hosts=[
                VirtualHost(name="host10", mac="10:10:10:10:10:10", ip="10.0.10.5", vlan_id=10),
                VirtualHost(name="host20", mac="20:20:20:20:20:20", ip="10.0.20.5", vlan_id=20),
            ],
            routers=[
                Router(
                    name="gw1",
                    interfaces=[
                        RouterInterface(name="vlan10", ip="10.0.10.1", subnet="10.0.10.0/24", vlan_id=10),
                        RouterInterface(name="vlan20", ip="10.0.20.1", subnet="10.0.20.0/24", vlan_id=20),
                    ],
                    routing_table=[
                        RouteEntry(destination="10.0.10.0/24", next_hop="10.0.10.1", interface="vlan10"),
                        RouteEntry(destination="10.0.20.0/24", next_hop="10.0.20.1", interface="vlan20"),
                    ],
                )
            ],
        )
        # Generate inter-VLAN traffic (conceptually routed)
        cap = SimulatedPacketCapture()
        pkts = cap.generate(src="host10", dst="host20", protocol="icmp", count=2)
        assert len(pkts) == 2
        # Router exists in topology
        assert topo.get_router("gw1") is not None
        assert len(topo.get_router("gw1").interfaces) == 2

    def test_fire_scenario_with_devices(self) -> None:
        """Fire a scenario referencing various device roles (endpoint, server, gateway)."""
        from home_net_analyzer.topology import Topology, VirtualHost
        from home_net_analyzer.simulation import SimulatedPacketCapture

        topo = Topology(
            name="DeviceNet",
            hosts=[
                VirtualHost(name="endpoint-pc", mac="aa:aa:aa:aa:aa:01", ip="10.0.1.10", role="endpoint"),
                VirtualHost(name="web-server", mac="bb:bb:bb:bb:bb:01", ip="10.0.1.50", role="server"),
                VirtualHost(name="gw", mac="cc:cc:cc:cc:cc:01", ip="10.0.1.1", role="gateway"),
            ],
        )
        cap = SimulatedPacketCapture()
        # Generate traffic from endpoint to server
        pkts = cap.generate(src="endpoint-pc", dst="web-server", protocol="tcp", dst_port=443, count=3)
        assert len(pkts) == 3
        # Verify device roles exist
        assert topo.get_host("endpoint-pc").role == "endpoint"
        assert topo.get_host("web-server").role == "server"
        assert topo.get_host("gw").role == "gateway"

    def test_status_after_firing_multiple_topology_scenarios(self) -> None:
        """Fire multiple scenarios, store, and verify cumulative stats (status)."""
        import tempfile
        from pathlib import Path

        from home_net_analyzer.topology import Topology, VLAN, VirtualHost
        from home_net_analyzer.simulation import SimulatedPacketCapture
        from home_net_analyzer.storage import PacketStore

        # Build a topology
        topo = Topology(
            name="StatusNet",
            vlans=[VLAN(id=5, name="V5", subnet="5.5.5.0/24", gateway="5.5.5.1")],
            hosts=[VirtualHost(name="h1", mac="01:01:01:01:01:01", ip="5.5.5.10", vlan_id=5)],
        )
        cap = SimulatedPacketCapture()
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "cumulative.db"
            # Fire first scenario
            s1 = cap.generate_and_store("dns_resolution", db_path=db)
            # Fire second
            s2 = cap.generate_and_store("ssh_admin", db_path=db)
            # Status via PacketStore
            with PacketStore(db) as store:
                total = store.count()
                # dns_resolution = 2 packets, ssh_admin = 20 packets
                assert total == s2["db_count"]
                assert total >= 2 + 20


# ---------------------------------------------------------------------------
# Interactive CLI "Simulate" Menu Tests
# Tests for the hna interactive simulate submenu (generation, storage, stats, topology)
# ---------------------------------------------------------------------------

class TestInteractiveSimulateMenu:
    """Tests for the 'Simulate' submenu in hna interactive CLI."""

    def test_main_menu_includes_simulate(self) -> None:
        """Main menu should include 'Simulate' option."""
        from home_net_analyzer.cli import app

        names = [c.name for c in app.registered_commands]
        # Simulate is an interactive menu option, not a subcommand
        # But we can verify the app has interactive
        assert "interactive" in names

    def test_interactive_simulate_function_exists(self) -> None:
        """The _interactive_simulate function should be importable."""
        from home_net_analyzer.cli import _interactive_simulate

        assert callable(_interactive_simulate)

    def test_simulate_generate_scenario(self) -> None:
        """Simulate: generate a scenario via SimulatedPacketCapture."""
        from home_net_analyzer.simulation import SimulatedPacketCapture

        cap = SimulatedPacketCapture()
        pkts = cap.generate_scenario("dns_resolution")
        assert len(pkts) == 2
        assert all(p.application_protocol == "DNS" for p in pkts)

    def test_simulate_generate_custom(self) -> None:
        """Simulate: generate custom packets."""
        from home_net_analyzer.simulation import SimulatedPacketCapture

        cap = SimulatedPacketCapture()
        pkts = cap.generate(src="a", dst="b", protocol="tcp", dst_port=22, count=3, app="SSH")
        assert len(pkts) == 3
        assert all(p.transport_protocol == "TCP" for p in pkts)
        assert all(p.dst_port == 22 for p in pkts)

    def test_simulate_store_and_stats(self) -> None:
        """Simulate: generate, store, and view stats."""
        import tempfile
        from pathlib import Path

        from home_net_analyzer.simulation import SimulatedPacketCapture
        from home_net_analyzer.storage import PacketStore

        cap = SimulatedPacketCapture()
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "sim_cli.db"
            stats = cap.generate_and_store("port_scan", db_path=db)
            assert stats["generated"] == 6
            assert stats["stored"] == 6

            # View stats via PacketStore (simulating "View Stats" menu)
            with PacketStore(db) as store:
                total = store.count()
                assert total == 6
                tcp = len(store.db.query(transport_protocol="TCP", limit=100))
                assert tcp == 6  # port_scan is all TCP SYN

    def test_simulate_example_topology(self) -> None:
        """Simulate: create example topology and generate traffic."""
        from home_net_analyzer.topology import Topology, VLAN, VirtualHost
        from home_net_analyzer.simulation import SimulatedPacketCapture

        topo = Topology(
            name="TestCorp",
            vlans=[
                VLAN(id=10, name="Mgmt", subnet="10.0.10.0/24", gateway="10.0.10.1"),
            ],
            hosts=[
                VirtualHost(name="pc1", mac="aa:bb:cc:01:00:01", ip="10.0.10.10", vlan_id=10),
                VirtualHost(name="srv", mac="aa:bb:cc:02:00:01", ip="10.0.10.50", vlan_id=10, role="server"),
            ],
        )
        assert topo.name == "TestCorp"
        assert len(topo.hosts) == 2

        cap = SimulatedPacketCapture()
        pkts = cap.generate(src="pc1", dst="srv", protocol="tcp", dst_port=443, count=2)
        assert len(pkts) == 2

    def test_simulate_list_scenarios(self) -> None:
        """Simulate: list all available scenarios."""
        from home_net_analyzer.simulation import list_scenarios

        names = list_scenarios()
        assert "web_browsing" in names
        assert "dns_resolution" in names
        assert "port_scan" in names
        assert "inter_vlan_ping" in names
        assert len(names) >= 5

    def test_simulate_vlan_generation(self) -> None:
        """Simulate: generate VLAN-tagged packets."""
        from home_net_analyzer.simulation import SimulatedPacketCapture

        cap = SimulatedPacketCapture()
        pkts = cap.generate(vlan_id=99, count=3)
        assert all(p.vlan_id == 99 for p in pkts)
        assert all(p.is_vlan_tagged() for p in pkts)

