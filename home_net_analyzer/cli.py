"""Command-line interface for Home Network Analyzer (hna)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from home_net_analyzer import __version__
from home_net_analyzer.config import Settings, get_settings
from home_net_analyzer.rules import RulesEngine, Rule, RuleAction, RuleTarget
from home_net_analyzer.storage.packet_store import PacketStore
from home_net_analyzer.simulation.switch import SwitchEngine, SwitchFrame
from home_net_analyzer.simulation.router import (
    RouterEngine,
    RouteEntry,
    RouteType,
    RouterInterface,
    SVI,
)
from home_net_analyzer.simulation.network import (
    NetworkSimulationEngine,
    ScenarioBuilder,
    ProtocolSimulator,
)
from home_net_analyzer.topology.models import SwitchPort, VirtualSwitch

# Path for persistence
SWITCH_STATE_FILE = Path("data/switches.json")
ROUTER_STATE_FILE = Path("data/routers.json")

console = Console()

# Global rules engine instance (uses noop for safety; can be configured)
_rules_engine: RulesEngine | None = None


def get_rules_engine() -> RulesEngine:
    global _rules_engine
    if _rules_engine is None:
        _rules_engine = RulesEngine(backend="noop")
    return _rules_engine


app = typer.Typer(
    name="hna",
    help="Home Network Analyzer - capture, store, and query network packets.",
    add_completion=False,
)


def version_callback(value: bool) -> None:
    if value:
        rprint(f"home-net-analyzer version: {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Home Network Analyzer CLI."""
    pass


# ---------------------------------------------------------------------------
# Storage commands
# ---------------------------------------------------------------------------


@app.command("count")
def cmd_count(
    db: Optional[Path] = typer.Option(
        None,
        "--db",
        "-d",
        help="Path to SQLite database file.",
    ),
) -> None:
    """Show number of stored packets."""
    settings = get_settings()
    db_path = db or settings.get_database_path()
    with PacketStore(db_path) as store:
        rprint(f"Total packets stored: [bold]{store.count()}[/bold]")


@app.command("recent")
def cmd_recent(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of recent packets to show."),
    db: Optional[Path] = typer.Option(None, "--db", "-d", help="Path to database file."),
) -> None:
    """Show recent captured packets."""
    settings = get_settings()
    db_path = db or settings.get_database_path()
    with PacketStore(db_path) as store:
        rows = store.recent(limit=limit)
        if not rows:
            rprint("[yellow]No packets stored yet.[/yellow]")
            return
        table = Table(title=f"Recent {len(rows)} Packets")
        table.add_column("ID", style="cyan")
        table.add_column("Time", style="green")
        table.add_column("Src IP", style="blue")
        table.add_column("Dst IP", style="blue")
        table.add_column("Proto", style="magenta")
        table.add_column("Len", justify="right")
        for r in rows:
            table.add_row(
                str(r.id or "-"),
                r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                r.src_ip or "-",
                r.dst_ip or "-",
                r.transport_protocol or "-",
                str(r.length),
            )
        rprint(table)


@app.command("query")
def cmd_query(
    src_ip: Optional[str] = typer.Option(None, "--src", help="Filter by source IP."),
    dst_ip: Optional[str] = typer.Option(None, "--dst", help="Filter by destination IP."),
    proto: Optional[str] = typer.Option(None, "--proto", help="Filter by transport protocol."),
    app_proto: Optional[str] = typer.Option(None, "--app", help="Filter by application protocol."),
    limit: int = typer.Option(50, "--limit", "-n", help="Max results."),
    db: Optional[Path] = typer.Option(None, "--db", "-d", help="Path to database."),
) -> None:
    """Query stored packets with filters."""
    settings = get_settings()
    db_path = db or settings.get_database_path()
    with PacketStore(db_path) as store:
        rows = store.db.query(
            src_ip=src_ip,
            dst_ip=dst_ip,
            transport_protocol=proto,
            application_protocol=app_proto,
            limit=limit,
        )
        if not rows:
            rprint("[yellow]No matching packets found.[/yellow]")
            return
        table = Table(title=f"Query Results ({len(rows)})")
        table.add_column("ID", style="cyan")
        table.add_column("Src", style="blue")
        table.add_column("Dst", style="blue")
        table.add_column("Proto", style="magenta")
        table.add_column("App", style="green")
        for r in rows:
            table.add_row(
                str(r.id or "-"),
                r.src_ip or "-",
                r.dst_ip or "-",
                r.transport_protocol or "-",
                r.application_protocol or "-",
            )
        rprint(table)


# ---------------------------------------------------------------------------
# Rules commands (full rules engine integration)
# ---------------------------------------------------------------------------

rules_app = typer.Typer(
    name="rules",
    help="Manage firewall rules (list, add, remove, enable, disable).",
    add_completion=False,
)


app.add_typer(rules_app, name="rules")


@rules_app.command("list")
def rules_list() -> None:
    """List all rules."""
    engine = get_rules_engine()
    rules = engine.list_rules()
    if not rules:
        rprint("[yellow]No rules defined.[/yellow]")
        rprint("[dim]Use 'hna rules add' to create a rule.[/dim]")
        return
    table = Table(title=f"Rules ({len(rules)})")
    table.add_column("ID", style="cyan")
    table.add_column("Action", style="green")
    table.add_column("Target", style="magenta")
    table.add_column("Value", style="blue")
    table.add_column("Proto", style="yellow")
    table.add_column("Dir")
    table.add_column("Enabled")
    for r in rules:
        table.add_row(
            str(r.id),
            r.action.value,
            r.target.value,
            r.value,
            r.protocol,
            r.direction,
            "✓" if r.enabled else "✗",
        )
    rprint(table)


@rules_app.command("add")
def rules_add(
    action: str = typer.Option(..., "--action", "-a", help="Action: block, allow, reject"),
    target: str = typer.Option(..., "--target", "-t", help="Target: ip, subnet, port, protocol, mac"),
    value: str = typer.Option(..., "--value", "-v", help="Target value (IP, subnet CIDR, port, protocol name)"),
    proto: str = typer.Option("any", "--proto", help="Protocol: any, tcp, udp, icmp"),
    direction: str = typer.Option("both", "--dir", help="Direction: in, out, both"),
    desc: Optional[str] = typer.Option(None, "--desc", help="Description"),
) -> None:
    """Add a new rule."""
    engine = get_rules_engine()
    try:
        rule = Rule(
            action=RuleAction(action),
            target=RuleTarget(target),
            value=value,
            protocol=proto,
            direction=direction,
            description=desc,
        )
    except ValueError as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)
    rid = engine.add_rule(rule)
    rprint(f"[green]Added rule #{rid}: {action} {target} {value}[/green]")


@rules_app.command("remove")
def rules_remove(id: int = typer.Option(..., "--id", "-i", help="Rule ID to remove")) -> None:
    """Remove a rule by ID."""
    engine = get_rules_engine()
    ok = engine.remove_rule(id)
    if ok:
        rprint(f"[green]Removed rule #{id}[/green]")
    else:
        rprint(f"[red]Rule #{id} not found.[/red]")
        raise typer.Exit(code=1)


@rules_app.command("enable")
def rules_enable(id: int = typer.Option(..., "--id", "-i", help="Rule ID to enable")) -> None:
    """Enable a rule by ID."""
    engine = get_rules_engine()
    ok = engine.enable_rule(id)
    if ok:
        rprint(f"[green]Enabled rule #{id}[/green]")
    else:
        rprint(f"[red]Rule #{id} not found.[/red]")
        raise typer.Exit(code=1)


@rules_app.command("disable")
def rules_disable(id: int = typer.Option(..., "--id", "-i", help="Rule ID to disable")) -> None:
    """Disable a rule by ID."""
    engine = get_rules_engine()
    ok = engine.disable_rule(id)
    if ok:
        rprint(f"[yellow]Disabled rule #{id}[/yellow]")
    else:
        rprint(f"[red]Rule #{id} not found.[/red]")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Dashboard (Web UI)
# ---------------------------------------------------------------------------


@app.command("dashboard")
def cmd_dashboard(
    host: str = typer.Option("0.0.0.0", "--host", help="Bind host."),
    port: int = typer.Option(8080, "--port", "-p", help="Bind port."),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev)."),
    backend: str = typer.Option(
        "noop",
        "--backend",
        "-b",
        help="Rules backend: noop, nftables, iptables. Or set HNA_RULES_BACKEND env var.",
    ),
) -> None:
    """Start the web dashboard server (FastAPI + Uvicorn)."""
    import os
    import uvicorn

    # Pass backend via env var so create_app picks it up
    os.environ.setdefault("HNA_RULES_BACKEND", backend)

    rprint(f"[green]Starting dashboard on http://{host}:{port}/[/green]")
    rprint(f"[dim]Rules backend: {os.environ['HNA_RULES_BACKEND']}[/dim]")
    rprint("[dim]API docs at /docs[/dim]")
    uvicorn.run(
        "home_net_analyzer.web.api:app",
        host=host,
        port=port,
        reload=reload,
    )


# ---------------------------------------------------------------------------
# Interactive CLI (menu-driven)
# ---------------------------------------------------------------------------


def _prompt_choice(prompt: str, choices: list[str], default: str | None = None) -> str:
    """Prompt user to pick from a list of choices (1-indexed)."""
    rprint(f"\n[bold]{prompt}[/bold]")
    for i, c in enumerate(choices, 1):
        rprint(f"  {i}. {c}")
    while True:
        sel = typer.prompt("Select", default=default or "1")
        try:
            idx = int(sel)
            if 1 <= idx <= len(choices):
                return choices[idx - 1]
        except ValueError:
            pass
        rprint("[red]Invalid choice. Try again.[/red]")


def _interactive_packets() -> None:
    """Packets submenu in interactive mode."""
    while True:
        choice = _prompt_choice(
            "Packets",
            ["Count", "Recent", "Query", "Back"],
        )
        if choice == "Back":
            break
        settings = get_settings()
        db_path = settings.get_database_path()
        with PacketStore(db_path) as store:
            if choice == "Count":
                rprint(f"\nTotal packets stored: [bold cyan]{store.count()}[/bold cyan]")
            elif choice == "Recent":
                limit = int(typer.prompt("How many recent packets?", default="10"))
                rows = store.recent(limit=limit)
                if not rows:
                    rprint("[yellow]No packets stored yet.[/yellow]")
                else:
                    table = Table(title=f"Recent {len(rows)} Packets")
                    table.add_column("ID", style="cyan")
                    table.add_column("Time", style="green")
                    table.add_column("Src IP", style="blue")
                    table.add_column("Dst IP", style="blue")
                    table.add_column("Proto", style="magenta")
                    table.add_column("Len", justify="right")
                    for r in rows:
                        table.add_row(
                            str(r.id or "-"),
                            r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                            r.src_ip or "-",
                            r.dst_ip or "-",
                            r.transport_protocol or "-",
                            str(r.length),
                        )
                    console.print(table)
            elif choice == "Query":
                src = typer.prompt("Source IP (blank=any)", default="") or None
                dst = typer.prompt("Dest IP (blank=any)", default="") or None
                proto = typer.prompt("Transport protocol (blank=any)", default="") or None
                app_proto = typer.prompt("App protocol (blank=any)", default="") or None
                limit = int(typer.prompt("Max results?", default="50"))
                rows = store.db.query(
                    src_ip=src,
                    dst_ip=dst,
                    transport_protocol=proto,
                    application_protocol=app_proto,
                    limit=limit,
                )
                if not rows:
                    rprint("[yellow]No matching packets found.[/yellow]")
                else:
                    table = Table(title=f"Query Results ({len(rows)})")
                    table.add_column("ID", style="cyan")
                    table.add_column("Src", style="blue")
                    table.add_column("Dst", style="blue")
                    table.add_column("Proto", style="magenta")
                    table.add_column("App", style="green")
                    for r in rows:
                        table.add_row(
                            str(r.id or "-"),
                            r.src_ip or "-",
                            r.dst_ip or "-",
                            r.transport_protocol or "-",
                            r.application_protocol or "-",
                        )
                    console.print(table)
        rprint()


def _interactive_rules() -> None:
    """Rules submenu in interactive mode."""
    engine = get_rules_engine()
    while True:
        choice = _prompt_choice(
            "Rules",
            ["List", "Add", "Remove", "Enable", "Disable", "Back"],
        )
        if choice == "Back":
            break
        if choice == "List":
            rules = engine.list_rules()
            if not rules:
                rprint("[yellow]No rules defined.[/yellow]")
            else:
                table = Table(title=f"Rules ({len(rules)})")
                table.add_column("ID", style="cyan")
                table.add_column("Action", style="green")
                table.add_column("Target", style="magenta")
                table.add_column("Value", style="blue")
                table.add_column("Proto", style="yellow")
                table.add_column("Dir")
                table.add_column("Enabled")
                for r in rules:
                    table.add_row(
                        str(r.id),
                        r.action.value,
                        r.target.value,
                        r.value,
                        r.protocol,
                        r.direction,
                        "✓" if r.enabled else "✗",
                    )
                console.print(table)
        elif choice == "Add":
            try:
                action = RuleAction(typer.prompt("Action (block/allow/reject)", default="block"))
                target = RuleTarget(typer.prompt("Target (ip/subnet/port/protocol/mac)", default="ip"))
                value = typer.prompt("Value (e.g., 192.168.1.50 or 10.0.0.0/24 or 22 or ssh)")
                proto = typer.prompt("Protocol (any/tcp/udp/icmp)", default="any")
                direction = typer.prompt("Direction (in/out/both)", default="both")
                desc = typer.prompt("Description (optional)", default="") or None
                rule = Rule(
                    action=action,
                    target=target,
                    value=value,
                    protocol=proto,
                    direction=direction,
                    description=desc,
                )
                rid = engine.add_rule(rule)
                rprint(f"[green]Added rule #{rid}[/green]")
            except ValueError as e:
                rprint(f"[red]Error: {e}[/red]")
        elif choice == "Remove":
            rid = int(typer.prompt("Rule ID to remove"))
            if engine.remove_rule(rid):
                rprint(f"[green]Removed rule #{rid}[/green]")
            else:
                rprint(f"[red]Rule #{rid} not found.[/red]")
        elif choice == "Enable":
            rid = int(typer.prompt("Rule ID to enable"))
            if engine.enable_rule(rid):
                rprint(f"[green]Enabled rule #{rid}[/green]")
            else:
                rprint(f"[red]Rule #{rid} not found.[/red]")
        elif choice == "Disable":
            rid = int(typer.prompt("Rule ID to disable"))
            if engine.disable_rule(rid):
                rprint(f"[yellow]Disabled rule #{rid}[/yellow]")
            else:
                rprint(f"[red]Rule #{rid} not found.[/red]")
        rprint()


def _interactive_dashboard() -> None:
    """Launch dashboard from interactive mode."""
    import os
    import uvicorn

    host = typer.prompt("Host", default="0.0.0.0")
    port = int(typer.prompt("Port", default="8080"))
    backend = typer.prompt("Rules backend (noop/nftables/iptables)", default="noop")
    os.environ.setdefault("HNA_RULES_BACKEND", backend)
    rprint(f"[green]Starting dashboard on http://{host}:{port}/[/green]")
    rprint("[dim]Press Ctrl+C to stop[/dim]")
    uvicorn.run("home_net_analyzer.web.api:app", host=host, port=port)


def _interactive_settings() -> None:
    """Show current settings."""
    s = get_settings()
    table = Table(title="Current Settings")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    for key in [
        "app_name",
        "debug",
        "log_level",
        "capture_interface",
        "capture_promiscuous",
        "database_path",
        "database_type",
        "bpf_filter",
    ]:
        table.add_row(key, str(getattr(s, key)))
    console.print(table)


def _interactive_simulate() -> None:
    """Simulation submenu: generate, store, stats for packet scenarios + topologies."""
    from home_net_analyzer.simulation import (
        SimulatedPacketCapture,
        list_scenarios,
        get_scenario,
    )
    from home_net_analyzer.topology import Topology, VLAN, VirtualHost

    cap = SimulatedPacketCapture()

    while True:
        choice = _prompt_choice(
            "Simulate",
            [
                "List Scenarios",
                "Generate Scenario",
                "Generate Custom",
                "Store Packets",
                "Generate + Store",
                "View Stats",
                "Example Topology",
                "Back",
            ],
        )
        if choice == "Back":
            break

        if choice == "List Scenarios":
            rprint("\n[bold]Available Scenarios:[/bold]")
            for name in list_scenarios():
                s = get_scenario(name)
                rprint(f"  • [cyan]{name}[/cyan]: {s.description or '(no description)'}")
            rprint()

        elif choice == "Generate Scenario":
            name = typer.prompt("Scenario name", default="web_browsing")
            try:
                pkts = cap.generate_scenario(name)
                rprint(f"[green]Generated {len(pkts)} packets for '{name}'.[/green]")
                # Show sample
                if pkts:
                    p = pkts[0]
                    rprint(f"  Example: {p.transport_protocol}/{p.application_protocol or '-'} "
                           f"{p.src_ip or '?'} -> {p.dst_ip or '?'} vlan={p.vlan_id or '-'}")
            except KeyError as e:
                rprint(f"[red]{e}[/red]")
            rprint()

        elif choice == "Generate Custom":
            src = typer.prompt("Src (host/IP)", default="client")
            dst = typer.prompt("Dst (host/IP)", default="server")
            proto = typer.prompt("Protocol (tcp/udp/icmp)", default="tcp")
            dport = typer.prompt("Dst port (blank=auto)", default="")
            dst_port = int(dport) if dport else None
            count = int(typer.prompt("Count", default="5"))
            app = typer.prompt("App (HTTP/DNS/SSH etc, blank=auto)", default="") or None
            vlan = typer.prompt("VLAN ID (blank=none)", default="")
            vlan_id = int(vlan) if vlan else None
            pkts = cap.generate(src=src, dst=dst, protocol=proto, dst_port=dst_port,
                                count=count, app=app, vlan_id=vlan_id)
            rprint(f"[green]Generated {len(pkts)} packets.[/green]")
            rprint()

        elif choice == "Store Packets":
            # Generate a quick scenario and store
            name = typer.prompt("Scenario to generate & store", default="dns_resolution")
            db_path = typer.prompt("DB path", default=str(get_settings().get_database_path()))
            try:
                stats = cap.generate_and_store(name, db_path=db_path)
                rprint(f"[green]Stored: {stats['stored']} (generated {stats['generated']}), DB total: {stats['db_count']}[/green]")
            except Exception as e:
                rprint(f"[red]Error: {e}[/red]")
            rprint()

        elif choice == "Generate + Store":
            name = typer.prompt("Scenario", default="web_browsing")
            db_path = typer.prompt("DB path", default=str(get_settings().get_database_path()))
            try:
                stats = cap.generate_and_store(name, db_path=db_path)
                rprint(f"[green]✓ Generated {stats['generated']} → stored {stats['stored']} → DB now has {stats['db_count']}[/green]")
            except Exception as e:
                rprint(f"[red]Error: {e}[/red]")
            rprint()

        elif choice == "View Stats":
            db_path = typer.prompt("DB path", default=str(get_settings().get_database_path()))
            try:
                with PacketStore(db_path) as store:
                    total = store.count()
                    rprint(f"\n[bold]Stats for {db_path}:[/bold]")
                    rprint(f"  Total packets: [cyan]{total}[/cyan]")
                    # Protocol breakdown
                    tcp = len(store.db.query(transport_protocol="TCP", limit=1000))
                    udp = len(store.db.query(transport_protocol="UDP", limit=1000))
                    icmp = len(store.db.query(transport_protocol="ICMP", limit=1000))
                    rprint(f"  TCP: {tcp}, UDP: {udp}, ICMP: {icmp}")
                    # Recent sample
                    recent = store.recent(limit=3)
                    if recent:
                        rprint("\n  Recent:")
                        for r in recent:
                            rprint(f"    {r.transport_protocol or '?'} {r.src_ip or '?'} → {r.dst_ip or '?'}")
            except Exception as e:
                rprint(f"[red]Error: {e}[/red]")
            rprint()

        elif choice == "Example Topology":
            rprint("\n[bold]Creating example corporate topology...[/bold]")
            topo = Topology(
                name="ExampleCorp",
                vlans=[
                    VLAN(id=10, name="Management", subnet="10.0.10.0/24", gateway="10.0.10.1"),
                    VLAN(id=20, name="Engineering", subnet="10.0.20.0/24", gateway="10.0.20.1"),
                ],
                hosts=[
                    VirtualHost(name="mgmt-pc", mac="aa:bb:cc:01:00:01", ip="10.0.10.101", vlan_id=10, role="endpoint"),
                    VirtualHost(name="eng-laptop", mac="aa:bb:cc:02:00:01", ip="10.0.20.101", vlan_id=20, role="endpoint"),
                    VirtualHost(name="web-server", mac="aa:bb:cc:03:00:01", ip="10.0.20.50", vlan_id=20, role="server"),
                ],
            )
            rprint(f"  Topology: [cyan]{topo.name}[/cyan] with {len(topo.vlans)} VLANs, {len(topo.hosts)} hosts")
            # Generate traffic between hosts
            pkts = cap.generate(src="mgmt-pc", dst="web-server", protocol="tcp", dst_port=443, count=4)
            rprint(f"  Generated {len(pkts)} packets: mgmt-pc → web-server (TLS)")
            # Store
            db_path = typer.prompt("Store to DB path (blank=skip)", default="")
            if db_path:
                stats = cap.store(pkts, db_path=db_path)
                rprint(f"  [green]Stored {stats['stored']} packets. DB total: {stats['db_count']}[/green]")
            rprint()


# ---------------------------------------------------------------------------
# Switch simulation commands
# ---------------------------------------------------------------------------


@app.command("switch")
def cmd_switch(
    action: str = typer.Argument(..., help="Action: create, list, status, mac-table, simulate, stats, delete"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Switch name"),
    vlan: Optional[int] = typer.Option(None, "--vlan", "-v", help="VLAN ID"),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Port ID"),
) -> None:
    """Switch simulation commands."""
    if action == "create":
        _switch_create(name)
    elif action == "list":
        _switch_list()
    elif action == "status":
        _switch_status(name)
    elif action == "mac-table":
        _switch_mac_table(name)
    elif action == "simulate":
        _switch_simulate(name)
    elif action == "stats":
        _switch_stats(name)
    elif action == "delete":
        _switch_delete(name)
    else:
        rprint(f"[red]Unknown action: {action}[/red]")
        rprint("Available actions: create, list, status, mac-table, simulate, stats, delete")


def _switch_create(name: Optional[str]) -> None:
    """Create an example switch and show its configuration."""
    switch_name = name or "example-sw"
    
    # Check if switch already exists
    if _switch_store.switch_exists(switch_name):
        rprint(f"[yellow]Switch '{switch_name}' already exists. Overwriting...[/yellow]")

    ports = [
        SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
        SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=10),
        SwitchPort(id=3, name="Gi1/0/3", mode="access", access_vlan=20),
        SwitchPort(id=4, name="Gi1/0/4", mode="access", access_vlan=20),
        SwitchPort(
            id=24,
            name="Gi1/0/24",
            mode="trunk",
            allowed_vlans=[10, 20]
        ),
    ]

    engine = _switch_store.create_switch(
        name=switch_name,
        ports=ports,
        vlans=[10, 20],
        native_vlan=1
    )

    rprint(f"\n[bold]Created switch: {switch_name}[/bold]")
    rprint(f"VLANs: {engine.switch.vlans}")

    table = Table(title="Ports")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Mode", style="magenta")
    table.add_column("VLAN", style="blue")

    for p in engine.switch.ports:
        vlan_info = str(p.access_vlan) if p.is_access() else f"T:{p.allowed_vlans}"
        table.add_row(str(p.id), p.name, p.mode, vlan_info)

    console.print(table)

    rprint(f"\n[green]Switch '{switch_name}' saved and ready for simulation.[/green]")
    rprint(f"Use 'hna switch mac-table --name {switch_name}' to view MAC table")
    rprint(f"Use 'hna switch simulate --name {switch_name}' to run simulations")


# ---------------------------------------------------------------------------
# Switch persistence
# ---------------------------------------------------------------------------

class SwitchStore:
    """Persistent storage for switch configurations and state.
    
    Switches are stored in a JSON file and recreated on demand.
    MAC table state is ephemeral (will be lost between sessions).
    """
    
    def __init__(self, state_file: Path = SWITCH_STATE_FILE) -> None:
        self.state_file = state_file
        self._ensure_dir()
        self._engines: dict[str, SwitchEngine] = {}
    
    def _ensure_dir(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
    
    def _load_configs(self) -> dict:
        if not self.state_file.exists():
            return {}
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def _save_configs(self, configs: dict) -> None:
        with open(self.state_file, "w") as f:
            json.dump(configs, f, indent=2)
    
    def create_switch(
        self,
        name: str,
        ports: list[SwitchPort],
        vlans: list[int],
        native_vlan: int = 1
    ) -> SwitchEngine:
        """Create and persist a new switch."""
        switch = VirtualSwitch(name=name, ports=ports, vlans=vlans)
        engine = SwitchEngine(switch, native_vlan=native_vlan)
        
        # Save config
        configs = self._load_configs()
        configs[name] = {
            "name": name,
            "vlans": vlans,
            "native_vlan": native_vlan,
            "ports": [
                {
                    "id": p.id,
                    "name": p.name,
                    "mode": p.mode,
                    "access_vlan": p.access_vlan,
                    "allowed_vlans": p.allowed_vlans,
                }
                for p in ports
            ]
        }
        self._save_configs(configs)
        
        # Cache in memory
        self._engines[name] = engine
        return engine
    
    def get_switch(self, name: str) -> SwitchEngine | None:
        """Get a switch by name (create from config if not in memory)."""
        # Return from memory if available
        if name in self._engines:
            return self._engines[name]
        
        # Try to load from config
        configs = self._load_configs()
        if name not in configs:
            return None
        
        config = configs[name]
        ports = [
            SwitchPort(
                id=p["id"],
                name=p["name"],
                mode=p["mode"],
                access_vlan=p.get("access_vlan"),
                allowed_vlans=p.get("allowed_vlans", []),
            )
            for p in config["ports"]
        ]
        
        switch = VirtualSwitch(
            name=config["name"],
            ports=ports,
            vlans=config["vlans"]
        )
        engine = SwitchEngine(switch, native_vlan=config.get("native_vlan", 1))
        self._engines[name] = engine
        return engine
    
    def list_switches(self) -> list[str]:
        """List all saved switch names."""
        configs = self._load_configs()
        return list(configs.keys())
    
    def delete_switch(self, name: str) -> bool:
        """Delete a switch configuration."""
        configs = self._load_configs()
        if name not in configs:
            return False
        del configs[name]
        self._save_configs(configs)
        if name in self._engines:
            del self._engines[name]
        return True
    
    def switch_exists(self, name: str) -> bool:
        """Check if a switch exists."""
        configs = self._load_configs()
        return name in configs


# Global switch store instance
_switch_store = SwitchStore()


# ---------------------------------------------------------------------------
# Router persistence
# ---------------------------------------------------------------------------

class RouterStore:
    """Persistent storage for router configurations.
    
    Routers are stored in a JSON file and recreated on demand.
    ARP table and routing state is ephemeral.
    """
    
    def __init__(self, state_file: Path = ROUTER_STATE_FILE) -> None:
        self.state_file = state_file
        self._ensure_dir()
        self._engines: dict[str, RouterEngine] = {}
    
    def _ensure_dir(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
    
    def _load_configs(self) -> dict:
        if not self.state_file.exists():
            return {}
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def _save_configs(self, configs: dict) -> None:
        with open(self.state_file, "w") as f:
            json.dump(configs, f, indent=2)
    
    def create_router(
        self,
        name: str,
        svis: list[SVI],
        physical_interfaces: list[RouterInterface],
        static_routes: list[RouteEntry] | None = None
    ) -> RouterEngine:
        """Create and persist a new router."""
        router = RouterEngine(name=name)
        
        # Add SVIs
        for svi in svis:
            router.add_svi(svi)
        
        # Add physical interfaces
        for iface in physical_interfaces:
            router.add_physical_interface(iface)
        
        # Add static routes
        if static_routes:
            for route in static_routes:
                router.add_route(route)
        
        # Save config
        configs = self._load_configs()
        configs[name] = {
            "name": name,
            "svis": [
                {
                    "vlan_id": s.vlan_id,
                    "ip_address": s.ip_address,
                    "subnet_mask": s.subnet_mask,
                    "mac_address": s.mac_address,
                    "enabled": s.enabled,
                    "description": s.description,
                }
                for s in svis
            ],
            "physical_interfaces": [
                {
                    "name": i.name,
                    "ip_address": i.ip_address,
                    "subnet_mask": i.subnet_mask,
                    "mac_address": i.mac_address,
                    "enabled": i.enabled,
                    "description": i.description,
                }
                for i in physical_interfaces
            ],
            "static_routes": [
                {
                    "destination": r.destination,
                    "next_hop": r.next_hop,
                    "interface": r.interface,
                    "metric": r.metric,
                }
                for r in (static_routes or [])
            ]
        }
        self._save_configs(configs)
        
        # Cache in memory
        self._engines[name] = router
        return router
    
    def get_router(self, name: str) -> RouterEngine | None:
        """Get a router by name (create from config if not in memory)."""
        # Return from memory if available
        if name in self._engines:
            return self._engines[name]
        
        # Try to load from config
        configs = self._load_configs()
        if name not in configs:
            return None
        
        config = configs[name]
        router = RouterEngine(name=config["name"])
        
        # Recreate SVIs
        for s in config.get("svis", []):
            svi = SVI(
                vlan_id=s["vlan_id"],
                ip_address=s["ip_address"],
                subnet_mask=s["subnet_mask"],
                mac_address=s["mac_address"],
                enabled=s.get("enabled", True),
                description=s.get("description", ""),
            )
            router.add_svi(svi)
        
        # Recreate physical interfaces
        for i in config.get("physical_interfaces", []):
            iface = RouterInterface(
                name=i["name"],
                ip_address=i.get("ip_address"),
                subnet_mask=i.get("subnet_mask"),
                mac_address=i.get("mac_address"),
                enabled=i.get("enabled", True),
                description=i.get("description", ""),
            )
            router.add_physical_interface(iface)
        
        # Recreate static routes
        for r in config.get("static_routes", []):
            route = RouteEntry(
                destination=r["destination"],
                next_hop=r.get("next_hop"),
                interface=r["interface"],
                metric=r.get("metric", 1),
                route_type=RouteType.STATIC,
            )
            router.add_route(route)
        
        self._engines[name] = router
        return router
    
    def list_routers(self) -> list[str]:
        """List all saved router names."""
        configs = self._load_configs()
        return list(configs.keys())
    
    def delete_router(self, name: str) -> bool:
        """Delete a router configuration."""
        configs = self._load_configs()
        if name not in configs:
            return False
        del configs[name]
        self._save_configs(configs)
        if name in self._engines:
            del self._engines[name]
        return True
    
    def router_exists(self, name: str) -> bool:
        """Check if a router exists."""
        configs = self._load_configs()
        return name in configs


# Global router store instance
_router_store = RouterStore()


def _switch_mac_table(name: Optional[str]) -> None:
    """Show MAC table for a switch."""
    switch_name = name or "example-sw"

    engine = _switch_store.get_switch(switch_name)
    if engine is None:
        rprint(f"[red]Switch '{switch_name}' not found. Create it first with 'hna switch create --name {switch_name}'[/red]")
        return
    entries = engine.get_mac_table_entries()

    if not entries:
        rprint(f"\n[yellow]MAC table for {switch_name} is empty.[/yellow]")
        rprint("Run a simulation to populate it.")
        return

    table = Table(title=f"MAC Table: {switch_name}")
    table.add_column("MAC Address", style="cyan")
    table.add_column("VLAN", style="magenta")
    table.add_column("Port", style="green")
    table.add_column("Type", style="blue")
    table.add_column("Age (s)", style="yellow")

    for e in entries:
        table.add_row(e["mac"], str(e["vlan"]), str(e["port"]), e["type"], str(e["age"]))

    console.print(table)
    rprint(f"\nTotal entries: {len(entries)}")


def _switch_simulate(name: Optional[str]) -> None:
    """Run interactive switch simulation."""
    switch_name = name or "example-sw"

    engine = _switch_store.get_switch(switch_name)
    if engine is None:
        rprint(f"[red]Switch '{switch_name}' not found. Create it first with 'hna switch create --name {switch_name}'[/red]")
        return

    rprint(f"\n[bold]Switch Simulation: {switch_name}[/bold]")
    rprint("Simulate frame forwarding through the switch.")
    rprint()

    # Get simulation parameters
    src_mac = typer.prompt("Source MAC", default="aa:bb:cc:dd:ee:01")
    dst_mac = typer.prompt("Destination MAC", default="aa:bb:cc:dd:ee:02")
    ingress = int(typer.prompt("Ingress port", default="1"))
    vlan_str = typer.prompt("VLAN ID (blank=untagged)", default="")
    vlan_id = int(vlan_str) if vlan_str else None

    from home_net_analyzer.capture.models import CapturedPacket

    packet = CapturedPacket(
        src_mac=src_mac,
        dst_mac=dst_mac,
        vlan_id=vlan_id
    )
    frame = SwitchFrame(
        packet=packet,
        ingress_port=ingress,
        ingress_switch=switch_name
    )

    rprint(f"\n[dim]Processing frame...[/dim]")
    decisions = engine.process_frame(frame)

    if not decisions:
        rprint("[yellow]Frame dropped (no forwarding decisions)[/yellow]")
    else:
        rprint(f"[green]Forwarding decisions ({len(decisions)}):[/green]")
        for d in decisions:
            vlan_action = f" (VLAN {d.egress_vlan})" if d.egress_vlan else ""
            rprint(f"  → Port {d.port_id}: {d.vlan_action.value}{vlan_action}")

    # Show updated MAC table
    rprint(f"\n[bold]Updated MAC Table:[/bold]")
    entries = engine.get_mac_table_entries()
    if entries:
        table = Table()
        table.add_column("MAC", style="cyan")
        table.add_column("VLAN", style="magenta")
        table.add_column("Port", style="green")
        for e in entries:
            table.add_row(e["mac"], str(e["vlan"]), str(e["port"]))
        console.print(table)
    else:
        rprint("  (empty)")


def _switch_stats(name: Optional[str]) -> None:
    """Show switch statistics."""
    switch_name = name or "example-sw"

    engine = _switch_store.get_switch(switch_name)
    if engine is None:
        rprint(f"[red]Switch '{switch_name}' not found. Create it first with 'hna switch create --name {switch_name}'[/red]")
        return
    stats = engine.get_stats()

    rprint(f"\n[bold]Statistics for {stats['switch_name']}:[/bold]")

    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Frames Received", str(stats["frames_received"]))
    table.add_row("Frames Forwarded", str(stats["frames_forwarded"]))
    table.add_row("Frames Flooded", str(stats["frames_flooded"]))
    table.add_row("Frames Dropped", str(stats["frames_dropped"]))
    table.add_row("Known Unicast", str(stats["unicast_known"]))
    table.add_row("Unknown Unicast", str(stats["unicast_unknown"]))
    table.add_row("Broadcast", str(stats["broadcast_received"]))
    table.add_row("Multicast", str(stats["multicast_received"]))

    console.print(table)

    # MAC table stats
    mac_stats = stats["mac_table_stats"]
    rprint(f"\n[bold]MAC Table Stats:[/bold]")
    rprint(f"  Learned: {mac_stats['learned']}")
    rprint(f"  Lookups: {mac_stats['lookups']}")
    rprint(f"  Hits: {mac_stats['hits']}")
    rprint(f"  Misses: {mac_stats['misses']}")


def _switch_list() -> None:
    """List all saved switches."""
    switches = _switch_store.list_switches()
    
    if not switches:
        rprint("[yellow]No switches found. Create one with 'hna switch create --name <name>'[/yellow]")
        return
    
    rprint(f"\n[bold]Saved Switches ({len(switches)}):[/bold]")
    for name in switches:
        rprint(f"  • {name}")
    rprint(f"\nUse 'hna switch status --name <name>' for details")


def _switch_status(name: Optional[str]) -> None:
    """Show switch configuration and status."""
    switch_name = name or "example-sw"
    
    engine = _switch_store.get_switch(switch_name)
    if engine is None:
        rprint(f"[red]Switch '{switch_name}' not found. Create it first with 'hna switch create --name {switch_name}'[/red]")
        return
    
    switch = engine.switch
    rprint(f"\n[bold]Switch: {switch.name}[/bold]")
    rprint(f"VLANs: {switch.vlans}")
    rprint(f"Native VLAN: {engine.native_vlan}")
    rprint(f"MAC Table Entries: {engine.mac_table.get_entry_count()}")
    
    table = Table(title="Ports")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Mode", style="magenta")
    table.add_column("VLAN Config", style="blue")
    
    for p in switch.ports:
        if p.is_access():
            vlan_info = f"access VLAN {p.access_vlan}"
        else:
            vlan_info = f"trunk allowed: {p.allowed_vlans}"
        table.add_row(str(p.id), p.name, p.mode, vlan_info)
    
    console.print(table)


def _switch_delete(name: Optional[str]) -> None:
    """Delete a switch."""
    switch_name = name
    
    if not switch_name:
        rprint("[red]Switch name required. Use: hna switch delete --name <name>[/red]")
        return
    
    if not _switch_store.switch_exists(switch_name):
        rprint(f"[red]Switch '{switch_name}' not found.[/red]")
        return
    
    if _switch_store.delete_switch(switch_name):
        rprint(f"[green]Switch '{switch_name}' deleted.[/green]")
    else:
        rprint(f"[red]Failed to delete switch '{switch_name}'.[/red]")


# ---------------------------------------------------------------------------
# Router CLI commands
# ---------------------------------------------------------------------------


@app.command("router")
def cmd_router(
    action: str = typer.Argument(..., help="Action: create, list, status, routes, arp, simulate, stats, delete"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Router name"),
) -> None:
    """Router simulation commands."""
    if action == "create":
        _router_create(name)
    elif action == "list":
        _router_list()
    elif action == "status":
        _router_status(name)
    elif action == "routes":
        _router_routes(name)
    elif action == "arp":
        _router_arp(name)
    elif action == "simulate":
        _router_simulate(name)
    elif action == "stats":
        _router_stats(name)
    elif action == "delete":
        _router_delete(name)
    else:
        rprint(f"[red]Unknown action: {action}[/red]")
        rprint("Available actions: create, list, status, routes, arp, simulate, stats, delete")


def _router_create(name: Optional[str]) -> None:
    """Create an example router with SVIs."""
    router_name = name or "example-router"
    
    # Check if router already exists
    if _router_store.router_exists(router_name):
        rprint(f"[yellow]Router '{router_name}' already exists. Overwriting...[/yellow]")

    # Create SVIs for VLAN routing
    svis = [
        SVI(
            vlan_id=10,
            ip_address="192.168.10.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:00:00:10",
            description="VLAN 10 Gateway"
        ),
        SVI(
            vlan_id=20,
            ip_address="192.168.20.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:00:00:20",
            description="VLAN 20 Gateway"
        ),
    ]

    # Create physical interface for upstream
    physical_interfaces = [
        RouterInterface(
            name="eth0",
            ip_address="10.0.0.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:00:00:01",
            description="WAN Uplink"
        ),
    ]

    # Add default route
    static_routes = [
        RouteEntry(
            destination="0.0.0.0/0",
            next_hop="10.0.0.254",
            interface="eth0",
            metric=1
        ),
    ]

    router = _router_store.create_router(
        name=router_name,
        svis=svis,
        physical_interfaces=physical_interfaces,
        static_routes=static_routes
    )

    rprint(f"\n[bold]Created router: {router_name}[/bold]")
    
    # Show SVIs
    rprint("\n[dim]SVIs (Switched Virtual Interfaces):[/dim]")
    for svi in svis:
        rprint(f"  Vlan{svi.vlan_id}: {svi.ip_address}/24 - {svi.description}")
    
    # Show physical interfaces
    rprint("\n[dim]Physical Interfaces:[/dim]")
    for iface in physical_interfaces:
        rprint(f"  {iface.name}: {iface.ip_address}/24 - {iface.description}")
    
    # Show routes
    rprint("\n[dim]Static Routes:[/dim]")
    for route in static_routes:
        rprint(f"  {route.destination} via {route.next_hop} ({route.interface})")

    rprint(f"\n[green]Router '{router_name}' saved and ready for simulation.[/green]")
    rprint(f"Use 'hna router routes --name {router_name}' to view routing table")
    rprint(f"Use 'hna router simulate --name {router_name}' to run simulations")


def _router_list() -> None:
    """List all saved routers."""
    routers = _router_store.list_routers()
    
    if not routers:
        rprint("[yellow]No routers found. Create one with 'hna router create --name <name>'[/yellow]")
        return
    
    rprint(f"\n[bold]Saved Routers ({len(routers)}):[/bold]")
    for name in routers:
        rprint(f"  • {name}")
    rprint(f"\nUse 'hna router status --name <name>' for details")


def _router_status(name: Optional[str]) -> None:
    """Show router configuration and status."""
    router_name = name or "example-router"
    
    router = _router_store.get_router(router_name)
    if router is None:
        rprint(f"[red]Router '{router_name}' not found. Create it first with 'hna router create --name {router_name}'[/red]")
        return
    
    rprint(f"\n[bold]Router: {router.name}[/bold]")
    rprint(f"SVIs: {len(router.svis)}")
    rprint(f"Physical Interfaces: {len(router.physical_interfaces)}")
    rprint(f"Routes: {len(router.get_routes())}")
    rprint(f"ARP Entries: {router.arp_table.get_entry_count()}")
    
    # Show SVIs
    if router.svis:
        table = Table(title="SVIs")
        table.add_column("Interface", style="cyan")
        table.add_column("IP Address", style="green")
        table.add_column("Network", style="magenta")
        table.add_column("Status", style="blue")
        
        for svi in router.svis.values():
            status = "up" if svi.enabled else "down"
            table.add_row(
                f"Vlan{svi.vlan_id}",
                svi.ip_address,
                svi.get_network(),
                status
            )
        console.print(table)
    
    # Show physical interfaces
    if router.physical_interfaces:
        table = Table(title="Physical Interfaces")
        table.add_column("Name", style="cyan")
        table.add_column("IP Address", style="green")
        table.add_column("Network", style="magenta")
        table.add_column("Status", style="blue")
        
        for iface in router.physical_interfaces.values():
            status = "up" if iface.enabled else "down"
            ip = iface.ip_address or "unassigned"
            network = iface.get_network() or "N/A"
            table.add_row(iface.name, ip, network, status)
        console.print(table)


def _router_routes(name: Optional[str]) -> None:
    """Show routing table."""
    router_name = name or "example-router"
    
    router = _router_store.get_router(router_name)
    if router is None:
        rprint(f"[red]Router '{router_name}' not found.[/red]")
        return
    
    routes = router.get_routes()
    
    if not routes:
        rprint(f"\n[yellow]Routing table for {router_name} is empty.[/yellow]")
        return
    
    table = Table(title=f"Routing Table: {router_name}")
    table.add_column("Destination", style="cyan")
    table.add_column("Next Hop", style="green")
    table.add_column("Interface", style="magenta")
    table.add_column("Type", style="blue")
    table.add_column("Metric", style="yellow")
    
    for r in routes:
        next_hop = r.next_hop or "connected"
        table.add_row(r.destination, next_hop, r.interface, r.route_type.value, str(r.metric))
    
    console.print(table)
    rprint(f"\nTotal routes: {len(routes)}")


def _router_arp(name: Optional[str]) -> None:
    """Show ARP table."""
    router_name = name or "example-router"
    
    router = _router_store.get_router(router_name)
    if router is None:
        rprint(f"[red]Router '{router_name}' not found.[/red]")
        return
    
    entries = router.get_arp_entries()
    
    if not entries:
        rprint(f"\n[yellow]ARP table for {router_name} is empty.[/yellow]")
        rprint("Run a simulation to populate it.")
        return
    
    table = Table(title=f"ARP Table: {router_name}")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="green")
    table.add_column("Interface", style="magenta")
    table.add_column("Type", style="blue")
    table.add_column("Age (s)", style="yellow")
    
    for e in entries:
        table.add_row(e["ip"], e["mac"], e["interface"], e["type"], str(e["age"]))
    
    console.print(table)
    rprint(f"\nTotal entries: {len(entries)}")


def _router_simulate(name: Optional[str]) -> None:
    """Run interactive router simulation."""
    router_name = name or "example-router"
    
    router = _router_store.get_router(router_name)
    if router is None:
        rprint(f"[red]Router '{router_name}' not found. Create it first with 'hna router create --name {router_name}'[/red]")
        return
    
    rprint(f"\n[bold]Router Simulation: {router_name}[/bold]")
    rprint("Simulate packet routing through the router.")
    rprint()
    
    # Pre-populate ARP table with some entries for demonstration
    router.learn_arp("192.168.10.10", "aa:bb:cc:10:00:01", "Vlan10")
    router.learn_arp("192.168.10.20", "aa:bb:cc:10:00:02", "Vlan10")
    router.learn_arp("192.168.20.10", "aa:bb:cc:20:00:01", "Vlan20")
    router.learn_arp("192.168.20.20", "aa:bb:cc:20:00:02", "Vlan20")
    router.learn_arp("10.0.0.254", "aa:bb:cc:00:ff:fe", "eth0")
    
    # Get simulation parameters
    src_ip = typer.prompt("Source IP", default="192.168.10.10")
    dst_ip = typer.prompt("Destination IP", default="192.168.20.10")
    ingress = typer.prompt("Ingress interface", default="Vlan10")
    
    from home_net_analyzer.capture.models import CapturedPacket
    
    packet = CapturedPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac="aa:bb:cc:dd:ee:01",
        dst_mac="aa:bb:cc:00:00:10"  # Router's MAC
    )
    
    rprint(f"\n[dim]Processing packet...[/dim]")
    decision = router.process_packet(packet, ingress)
    
    rprint(f"\n[bold]Forwarding Decision:[/bold]")
    if decision.action == "forward":
        rprint(f"[green]Action: Forward[/green]")
        rprint(f"  Next Hop IP: {decision.next_hop_ip}")
        rprint(f"  Next Hop MAC: {decision.next_hop_mac}")
        rprint(f"  Outgoing Interface: {decision.outgoing_interface}")
    elif decision.action == "deliver_local":
        rprint(f"[blue]Action: Deliver to Router[/blue]")
        rprint(f"  Packet is destined for the router itself")
    else:
        rprint(f"[red]Action: Drop[/red]")
        rprint(f"  Reason: {decision.reason}")
    
    # Show updated stats
    stats = router.get_stats()
    rprint(f"\n[dim]Packet Stats:[/dim]")
    rprint(f"  Received: {stats['packets_received']}")
    rprint(f"  Forwarded: {stats['packets_forwarded']}")
    rprint(f"  Dropped: {stats['packets_dropped']}")


def _router_stats(name: Optional[str]) -> None:
    """Show router statistics."""
    router_name = name or "example-router"
    
    router = _router_store.get_router(router_name)
    if router is None:
        rprint(f"[red]Router '{router_name}' not found.[/red]")
        return
    
    stats = router.get_stats()
    
    rprint(f"\n[bold]Statistics for {stats['router_name']}:[/bold]")
    
    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Packets Received", str(stats["packets_received"]))
    table.add_row("Packets Forwarded", str(stats["packets_forwarded"]))
    table.add_row("Packets Dropped", str(stats["packets_dropped"]))
    table.add_row("Packets to Self", str(stats["packets_to_self"]))
    table.add_row("Routing Failures", str(stats["routing_failures"]))
    table.add_row("ARP Failures", str(stats["arp_failures"]))
    
    console.print(table)
    
    # Routing table stats
    rprint(f"\n[bold]Routing Table Stats:[/bold]")
    rt_stats = stats["routing_table_stats"]
    rprint(f"  Lookups: {rt_stats['lookups']}")
    rprint(f"  Hits: {rt_stats['hits']}")
    rprint(f"  Misses: {rt_stats['misses']}")
    
    # ARP table stats
    rprint(f"\n[bold]ARP Table Stats:[/bold]")
    arp_stats = stats["arp_table_stats"]
    rprint(f"  Learned: {arp_stats['learned']}")
    rprint(f"  Resolved: {arp_stats['resolved']}")
    rprint(f"  Failed: {arp_stats['failed']}")


def _router_delete(name: Optional[str]) -> None:
    """Delete a router."""
    router_name = name
    
    if not router_name:
        rprint("[red]Router name required. Use: hna router delete --name <name>[/red]")
        return
    
    if not _router_store.router_exists(router_name):
        rprint(f"[red]Router '{router_name}' not found.[/red]")
        return
    
    if _router_store.delete_router(router_name):
        rprint(f"[green]Router '{router_name}' deleted.[/green]")
    else:
        rprint(f"[red]Failed to delete router '{router_name}'.[/red]")


# ---------------------------------------------------------------------------
# Interactive switch simulation
# ---------------------------------------------------------------------------


def _interactive_switch_simulation() -> None:
    """Interactive switch simulation menu."""
    from home_net_analyzer.capture.models import CapturedPacket

    rprint("\n[bold]Switch Simulation[/bold]")

    # List existing switches first
    existing_switches = _switch_store.list_switches()
    if existing_switches:
        rprint("\n[dim]Existing switches:[/dim]")
        for sw in existing_switches:
            rprint(f"  • {sw}")

    # Create or select switch
    switch_name = typer.prompt("Switch name", default="lab-sw")

    engine = _switch_store.get_switch(switch_name)
    if engine is None:
        rprint(f"[yellow]Creating new switch '{switch_name}'...[/yellow]")
        num_ports = int(typer.prompt("Number of access ports", default="4"))
        vlans_input = typer.prompt("VLANs (comma-separated)", default="10,20")
        vlans = [int(v.strip()) for v in vlans_input.split(",")]

        ports = []
        for i in range(1, num_ports + 1):
            vlan = vlans[(i - 1) % len(vlans)]
            ports.append(SwitchPort(
                id=i,
                name=f"Gi1/0/{i}",
                mode="access",
                access_vlan=vlan
            ))

        # Add trunk port
        ports.append(SwitchPort(
            id=24,
            name="Gi1/0/24",
            mode="trunk",
            allowed_vlans=vlans
        ))

        engine = _switch_store.create_switch(
            name=switch_name,
            ports=ports,
            vlans=vlans
        )
        rprint(f"[green]Created and saved switch with {num_ports} access ports and 1 trunk port[/green]")

    while True:
        choice = _prompt_choice(
            f"Switch: {switch_name}",
            [
                "Send Frame",
                "View MAC Table",
                "View Stats",
                "Clear MAC Table",
                "Run Scenario",
                "Back",
            ],
        )

        if choice == "Back":
            break

        elif choice == "Send Frame":
            rprint("\n[dim]Configure frame:[/dim]")
            src_mac = typer.prompt("Source MAC", default="aa:bb:cc:dd:ee:01")
            dst_mac = typer.prompt("Dest MAC (or 'ff:ff:ff:ff:ff:ff' for broadcast)", default="aa:bb:cc:dd:ee:02")
            ingress = int(typer.prompt("Ingress port", default="1"))
            vlan_str = typer.prompt("VLAN tag (blank=untagged)", default="")
            vlan_id = int(vlan_str) if vlan_str else None

            packet = CapturedPacket(
                src_mac=src_mac,
                dst_mac=dst_mac,
                vlan_id=vlan_id
            )
            frame = SwitchFrame(
                packet=packet,
                ingress_port=ingress,
                ingress_switch=switch_name
            )

            decisions = engine.process_frame(frame)

            if decisions:
                rprint(f"\n[green]Forwarded to {len(decisions)} port(s):[/green]")
                for d in decisions:
                    rprint(f"  Port {d.port_id} ({d.vlan_action.value})")
            else:
                rprint("\n[yellow]Frame dropped[/yellow]")

        elif choice == "View MAC Table":
            entries = engine.get_mac_table_entries()
            if entries:
                table = Table(title="MAC Table")
                table.add_column("MAC", style="cyan")
                table.add_column("VLAN", style="magenta")
                table.add_column("Port", style="green")
                table.add_column("Type", style="blue")
                for e in entries:
                    table.add_row(e["mac"], str(e["vlan"]), str(e["port"]), e["type"])
                console.print(table)
            else:
                rprint("[yellow]MAC table is empty[/yellow]")

        elif choice == "View Stats":
            stats = engine.get_stats()
            rprint(f"\nFrames: {stats['frames_received']} received, "
                   f"{stats['frames_forwarded']} forwarded, "
                   f"{stats['frames_flooded']} flooded")
            rprint(f"MAC table: {stats['mac_table_stats']['learned']} learned, "
                   f"{stats['mac_table_stats']['hits']} hits")

        elif choice == "Clear MAC Table":
            cleared = engine.clear_mac_table()
            rprint(f"[green]Cleared {cleared} MAC table entries[/green]")

        elif choice == "Run Scenario":
            scenario = _prompt_choice(
                "Select scenario",
                [
                    "MAC Learning",
                    "VLAN Isolation",
                    "Broadcast Storm",
                    "Trunk Test",
                    "Unknown Unicast Flooding",
                    "Back",
                ],
            )

            if scenario == "Back":
                continue

            if scenario == "MAC Learning":
                rprint("\n[bold]MAC Learning Scenario[/bold]")
                rprint("Learning 4 hosts on different ports...")
                hosts = [
                    ("aa:bb:cc:01:01:01", 1, 10),
                    ("aa:bb:cc:01:02:02", 2, 10),
                    ("aa:bb:cc:02:01:01", 3, 20),
                    ("aa:bb:cc:02:02:02", 4, 20),
                ]

                for mac, port, vlan in hosts:
                    packet = CapturedPacket(
                        src_mac=mac,
                        dst_mac="ff:ff:ff:ff:ff:ff",
                        vlan_id=None
                    )
                    frame = SwitchFrame(
                        packet=packet,
                        ingress_port=port,
                        ingress_switch=switch_name
                    )
                    engine.process_frame(frame)
                    rprint(f"  ✓ Learned {mac} on port {port} (VLAN {vlan})")

                rprint("\n[green]MAC table populated! Try 'View MAC Table' to see entries.[/green]")

            elif scenario == "VLAN Isolation":
                rprint("\n[bold]VLAN Isolation Test[/bold]")
                rprint("Testing that VLAN 10 cannot reach VLAN 20...")

                # Learn hosts in both VLANs
                for mac, port, vlan in [("aa:bb:cc:01:01:01", 1, 10), ("aa:bb:cc:02:01:01", 3, 20)]:
                    packet = CapturedPacket(
                        src_mac=mac,
                        dst_mac="ff:ff:ff:ff:ff:ff",
                        vlan_id=None
                    )
                    frame = SwitchFrame(packet=packet, ingress_port=port, ingress_switch=switch_name)
                    engine.process_frame(frame)

                # Try to send from VLAN 10 to VLAN 20
                packet = CapturedPacket(
                    src_mac="aa:bb:cc:01:01:01",
                    dst_mac="aa:bb:cc:02:01:01",
                    vlan_id=None
                )
                frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch=switch_name)
                decisions = engine.process_frame(frame)

                if not decisions:
                    rprint("[green]✓ Correctly isolated - no forwarding between VLANs[/green]")
                else:
                    rprint(f"[red]✗ Error: forwarded to {len(decisions)} ports[/red]")

            elif scenario == "Broadcast Storm":
                rprint("\n[bold]Broadcast Storm Simulation[/bold]")
                count = int(typer.prompt("Number of broadcast frames", default="5"))

                for i in range(count):
                    packet = CapturedPacket(
                        src_mac=f"aa:bb:cc:00:00:{i+1:02x}",
                        dst_mac="ff:ff:ff:ff:ff:ff",
                        vlan_id=None
                    )
                    frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch=switch_name)
                    decisions = engine.process_frame(frame)
                    rprint(f"  Frame {i+1}: flooded to {len(decisions)} ports")

                rprint(f"\n[green]Sent {count} broadcast frames[/green]")

            elif scenario == "Trunk Test":
                rprint("\n[bold]Trunk Port Test[/bold]")
                rprint("Sending tagged traffic through trunk port...")

                # Send tagged frame into trunk
                packet = CapturedPacket(
                    src_mac="aa:bb:cc:01:01:01",
                    dst_mac="ff:ff:ff:ff:ff:ff",
                    vlan_id=10
                )
                frame = SwitchFrame(packet=packet, ingress_port=24, ingress_switch=switch_name)
                decisions = engine.process_frame(frame)
                rprint(f"  Tagged VLAN 10 into trunk: flooded to {len(decisions)} ports")

                # Learn a MAC on trunk
                packet = CapturedPacket(
                    src_mac="aa:bb:cc:99:99:99",
                    dst_mac="ff:ff:ff:ff:ff:ff",
                    vlan_id=20
                )
                frame = SwitchFrame(packet=packet, ingress_port=24, ingress_switch=switch_name)
                engine.process_frame(frame)
                rprint(f"  Learned aa:bb:cc:99:99:99 on trunk port (VLAN 20)")

                # Send from access port to trunk
                packet = CapturedPacket(
                    src_mac="aa:bb:cc:01:01:01",
                    dst_mac="aa:bb:cc:99:99:99",
                    vlan_id=None
                )
                frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch=switch_name)
                decisions = engine.process_frame(frame)
                if decisions and any(d.port_id == 24 for d in decisions):
                    rprint(f"  [green]✓ Access port can reach trunk port with VLAN tag[/green]")

            elif scenario == "Unknown Unicast Flooding":
                rprint("\n[bold]Unknown Unicast Flooding[/bold]")
                rprint("Sending to unknown MAC addresses (should flood)...")

                for i in range(3):
                    packet = CapturedPacket(
                        src_mac="aa:bb:cc:01:01:01",
                        dst_mac=f"00:00:00:00:00:0{i+1}",
                        vlan_id=None
                    )
                    frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch=switch_name)
                    decisions = engine.process_frame(frame)
                    rprint(f"  To unknown MAC {i+1}: flooded to {len(decisions)} ports")

                rprint("\n[green]Unknown unicast frames flooded to all ports in VLAN[/green]")


# ---------------------------------------------------------------------------
# Interactive router simulation
# ---------------------------------------------------------------------------


def _interactive_router_simulation() -> None:
    """Interactive router simulation menu."""
    from home_net_analyzer.capture.models import CapturedPacket

    rprint("\n[bold]Router Simulation[/bold]")

    # List existing routers first
    existing_routers = _router_store.list_routers()
    if existing_routers:
        rprint("\n[dim]Existing routers:[/dim]")
        for r in existing_routers:
            rprint(f"  • {r}")

    # Create or select router
    router_name = typer.prompt("Router name", default="lab-router")

    router = _router_store.get_router(router_name)
    if router is None:
        rprint(f"[yellow]Creating new router '{router_name}'...[/yellow]")
        
        # Create default SVIs
        vlans_input = typer.prompt("VLANs for SVIs (comma-separated)", default="10,20")
        vlans = [int(v.strip()) for v in vlans_input.split(",")]
        
        base_ip = typer.prompt("Base network (e.g., 192.168)", default="192.168")
        
        svis = []
        for i, vlan in enumerate(vlans):
            svi = SVI(
                vlan_id=vlan,
                ip_address=f"{base_ip}.{vlan}.1",
                subnet_mask="255.255.255.0",
                mac_address=f"aa:bb:cc:00:{vlan:02x}:01",
                description=f"VLAN {vlan} Gateway"
            )
            svis.append(svi)
        
        # Add WAN interface
        wan_ip = typer.prompt("WAN interface IP", default="10.0.0.1")
        physical_interfaces = [
            RouterInterface(
                name="eth0",
                ip_address=wan_ip,
                subnet_mask="255.255.255.0",
                mac_address="aa:bb:cc:00:00:01",
                description="WAN Uplink"
            ),
        ]
        
        # Add default route
        default_gw = typer.prompt("Default gateway", default="10.0.0.254")
        static_routes = [
            RouteEntry(
                destination="0.0.0.0/0",
                next_hop=default_gw,
                interface="eth0",
                metric=1
            ),
        ]
        
        router = _router_store.create_router(
            name=router_name,
            svis=svis,
            physical_interfaces=physical_interfaces,
            static_routes=static_routes
        )
        rprint(f"[green]Created router with {len(svis)} SVIs and WAN interface[/green]")

    while True:
        choice = _prompt_choice(
            f"Router: {router_name}",
            [
                "Route Packet",
                "View Routing Table",
                "View ARP Table",
                "View Stats",
                "Clear ARP Table",
                "Run Scenario",
                "Back",
            ],
        )

        if choice == "Back":
            break

        elif choice == "Route Packet":
            rprint("\n[dim]Configure packet:[/dim]")
            src_ip = typer.prompt("Source IP", default="192.168.10.10")
            dst_ip = typer.prompt("Dest IP", default="192.168.20.10")
            ingress = typer.prompt("Ingress interface (e.g., Vlan10)", default="Vlan10")

            # Pre-populate ARP if needed
            if not router.arp_table.resolve(src_ip):
                mac = f"aa:bb:cc:{src_ip.split('.')[2]}:{src_ip.split('.')[3]}:01"
                router.learn_arp(src_ip, mac, ingress)

            packet = CapturedPacket(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_mac="aa:bb:cc:dd:ee:01",
                dst_mac="aa:bb:cc:00:00:10"
            )

            decision = router.process_packet(packet, ingress)

            rprint(f"\n[bold]Forwarding Decision:[/bold]")
            if decision.action == "forward":
                rprint(f"[green]Action: Forward[/green]")
                rprint(f"  Next Hop: {decision.next_hop_ip}")
                rprint(f"  Outgoing Interface: {decision.outgoing_interface}")
            elif decision.action == "deliver_local":
                rprint(f"[blue]Action: Deliver to Router[/blue]")
            else:
                rprint(f"[red]Action: Drop - {decision.reason}[/red]")

        elif choice == "View Routing Table":
            routes = router.get_routes()
            if routes:
                table = Table(title="Routing Table")
                table.add_column("Destination", style="cyan")
                table.add_column("Next Hop", style="green")
                table.add_column("Interface", style="magenta")
                for r in routes:
                    next_hop = r.next_hop or "connected"
                    table.add_row(r.destination, next_hop, r.interface)
                console.print(table)
            else:
                rprint("[yellow]Routing table is empty[/yellow]")

        elif choice == "View ARP Table":
            entries = router.get_arp_entries()
            if entries:
                table = Table(title="ARP Table")
                table.add_column("IP", style="cyan")
                table.add_column("MAC", style="green")
                table.add_column("Interface", style="magenta")
                for e in entries:
                    table.add_row(e["ip"], e["mac"], e["interface"])
                console.print(table)
            else:
                rprint("[yellow]ARP table is empty[/yellow]")

        elif choice == "View Stats":
            stats = router.get_stats()
            rprint(f"\nPackets: {stats['packets_received']} received, "
                   f"{stats['packets_forwarded']} forwarded, "
                   f"{stats['packets_dropped']} dropped")
            rprint(f"Routing: {stats['routing_table_stats']['hits']} hits, "
                   f"{stats['routing_table_stats']['misses']} misses")
            rprint(f"ARP: {stats['arp_table_stats']['resolved']} resolved, "
                   f"{stats['arp_table_stats']['failed']} failed")

        elif choice == "Clear ARP Table":
            cleared = router.clear_arp_table()
            rprint(f"[green]Cleared {cleared} ARP entries[/green]")

        elif choice == "Run Scenario":
            scenario = _prompt_choice(
                "Select scenario",
                [
                    "Inter-VLAN Routing",
                    "Default Route to Internet",
                    "ARP Learning",
                    "Longest Prefix Match",
                    "Back",
                ],
            )

            if scenario == "Back":
                continue

            if scenario == "Inter-VLAN Routing":
                rprint("\n[bold]Inter-VLAN Routing Scenario[/bold]")
                rprint("Demonstrating routing between VLAN 10 and VLAN 20...")

                # Learn ARP entries
                router.learn_arp("192.168.10.10", "aa:bb:cc:10:00:01", "Vlan10")
                router.learn_arp("192.168.20.10", "aa:bb:cc:20:00:01", "Vlan20")

                # Send packet from VLAN 10 to VLAN 20
                packet = CapturedPacket(
                    src_ip="192.168.10.10",
                    dst_ip="192.168.20.10",
                    src_mac="aa:bb:cc:10:00:01",
                    dst_mac="aa:bb:cc:00:00:10"
                )
                decision = router.process_packet(packet, "Vlan10")

                if decision.action == "forward":
                    rprint(f"[green]✓ Packet routed from VLAN 10 to VLAN 20[/green]")
                    rprint(f"  Outgoing interface: {decision.outgoing_interface}")
                else:
                    rprint(f"[red]✗ Routing failed: {decision.reason}[/red]")

            elif scenario == "Default Route to Internet":
                rprint("\n[bold]Default Route Scenario[/bold]")
                rprint("Sending packet to Internet (8.8.8.8)...")

                # Learn ARP for default gateway
                router.learn_arp("10.0.0.254", "aa:bb:cc:00:ff:fe", "eth0")

                packet = CapturedPacket(
                    src_ip="192.168.10.10",
                    dst_ip="8.8.8.8",
                    src_mac="aa:bb:cc:10:00:01",
                    dst_mac="aa:bb:cc:00:00:10"
                )
                decision = router.process_packet(packet, "Vlan10")

                if decision.action == "forward" and decision.outgoing_interface == "eth0":
                    rprint(f"[green]✓ Packet forwarded to Internet via default route[/green]")
                    rprint(f"  Next hop: {decision.next_hop_ip}")
                else:
                    rprint(f"[red]✗ Failed: {decision.reason}[/red]")

            elif scenario == "ARP Learning":
                rprint("\n[bold]ARP Learning Scenario[/bold]")
                rprint("Learning MAC addresses for hosts...")

                hosts = [
                    ("192.168.10.10", "aa:bb:cc:10:00:01", "Vlan10"),
                    ("192.168.10.20", "aa:bb:cc:10:00:02", "Vlan10"),
                    ("192.168.20.10", "aa:bb:cc:20:00:01", "Vlan20"),
                    ("192.168.20.20", "aa:bb:cc:20:00:02", "Vlan20"),
                ]

                for ip, mac, iface in hosts:
                    router.learn_arp(ip, mac, iface)
                    rprint(f"  ✓ Learned {ip} -> {mac} on {iface}")

                rprint(f"\n[green]ARP table now has {router.arp_table.get_entry_count()} entries[/green]")

            elif scenario == "Longest Prefix Match":
                rprint("\n[bold]Longest Prefix Match Scenario[/bold]")
                rprint("Testing route selection...")

                # Add more specific routes
                router.add_route(RouteEntry(
                    destination="192.168.0.0/16",
                    next_hop="10.0.0.2",
                    interface="eth0",
                    metric=1
                ))

                test_ips = ["192.168.10.50", "192.168.20.50", "10.0.0.50"]
                for ip in test_ips:
                    route = router.routing_table.lookup(ip)
                    if route:
                        rprint(f"  {ip} -> {route.destination} via {route.interface}")


# ---------------------------------------------------------------------------
# Network Simulation CLI commands
# ---------------------------------------------------------------------------


@app.command("network")
def cmd_network(
    action: str = typer.Argument(..., help="Action: simulate, scenario"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Scenario name"),
) -> None:
    """Multi-device network simulation with hop-by-hop tracing."""
    if action == "simulate":
        _interactive_network_simulation()
    elif action == "scenario":
        _network_run_scenario(name)
    else:
        rprint(f"[red]Unknown action: {action}[/red]")
        rprint("Available actions: simulate, scenario")


def _network_run_scenario(name: Optional[str]) -> None:
    """Run a predefined network scenario."""
    scenario_name = name or "router-on-stick"

    sim = NetworkSimulationEngine(name=scenario_name)

    scenarios = {
        "single-switch": ScenarioBuilder.create_single_switch_vlan,
        "multi-switch": ScenarioBuilder.create_multi_switch_trunk,
        "router-on-stick": ScenarioBuilder.create_router_on_stick,
        "multi-site": ScenarioBuilder.create_multi_site_network,
        "campus": ScenarioBuilder.create_campus_network,
    }

    if scenario_name not in scenarios:
        rprint(f"[red]Unknown scenario: {scenario_name}[/red]")
        rprint(f"Available: {', '.join(scenarios.keys())}")
        return

    rprint(f"\n[bold]Loading scenario: {scenario_name}[/bold]")
    scenarios[scenario_name](sim)

    # Show topology
    _show_network_topology(sim)

    # Run sample flows
    _run_sample_flows(sim, scenario_name)


def _show_network_topology(sim: NetworkSimulationEngine) -> None:
    """Display network topology."""
    if not sim.topology:
        return

    rprint(f"\n[bold cyan]Network Topology: {sim.topology.name}[/bold cyan]")

    # Devices
    if sim.topology.devices:
        table = Table(title="Devices")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Type", style="magenta")
        for dev in sim.topology.devices.values():
            table.add_row(dev.id, dev.name, dev.device_type.value)
        console.print(table)

    # Hosts
    if sim.topology.hosts:
        table = Table(title="Hosts")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("IP", style="blue")
        table.add_column("VLAN", style="magenta")
        table.add_column("Connected To", style="yellow")
        for host in sim.topology.hosts.values():
            table.add_row(
                host.id, host.name, host.ip,
                str(host.vlan_id) if host.vlan_id else "-",
                f"{host.connected_switch}:{host.connected_port}"
            )
        console.print(table)

    # Links
    if sim.topology.links:
        table = Table(title="Links")
        table.add_column("From", style="cyan")
        table.add_column("Port", style="green")
        table.add_column("To", style="blue")
        table.add_column("Port", style="green")
        table.add_column("Type", style="magenta")
        for link in sim.topology.links:
            table.add_row(
                link.from_device, str(link.from_port),
                link.to_device, str(link.to_port),
                link.link_type
            )
        console.print(table)


def _run_sample_flows(sim: NetworkSimulationEngine, scenario_name: str) -> None:
    """Run sample packet flows for the scenario."""
    rprint("\n[bold]Running Sample Flows:[/bold]")

    # Define sample flows based on scenario
    sample_flows = {
        "single-switch": [("pc1", "pc3", "ICMP")],  # Same VLAN
        "multi-switch": [("pc1", "pc3", "ICMP")],  # Across trunk
        "router-on-stick": [("pc1", "pc2", "ICMP")],  # Inter-VLAN
        "multi-site": [("pc1", "pc3", "ICMP")],  # Across WAN
        "campus": [("pc1", "pc5", "ICMP")],  # Across campus
    }

    flows = sample_flows.get(scenario_name, [])

    for src, dst, proto in flows:
        if src in sim.topology.hosts and dst in sim.topology.hosts:
            rprint(f"\n[dim]Flow: {src} -> {dst} ({proto})[/dim]")
            flow = sim.simulate_packet(src, dst, proto)
            _display_flow_result(flow)


def _display_flow_result(flow) -> None:
    """Display packet flow result with hop-by-hop trace."""
    if flow.success:
        rprint(f"[green]✓ Success[/green] - {flow.final_action}")
    else:
        rprint(f"[red]✗ Failed[/red] - {flow.final_action}")

    # Display hops
    if flow.hops:
        table = Table(title=f"Hop-by-Hop Trace ({len(flow.hops)} hops)")
        table.add_column("Hop", style="cyan", width=4)
        table.add_column("Device", style="green")
        table.add_column("Type", style="magenta")
        table.add_column("Action", style="blue")
        table.add_column("Ingress", style="yellow", width=8)
        table.add_column("Egress", style="yellow", width=8)
        table.add_column("Details", style="dim")

        for hop in flow.hops:
            table.add_row(
                str(hop.hop_number),
                hop.device_name,
                hop.device_type.value,
                hop.action,
                str(hop.ingress_port) if hop.ingress_port else "-",
                str(hop.egress_port) if hop.egress_port else "-",
                hop.details[:40] + "..." if len(hop.details) > 40 else hop.details
            )
        console.print(table)

        # Summary stats
        duration = flow.get_duration_ms()
        rprint(f"[dim]Duration: {duration:.2f}ms | Hops: {len(flow.hops)}[/dim]")


def _interactive_network_simulation() -> None:
    """Interactive multi-device network simulation."""
    global _current_network_sim

    rprint("\n[bold]Multi-Device Network Simulation[/bold]")
    rprint("Simulate packet flows through complex network topologies.")

    while True:
        choice = _prompt_choice(
            "Network Simulation",
            [
                "Load Scenario",
                "Custom Topology",
                "Trace Packet Flow",
                "Test Protocols",
                "View Topology",
                "Back",
            ],
        )

        if choice == "Back":
            break

        elif choice == "Load Scenario":
            scenario = _prompt_choice(
                "Select Scenario",
                [
                    "Single Switch VLAN",
                    "Multi-Switch Trunk",
                    "Router on a Stick",
                    "Multi-Site Network",
                    "Campus Network",
                    "Back",
                ],
            )

            if scenario == "Back":
                continue

            sim = NetworkSimulationEngine()

            if scenario == "Single Switch VLAN":
                ScenarioBuilder.create_single_switch_vlan(sim)
            elif scenario == "Multi-Switch Trunk":
                ScenarioBuilder.create_multi_switch_trunk(sim)
            elif scenario == "Router on a Stick":
                ScenarioBuilder.create_router_on_stick(sim)
            elif scenario == "Multi-Site Network":
                ScenarioBuilder.create_multi_site_network(sim)
            elif scenario == "Campus Network":
                ScenarioBuilder.create_campus_network(sim)

            _show_network_topology(sim)

            # Store for later use
            _current_network_sim = sim

            # Offer to run flows
            if typer.confirm("Run sample packet flows?", default=True):
                _run_interactive_flows(sim)

        elif choice == "Custom Topology":
            _create_custom_topology()

        elif choice == "Trace Packet Flow":
            if _current_network_sim is None:
                rprint("[yellow]Load a scenario first![/yellow]")
                continue
            _run_interactive_flows(_current_network_sim)

        elif choice == "Test Protocols":
            _test_protocols_menu()

        elif choice == "View Topology":
            if _current_network_sim is None:
                rprint("[yellow]Load a scenario first![/yellow]")
                continue
            _show_network_topology(_current_network_sim)


def _run_interactive_flows(sim: NetworkSimulationEngine) -> None:
    """Run interactive packet flows."""
    rprint("\n[bold]Packet Flow Tracing[/bold]")
    rprint("Available hosts:")
    for host_id, host in sim.topology.hosts.items():
        rprint(f"  • {host_id}: {host.name} ({host.ip})")

    while True:
        rprint("")
        src = typer.prompt("Source host (or 'back')", default="pc1")
        if src.lower() == "back":
            break

        dst = typer.prompt("Destination host", default="pc2")
        proto = typer.prompt("Protocol (ICMP/TCP/UDP)", default="ICMP")

        if src not in sim.topology.hosts or dst not in sim.topology.hosts:
            rprint("[red]Invalid host ID. Check available hosts above.[/red]")
            continue

        flow = sim.simulate_packet(src, dst, proto)
        _display_flow_result(flow)


def _create_custom_topology() -> None:
    """Create a custom network topology interactively."""
    global _current_network_sim

    rprint("\n[bold]Custom Topology Builder[/bold]")
    rprint("Create your own network topology.")

    sim = NetworkSimulationEngine(name="custom")
    sim.create_topology("custom")

    # Add switches
    num_switches = int(typer.prompt("Number of switches", default="1"))
    for i in range(num_switches):
        name = typer.prompt(f"Switch {i+1} name", default=f"sw{i+1}")
        num_ports = int(typer.prompt(f"  Number of ports", default="8"))

        ports = [SwitchPort(id=p, name=f"Gi1/0/{p}", mode="access", access_vlan=1)
                 for p in range(1, num_ports + 1)]

        from home_net_analyzer.simulation.switch.models import SwitchPort as SWSwitchPort
        sw_ports = [SWSwitchPort(id=p, name=f"Gi1/0/{p}", mode="access", access_vlan=1)
                    for p in range(1, num_ports + 1)]

        switch = SwitchEngine(
            switch=type('obj', (object,), {
                'name': name,
                'ports': sw_ports,
                'vlans': [1],
                'get_port': lambda self, pid: next((p for p in self.ports if p.id == pid), None)
            })()
        )
        sim.add_switch(name, f"Switch {name}", switch)
        rprint(f"[green]Added switch: {name} with {num_ports} ports[/green]")

    # Add routers
    num_routers = int(typer.prompt("Number of routers", default="0"))
    for i in range(num_routers):
        name = typer.prompt(f"Router {i+1} name", default=f"r{i+1}")
        router = RouterEngine(name=name)
        sim.add_router(name, f"Router {name}", router)
        rprint(f"[green]Added router: {name}[/green]")

    # Add hosts
    num_hosts = int(typer.prompt("Number of hosts", default="2"))
    for i in range(num_hosts):
        name = typer.prompt(f"Host {i+1} name", default=f"pc{i+1}")
        ip = typer.prompt(f"  IP address", default=f"192.168.1.{10+i}")
        mac = f"aa:bb:cc:01:00:{i+1:02x}"
        vlan = int(typer.prompt(f"  VLAN", default="1"))
        switch = typer.prompt(f"  Connected switch", default="sw1")
        port = int(typer.prompt(f"  Connected port", default=str(i+1)))

        sim.add_host(name, name, mac, ip, switch, port, vlan_id=vlan)
        rprint(f"[green]Added host: {name} ({ip})[/green]")

    _show_network_topology(sim)
    _current_network_sim = sim


def _test_protocols_menu() -> None:
    """Test protocol simulations."""
    proto_sim = ProtocolSimulator()

    while True:
        choice = _prompt_choice(
            "Protocol Testing",
            [
                "DHCP Request",
                "DNS Query",
                "Ping",
                "HTTP GET",
                "Back",
            ],
        )

        if choice == "Back":
            break

        elif choice == "DHCP Request":
            rprint("\n[bold]DHCP Transaction Simulation[/bold]")
            mac = typer.prompt("Client MAC", default="aa:bb:cc:dd:ee:01")
            subnet = typer.prompt("Subnet", default="192.168.1.0/24")

            result = proto_sim.dhcp_request(mac, subnet)

            if result["success"]:
                rprint(f"[green]✓ DHCP Success[/green]")
                rprint(f"  Assigned IP: {result['ip']}")
                rprint(f"  Gateway: {result['gateway']}")
                rprint(f"  DNS: {', '.join(result['dns_servers'])}")
                rprint(f"  Lease: {result['lease_time']}s")

            rprint("\n[dim]DORA Process:[/dim]")
            for step in result["steps"]:
                rprint(f"  {step['step']}. {step['message']}: {step['details']}")

        elif choice == "DNS Query":
            rprint("\n[bold]DNS Query Simulation[/bold]")
            name = typer.prompt("Hostname", default="google.com")
            qtype = typer.prompt("Query type (A/AAAA/MX)", default="A")

            result = proto_sim.dns_query(name, qtype)

            if result["success"]:
                rprint(f"[green]✓ DNS Resolved[/green]")
                for ans in result["answers"]:
                    rprint(f"  {ans['name']} {ans['type']} {ans['value']}")
            else:
                rprint(f"[red]✗ {result.get('error', 'Query failed')}[/red]")

        elif choice == "Ping":
            rprint("\n[bold]ICMP Ping Simulation[/bold]")
            src = typer.prompt("Source IP", default="192.168.1.10")
            dst = typer.prompt("Destination IP", default="8.8.8.8")
            count = int(typer.prompt("Count", default="4"))

            result = proto_sim.ping(src, dst, count, reachable=True, latency_ms=1.5)

            rprint(f"\nPing {dst}:")
            for r in result["results"]:
                if r["status"] == "reply":
                    rprint(f"  Reply from {dst}: time={r['time_ms']}ms TTL={r['ttl']}")
                else:
                    rprint(f"  Request timed out")

            rprint(f"\nStatistics:")
            rprint(f"  Sent: {result['packets_sent']}, Received: {result['packets_received']}")
            rprint(f"  Loss: {result['packet_loss_percent']}%")
            if result['avg_time_ms']:
                rprint(f"  RTT: min={result['min_time_ms']}ms, avg={result['avg_time_ms']}ms, max={result['max_time_ms']}ms")

        elif choice == "HTTP GET":
            rprint("\n[bold]HTTP GET Simulation[/bold]")
            url = typer.prompt("URL", default="http://example.com/")

            result = proto_sim.http_get(url)

            if result["success"]:
                rprint(f"[green]✓ HTTP {result['status_code']}[/green]")
                rprint(f"  Server: {result.get('server_ip', 'unknown')}")
                rprint(f"  Content-Type: {result['headers'].get('Content-Type', 'unknown')}")
                rprint(f"  Body: {result['body'][:100]}...")
            else:
                rprint(f"[red]✗ Error: {result.get('error', 'Request failed')}[/red]")


# Global reference for current network simulation
_current_network_sim: NetworkSimulationEngine | None = None


@app.command("interactive")
def cmd_interactive() -> None:
    """Launch the interactive menu-driven CLI."""
    rprint("[bold cyan]Home Network Analyzer — Interactive CLI[/bold cyan]")
    rprint("[dim]Type menu numbers to navigate. Choose 'Exit' to quit.[/dim]\n")
    while True:
        choice = _prompt_choice(
            "Main Menu",
            ["Packets", "Rules", "Simulate", "Switch", "Router", "Network", "Dashboard", "Settings", "Exit"],
        )
        if choice == "Exit":
            rprint("[cyan]Goodbye![/cyan]")
            break
        if choice == "Packets":
            _interactive_packets()
        elif choice == "Rules":
            _interactive_rules()
        elif choice == "Simulate":
            _interactive_simulate()
        elif choice == "Switch":
            _interactive_switch_simulation()
        elif choice == "Router":
            _interactive_router_simulation()
        elif choice == "Network":
            _interactive_network_simulation()
        elif choice == "Dashboard":
            _interactive_dashboard()
            break  # Dashboard blocks until stopped
        elif choice == "Settings":
            _interactive_settings()
    raise typer.Exit()


if __name__ == "__main__":
    app()
