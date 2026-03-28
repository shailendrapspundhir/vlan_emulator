"""Command-line interface for Home Network Analyzer (hna)."""

from __future__ import annotations

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


@app.command("interactive")
def cmd_interactive() -> None:
    """Launch the interactive menu-driven CLI."""
    rprint("[bold cyan]Home Network Analyzer — Interactive CLI[/bold cyan]")
    rprint("[dim]Type menu numbers to navigate. Choose 'Exit' to quit.[/dim]\n")
    while True:
        choice = _prompt_choice(
            "Main Menu",
            ["Packets", "Rules", "Dashboard", "Settings", "Exit"],
        )
        if choice == "Exit":
            rprint("[cyan]Goodbye![/cyan]")
            break
        if choice == "Packets":
            _interactive_packets()
        elif choice == "Rules":
            _interactive_rules()
        elif choice == "Dashboard":
            _interactive_dashboard()
            break  # Dashboard blocks until stopped
        elif choice == "Settings":
            _interactive_settings()
    raise typer.Exit()


if __name__ == "__main__":
    app()
