"""Main Flet application with navigation and routing.

This scaffolds the desktop GUI with a NavigationRail sidebar and
placeholder content for each screen.
"""

from __future__ import annotations

import flet as ft

from home_net_analyzer.desktop.theme import apply_dark_theme
from home_net_analyzer.desktop.state import get_app_state
from home_net_analyzer.desktop.events import get_event_bus
from home_net_analyzer.desktop.components.log_panel import LogPanel

# Import view builders
from home_net_analyzer.desktop.views import (
    build_dashboard_view,
    build_topology_view,
    build_device_detail_view,
    build_simulation_view,
    build_flow_trace_view,
    build_packet_view,
    build_rules_view,
    build_settings_view,
)

# Navigation destinations
NAV_ITEMS = [
    ("Dashboard", ft.Icons.HOME, "/"),
    ("Topology", ft.Icons.ACCOUNT_TREE, "/topology"),
    ("Device Detail", ft.Icons.INFO, "/device"),
    ("Simulation", ft.Icons.PLAY_CIRCLE, "/simulation"),
    ("Flow Trace", ft.Icons.TIMELINE, "/flow"),
    ("Packets", ft.Icons.INBOX, "/packets"),
    ("Firewall", ft.Icons.SECURITY, "/rules"),
    ("Settings", ft.Icons.SETTINGS, "/settings"),
]


def build_nav_rail(on_change: callable) -> ft.NavigationRail:
    """Build the left sidebar NavigationRail."""
    return ft.NavigationRail(
        selected_index=0,
        label_type=ft.NavigationRailLabelType.ALL,
        min_width=72,
        min_extended_width=200,
        destinations=[
            ft.NavigationRailDestination(
                icon=icon,
                selected_icon=icon,
                label=label,
            )
            for label, icon, _ in NAV_ITEMS
        ],
        on_change=on_change,
    )


def main(page: ft.Page) -> None:
    """Main entry point for the Flet app."""
    apply_dark_theme(page)
    page.title = "VLAN Emulator"
    page.window_width = 1200
    page.window_height = 800

    # State & EventBus (for future use)
    app_state = get_app_state()
    event_bus = get_event_bus()

    # Log panel
    log_panel = LogPanel()
    log_panel.append("[App] VLAN Emulator Desktop started.")

    # Content container (swapped per nav selection)
    content_area = ft.Container(expand=True)

    # Map of route -> view builder
    view_builders = {
        "/": build_dashboard_view,
        "/topology": build_topology_view,
        "/device": build_device_detail_view,
        "/simulation": build_simulation_view,
        "/flow": build_flow_trace_view,
        "/packets": build_packet_view,
        "/rules": build_rules_view,
        "/settings": build_settings_view,
    }

    def switch_view(index: int) -> None:
        """Switch the main content to the selected view."""
        route = NAV_ITEMS[index][2]
        builder = view_builders.get(route, build_dashboard_view)
        try:
            content_area.content = builder(page)
        except Exception as e:
            content_area.content = ft.Container(
                content=ft.Text(f"Error loading view: {e}", color=ft.Colors.RED),
                padding=24,
            )
        try:
            content_area.update()
        except RuntimeError:
            pass  # Control not on page yet
        log_panel.append(f"[Nav] Switched to {NAV_ITEMS[index][0]}")

    def on_nav_change(e: ft.ControlEvent) -> None:
        """Handle NavigationRail selection change."""
        switch_view(e.control.selected_index)

    # Initial view
    switch_view(0)

    # Layout: NavRail | Content + Log
    page.add(
        ft.Row(
            [
                build_nav_rail(on_nav_change),
                ft.VerticalDivider(width=1),
                ft.Column(
                    [
                        content_area,
                        ft.Divider(height=1),
                        log_panel.control,
                    ],
                    expand=True,
                ),
            ],
            expand=True,
        )
    )


def run_app() -> None:
    """Launch the Flet app (blocking)."""
    ft.app(target=main)


if __name__ == "__main__":
    run_app()
