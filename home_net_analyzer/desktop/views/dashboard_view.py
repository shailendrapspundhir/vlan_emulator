"""Dashboard view - Overview and quick actions."""

from __future__ import annotations

import flet as ft


def build_dashboard_view(page: ft.Page) -> ft.Control:
    """Build the Dashboard view.

    Args:
        page: The Flet page instance.

    Returns:
        A Control containing the dashboard content.
    """
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("🏠 Dashboard", size=28, weight=ft.FontWeight.BOLD),
                ft.Text(
                    "Welcome to VLAN Emulator Desktop. Use the sidebar to navigate.",
                    size=14,
                    color=ft.Colors.GREY_400,
                ),
                ft.Divider(),
                ft.Row(
                    [
                        _stat_card("Packets Stored", "0", ft.Icons.STORAGE),
                        _stat_card("Switches", "0", ft.Icons.SWAP_HORIZ),
                        _stat_card("Routers", "0", ft.Icons.ROUTER),
                        _stat_card("Rules", "0", ft.Icons.SECURITY),
                    ],
                    wrap=True,
                    spacing=16,
                ),
                ft.Divider(),
                ft.Text("Quick Actions", size=18, weight=ft.FontWeight.W_600),
                ft.Row(
                    [
                        ft.ElevatedButton(
                            "➕ New Switch",
                            icon=ft.Icons.ADD,
                            on_click=lambda e: page.go("/topology"),
                        ),
                        ft.ElevatedButton(
                            "➕ New Router",
                            icon=ft.Icons.ADD,
                            on_click=lambda e: page.go("/topology"),
                        ),
                        ft.ElevatedButton(
                            "▶ Run Scenario",
                            icon=ft.Icons.PLAY_ARROW,
                            on_click=lambda e: page.go("/simulation"),
                        ),
                        ft.ElevatedButton(
                            "📊 View Packets",
                            icon=ft.Icons.LIST,
                            on_click=lambda e: page.go("/packets"),
                        ),
                    ],
                    wrap=True,
                    spacing=12,
                ),
                ft.Divider(),
                ft.Text("Recent Activity", size=18, weight=ft.FontWeight.W_600),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("• No recent activity yet.", color=ft.Colors.GREY_500),
                        ]
                    ),
                    padding=10,
                    border=ft.border.all(1, ft.Colors.GREY_700),
                    border_radius=8,
                ),
            ],
            spacing=16,
            scroll=ft.ScrollMode.AUTO,
        ),
        padding=24,
        expand=True,
    )


def _stat_card(title: str, value: str, icon: str) -> ft.Container:
    """Create a small stat card."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Icon(icon, size=28, color=ft.Colors.GREEN_400),
                ft.Text(value, size=24, weight=ft.FontWeight.BOLD),
                ft.Text(title, size=12, color=ft.Colors.GREY_400),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=4,
        ),
        width=140,
        height=100,
        padding=16,
        border=ft.border.all(1, ft.Colors.GREY_700),
        border_radius=12,
        alignment=ft.alignment.center,
    )
