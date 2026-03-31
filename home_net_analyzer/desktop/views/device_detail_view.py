"""Device Detail view - MAC/ARP/Routing tables for selected device."""

from __future__ import annotations

import flet as ft


def build_device_detail_view(page: ft.Page) -> ft.Control:
    """Build the Device Detail view."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("🔍 Device Details", size=28, weight=ft.FontWeight.BOLD),
                ft.Text("Select a device from Topology to inspect its tables.", size=14, color=ft.Colors.GREY_400),
                ft.Divider(),
                ft.Tabs(
                    selected_index=0,
                    tabs=[
                        ft.Tab(text="Config", icon=ft.Icons.SETTINGS),
                        ft.Tab(text="MAC Table", icon=ft.Icons.LIST),
                        ft.Tab(text="ARP Table", icon=ft.Icons.NETWORK_CELL),
                        ft.Tab(text="Routing", icon=ft.Icons.ALT_ROUTE),
                    ],
                    content=ft.Container(
                        content=ft.Text("No device selected.", color=ft.Colors.GREY_500),
                        padding=24,
                    ),
                ),
            ],
            spacing=16,
            expand=True,
        ),
        padding=24,
        expand=True,
    )
