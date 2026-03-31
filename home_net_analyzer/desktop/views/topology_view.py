"""Topology view - Visual network diagram builder."""

from __future__ import annotations

import flet as ft


def build_topology_view(page: ft.Page) -> ft.Control:
    """Build the Topology Builder view."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("🗺️ Topology Builder", size=28, weight=ft.FontWeight.BOLD),
                ft.Text(
                    "Create and edit network topologies visually.",
                    size=14,
                    color=ft.Colors.GREY_400,
                ),
                ft.Divider(),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text(
                                "Canvas area (drag-and-drop coming soon)",
                                size=16,
                                color=ft.Colors.GREY_500,
                            ),
                            ft.Text(
                                "• Add Switches, Routers, Hosts\n"
                                "• Connect devices with links\n"
                                "• Save / Load topologies",
                                size=13,
                                color=ft.Colors.GREY_500,
                            ),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    padding=40,
                    border=ft.border.all(1, ft.Colors.GREY_700),
                    border_radius=12,
                    alignment=ft.alignment.center,
                    expand=True,
                ),
                ft.Row(
                    [
                        ft.ElevatedButton("Add Switch", icon=ft.Icons.ADD),
                        ft.ElevatedButton("Add Router", icon=ft.Icons.ADD),
                        ft.ElevatedButton("Add Host", icon=ft.Icons.ADD),
                        ft.OutlinedButton("Save", icon=ft.Icons.SAVE),
                        ft.OutlinedButton("Load", icon=ft.Icons.FOLDER_OPEN),
                    ],
                    wrap=True,
                    spacing=12,
                ),
            ],
            spacing=16,
            expand=True,
        ),
        padding=24,
        expand=True,
    )
