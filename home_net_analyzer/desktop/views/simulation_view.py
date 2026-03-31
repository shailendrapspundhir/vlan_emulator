"""Simulation view - Run scenarios and control simulations."""

from __future__ import annotations

import flet as ft


def build_simulation_view(page: ft.Page) -> ft.Control:
    """Build the Simulation view."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("▶ Simulation Control", size=28, weight=ft.FontWeight.BOLD),
                ft.Text("Run predefined scenarios or custom simulations.", size=14, color=ft.Colors.GREY_400),
                ft.Divider(),
                ft.Row(
                    [
                        ft.Text("Scenario:", size=14),
                        ft.Dropdown(
                            value="router-on-stick",
                            options=[
                                ft.dropdown.Option("single-switch", "Single Switch VLAN"),
                                ft.dropdown.Option("router-on-stick", "Router-on-a-Stick"),
                                ft.dropdown.Option("multi-switch", "Multi-Switch Trunk"),
                                ft.dropdown.Option("campus", "Campus Network"),
                            ],
                            width=300,
                        ),
                        ft.ElevatedButton("Load Scenario", icon=ft.Icons.DOWNLOAD),
                    ],
                    alignment=ft.MainAxisAlignment.START,
                    spacing=12,
                ),
                ft.Divider(),
                ft.Row(
                    [
                        ft.ElevatedButton("▶ Run", icon=ft.Icons.PLAY_ARROW),
                        ft.OutlinedButton("⏸ Pause", icon=ft.Icons.PAUSE),
                        ft.OutlinedButton("Step", icon=ft.Icons.SKIP_NEXT),
                        ft.OutlinedButton("Reset", icon=ft.Icons.RESTART_ALT),
                    ],
                    spacing=12,
                ),
                ft.Container(
                    content=ft.Text("Simulation output / logs will appear here.", color=ft.Colors.GREY_500),
                    padding=20,
                    border=ft.border.all(1, ft.Colors.GREY_700),
                    border_radius=8,
                    expand=True,
                ),
            ],
            spacing=16,
            expand=True,
        ),
        padding=24,
        expand=True,
    )
