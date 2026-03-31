"""Rules view - Firewall rules management."""

from __future__ import annotations

import flet as ft


def build_rules_view(page: ft.Page) -> ft.Control:
    """Build the Firewall Rules view."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("🛡️ Firewall Rules", size=28, weight=ft.FontWeight.BOLD),
                ft.Text("Manage allow/block rules.", size=14, color=ft.Colors.GREY_400),
                ft.Divider(),
                ft.Row(
                    [
                        ft.ElevatedButton("Add Rule", icon=ft.Icons.ADD),
                        ft.OutlinedButton("Enable All"),
                        ft.OutlinedButton("Disable All"),
                    ],
                    spacing=12,
                ),
                ft.DataTable(
                    columns=[
                        ft.DataColumn(ft.Text("ID")),
                        ft.DataColumn(ft.Text("Action")),
                        ft.DataColumn(ft.Text("Target")),
                        ft.DataColumn(ft.Text("Value")),
                        ft.DataColumn(ft.Text("Proto")),
                        ft.DataColumn(ft.Text("Enabled")),
                    ],
                    rows=[
                        ft.DataRow(
                            cells=[
                                ft.DataCell(ft.Text("—")),
                                ft.DataCell(ft.Text("—")),
                                ft.DataCell(ft.Text("No rules yet")),
                                ft.DataCell(ft.Text("—")),
                                ft.DataCell(ft.Text("—")),
                                ft.DataCell(ft.Text("—")),
                            ]
                        )
                    ],
                ),
            ],
            spacing=16,
            expand=True,
        ),
        padding=24,
        expand=True,
    )
