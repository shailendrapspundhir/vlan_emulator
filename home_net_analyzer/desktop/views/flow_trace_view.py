"""Flow Trace view - Animated packet flow visualization."""

from __future__ import annotations

import flet as ft


def build_flow_trace_view(page: ft.Page) -> ft.Control:
    """Build the Flow Trace view."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("🔄 Flow Trace", size=28, weight=ft.FontWeight.BOLD),
                ft.Text("Visualize packet flows hop-by-hop.", size=14, color=ft.Colors.GREY_400),
                ft.Divider(),
                ft.Row(
                    [
                        ft.ElevatedButton("▶ Play Animation", icon=ft.Icons.PLAY_ARROW),
                        ft.OutlinedButton("⏸ Pause", icon=ft.Icons.PAUSE),
                        ft.OutlinedButton("Step", icon=ft.Icons.SKIP_NEXT),
                    ],
                    spacing=12,
                ),
                ft.Container(
                    content=ft.Text(
                        "Animation canvas (packet traveling along links) will render here.",
                        color=ft.Colors.GREY_500,
                    ),
                    padding=20,
                    border=ft.border.all(1, ft.Colors.GREY_700),
                    border_radius=8,
                    height=200,
                ),
                ft.Text("Hop-by-Hop Trace", size=18, weight=ft.FontWeight.W_600),
                ft.DataTable(
                    columns=[
                        ft.DataColumn(ft.Text("#")),
                        ft.DataColumn(ft.Text("Device")),
                        ft.DataColumn(ft.Text("Action")),
                        ft.DataColumn(ft.Text("Ingress")),
                        ft.DataColumn(ft.Text("Egress")),
                    ],
                    rows=[
                        ft.DataRow(
                            cells=[
                                ft.DataCell(ft.Text("—")),
                                ft.DataCell(ft.Text("—")),
                                ft.DataCell(ft.Text("No flow yet")),
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
