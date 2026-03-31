"""Packet view - Browse and query stored packets."""

from __future__ import annotations

import flet as ft


def build_packet_view(page: ft.Page) -> ft.Control:
    """Build the Packet view."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("📦 Packets", size=28, weight=ft.FontWeight.BOLD),
                ft.Text("Browse captured/stored packets.", size=14, color=ft.Colors.GREY_400),
                ft.Divider(),
                ft.Row(
                    [
                        ft.TextField(hint_text="Filter: src IP", width=150),
                        ft.TextField(hint_text="dst IP", width=150),
                        ft.TextField(hint_text="proto", width=80),
                        ft.ElevatedButton("Query", icon=ft.Icons.SEARCH),
                    ],
                    wrap=True,
                    spacing=12,
                ),
                ft.DataTable(
                    columns=[
                        ft.DataColumn(ft.Text("ID")),
                        ft.DataColumn(ft.Text("Time")),
                        ft.DataColumn(ft.Text("Src")),
                        ft.DataColumn(ft.Text("Dst")),
                        ft.DataColumn(ft.Text("Proto")),
                        ft.DataColumn(ft.Text("Len")),
                    ],
                    rows=[
                        ft.DataRow(
                            cells=[
                                ft.DataCell(ft.Text("—")),
                                ft.DataCell(ft.Text("—")),
                                ft.DataCell(ft.Text("No packets yet")),
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
