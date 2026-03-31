"""Settings view - Application configuration."""

from __future__ import annotations

import flet as ft


def build_settings_view(page: ft.Page) -> ft.Control:
    """Build the Settings view."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("⚙️ Settings", size=28, weight=ft.FontWeight.BOLD),
                ft.Text("Configure application behavior.", size=14, color=ft.Colors.GREY_400),
                ft.Divider(),
                ft.Text("Appearance", size=18, weight=ft.FontWeight.W_600),
                ft.Row(
                    [
                        ft.Text("Theme:"),
                        ft.Dropdown(
                            value="dark",
                            options=[
                                ft.dropdown.Option("dark", "Dark"),
                                ft.dropdown.Option("light", "Light"),
                                ft.dropdown.Option("system", "System"),
                            ],
                            width=150,
                        ),
                    ],
                    spacing=12,
                ),
                ft.Divider(),
                ft.Text("Rules Backend", size=18, weight=ft.FontWeight.W_600),
                ft.Text(
                    "⚠️ Use 'noop' for safe testing. 'nftables'/'iptables' require root.",
                    size=12,
                    color=ft.Colors.ORANGE_400,
                ),
                ft.Dropdown(
                    value="noop",
                    options=[
                        ft.dropdown.Option("noop", "Noop (safe)"),
                        ft.dropdown.Option("nftables", "nftables"),
                        ft.dropdown.Option("iptables", "iptables"),
                    ],
                    width=200,
                ),
                ft.Divider(),
                ft.Text("Database", size=18, weight=ft.FontWeight.W_600),
                ft.Row(
                    [
                        ft.TextField(hint_text="Database path", value="data/packets.db", expand=True),
                        ft.OutlinedButton("Browse", icon=ft.Icons.FOLDER_OPEN),
                    ],
                    spacing=12,
                ),
                ft.Row(
                    [
                        ft.ElevatedButton("Save Settings", icon=ft.Icons.SAVE),
                        ft.OutlinedButton("Reset to Defaults"),
                    ],
                    spacing=12,
                ),
            ],
            spacing=16,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        ),
        padding=24,
        expand=True,
    )
