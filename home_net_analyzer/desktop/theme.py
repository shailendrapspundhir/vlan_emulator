"""Theme and styling constants for the Flet desktop application."""

from __future__ import annotations

import flet as ft

# Color palette (Dark mode default)
COLORS = {
    "bg": "#0F172A",        # slate-900
    "surface": "#1E293B",   # slate-800
    "primary": "#22C55E",   # green-500
    "accent": "#3B82F6",    # blue-500
    "text": "#E2E8F0",      # slate-200
    "muted": "#94A3B8",     # slate-400
    "danger": "#EF4444",    # red-500
    "border": "#334155",    # slate-700
    "warning": "#F59E0B",   # amber-500
}


def get_theme() -> ft.Theme:
    """Return the default Flet theme for the app."""
    return ft.Theme(
        color_scheme=ft.ColorScheme(
            primary=ft.Colors.GREEN_500,
            primary_container=ft.Colors.GREEN_900,
            secondary=ft.Colors.BLUE_500,
            surface=ft.Colors.with_opacity(1, "#1E293B"),
            on_primary=ft.Colors.WHITE,
            on_secondary=ft.Colors.WHITE,
            on_surface=ft.Colors.GREY_200,
        ),
        font_family="System",
    )


def apply_dark_theme(page: ft.Page) -> None:
    """Apply dark theme to the page."""
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = get_theme()
    page.bgcolor = "#0F172A"
