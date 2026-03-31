"""Log panel component - scrollable event log."""

from __future__ import annotations

import flet as ft


class LogPanel:
    """A scrollable log panel for displaying events."""

    def __init__(self) -> None:
        self._list = ft.ListView(expand=True, spacing=2, auto_scroll=True)

    @property
    def control(self) -> ft.Control:
        """Return the Flet control for embedding."""
        return ft.Container(
            content=self._list,
            height=120,
            padding=8,
            border=ft.border.all(1, ft.Colors.GREY_700),
            border_radius=8,
        )

    def append(self, message: str) -> None:
        """Append a log line."""
        self._list.controls.append(ft.Text(message, size=12, color=ft.Colors.GREY_400))
        # Keep at most 200 entries
        if len(self._list.controls) > 200:
            self._list.controls = self._list.controls[-200:]
        try:
            self._list.update()
        except RuntimeError:
            pass  # Control not on page yet

    def clear(self) -> None:
        """Clear all log entries."""
        self._list.controls.clear()
        try:
            self._list.update()
        except RuntimeError:
            pass  # Control not on page yet
