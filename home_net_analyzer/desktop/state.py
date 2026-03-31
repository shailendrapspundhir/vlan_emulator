"""Application state management for the Flet desktop application."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class UIPreferences:
    """UI-related preferences."""
    theme_mode: str = "dark"       # "dark", "light", "system"
    canvas_zoom: float = 1.0
    log_level: str = "INFO"


@dataclass
class AppState:
    """Global application state."""

    current_topology_id: Optional[str] = None
    selected_device_id: Optional[str] = None
    active_simulation_id: Optional[str] = None
    preferences: UIPreferences = field(default_factory=UIPreferences)

    # In-memory caches (not persisted)
    _topology_cache: dict[str, Any] = field(default_factory=dict, repr=False)
    _logs: list[str] = field(default_factory=list, repr=False)

    def add_log(self, message: str) -> None:
        """Append a log message."""
        self._logs.append(message)
        # Keep last 1000 entries
        if len(self._logs) > 1000:
            self._logs = self._logs[-1000:]

    def get_logs(self) -> list[str]:
        """Return recent log messages."""
        return list(self._logs)

    def clear_logs(self) -> None:
        """Clear all logs."""
        self._logs.clear()


# Global singleton state (simple approach for MVP)
_app_state: Optional[AppState] = None


def get_app_state() -> AppState:
    """Get or create the global AppState."""
    global _app_state
    if _app_state is None:
        _app_state = AppState()
    return _app_state
