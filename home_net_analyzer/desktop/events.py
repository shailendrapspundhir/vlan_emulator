"""Event Bus for decoupled component communication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass
class Event:
    """A simple event with name and payload."""
    name: str
    payload: Any = None


class EventBus:
    """Simple pub/sub event bus."""

    def __init__(self) -> None:
        self._listeners: Dict[str, List[Callable[[Event], None]]] = {}

    def subscribe(self, event_name: str, handler: Callable[[Event], None]) -> None:
        """Register a handler for an event type."""
        self._listeners.setdefault(event_name, []).append(handler)

    def unsubscribe(self, event_name: str, handler: Callable[[Event], None]) -> None:
        """Remove a handler."""
        listeners = self._listeners.get(event_name, [])
        if handler in listeners:
            listeners.remove(handler)

    def publish(self, event_name: str, payload: Any = None) -> None:
        """Emit an event to all subscribers."""
        event = Event(name=event_name, payload=payload)
        for handler in self._listeners.get(event_name, []):
            try:
                handler(event)
            except Exception as e:
                # Log but don't crash other handlers
                print(f"[EventBus] Handler error for '{event_name}': {e}")


# Global singleton
_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get or create the global EventBus."""
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
