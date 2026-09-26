from typing import Callable
from statecraft.model.events import Event


class TelemetryBus:
    """In-memory event bus for dispatching events to observers and event log."""

    def __init__(self):
        self._subscribers: list[Callable[[Event], None]] = []
        self._history: list[Event] = []

    def subscribe(self, callback: Callable[[Event], None]) -> None:
        self._subscribers.append(callback)

    def emit(self, event: Event) -> None:
        self._history.append(event)
        for sub in self._subscribers:
            try:
                sub(event)
            except Exception:
                pass

    def emit_all(self, events: list[Event]) -> None:
        for event in events:
            self.emit(event)

    @property
    def history(self) -> list[Event]:
        return list(self._history)
