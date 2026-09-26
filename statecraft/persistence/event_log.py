import json
from pathlib import Path
import sqlite3
from typing import Union

from statecraft.model.events import Event


class EventLog:
    """Append-only SQLite event log."""

    def __init__(self, db_path: Union[str, Path] = ":memory:"):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(self.db_path)
        self._init_db()

    def _init_db(self):
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    tick INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    actor_id TEXT,
                    target_id TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    data_json TEXT NOT NULL
                )
                """
            )

    def append(self, event: Event) -> None:
        data = event.model_dump_json()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO events (id, tick, sequence, type, actor_id, target_id, target_type, success, severity, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.tick,
                    event.sequence,
                    event.type.value,
                    event.actor_id,
                    event.target_id,
                    event.target_type.value,
                    1 if event.success else 0,
                    event.severity.value,
                    data,
                ),
            )

    def append_all(self, events: list[Event]) -> None:
        for event in events:
            self.append(event)

    def get_all(self) -> list[Event]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT data_json FROM events ORDER BY tick ASC, sequence ASC")
        rows = cursor.fetchall()
        return [Event.model_validate_json(row[0]) for row in rows]

    def close(self):
        self._conn.close()
