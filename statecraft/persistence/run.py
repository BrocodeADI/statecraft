from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field

from statecraft.model.actions import ProposedAction
from statecraft.model.events import Event
from statecraft.model.state import EnvironmentState
from statecraft.spec.schema import EnvironmentSpec


class Run(BaseModel):
    id: str = Field(default_factory=lambda: f"run-{uuid.uuid4().hex[:8]}")
    environment_spec: EnvironmentSpec
    seed: int = 42
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actions: list[ProposedAction] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    final_state: EnvironmentState | None = None
