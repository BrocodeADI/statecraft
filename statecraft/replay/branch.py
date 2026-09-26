from pydantic import BaseModel, Field

from statecraft.model.events import Event


class Branch(BaseModel):
    """Stub for v2 branching replay feature."""

    parent_run_id: str
    fork_at_tick: int
    modified_spec_delta: dict | None = None
    branch_events: list[Event] = Field(default_factory=list)
