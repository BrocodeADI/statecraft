from enum import Enum
from pydantic import BaseModel, Field

from statecraft.model.events import Event
from statecraft.model.state import StateDelta


class ActionVerb(str, Enum):
    scan = "scan"
    enumerate = "enumerate"
    authenticate = "authenticate"
    exploit = "exploit"
    escalate_privilege = "escalate_privilege"
    pivot = "pivot"
    access_data = "access_data"
    persist = "persist"


class FailureReason(str, Enum):
    not_reachable = "Target not reachable from current position"
    host_offline = "Target host is offline"
    service_not_running = "Target service is not running"
    no_session = "No active session on target host"
    insufficient_privilege = "Session privilege insufficient"
    no_compatible_credential = "No compatible credential available"
    target_not_discovered = "Target not yet discovered"
    precondition_not_met = "Specific precondition not met"
    exploit_failed = "Exploit attempt failed (reliability < 1.0)"
    no_vulnerability_identified = "No vulnerability identified on target service"
    forbidden_by_grammar = "Action verb not permitted for actor role"
    invalid_action = "Action parameters invalid"


class ProposedAction(BaseModel):
    actor_id: str
    verb: ActionVerb
    target_id: str
    parameters: dict = Field(default_factory=dict)


class ActionResult(BaseModel):
    success: bool
    failure_reason: FailureReason | None = None
    state_delta: StateDelta = Field(default_factory=StateDelta.empty)
    events: list[Event] = Field(default_factory=list)
    narrative_hint: str = ""
