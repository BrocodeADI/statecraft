from enum import Enum
from pydantic import BaseModel, Field


class EventType(str, Enum):
    # Discovery
    scan_attempt = "scan_attempt"
    host_discovered = "host_discovered"
    service_discovered = "service_discovered"

    # Authentication
    authentication_attempt = "authentication_attempt"
    authentication_success = "authentication_success"
    authentication_failure = "authentication_failure"

    # Exploitation
    exploit_attempt = "exploit_attempt"
    exploit_success = "exploit_success"
    exploit_failure = "exploit_failure"

    # Privilege
    privilege_change = "privilege_change"

    # Credential
    credential_acquired = "credential_acquired"

    # Movement
    lateral_movement = "lateral_movement"

    # Data
    data_access = "data_access"

    # Persistence
    persistence_created = "persistence_created"

    # Defense
    detection_triggered = "detection_triggered"
    control_disabled = "control_disabled"

    # Objective
    objective_achieved = "objective_achieved"


class TargetType(str, Enum):
    host = "host"
    service = "service"
    asset = "asset"
    network = "network"
    session = "session"
    credential = "credential"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EventVisibility(BaseModel):
    visible_to_attacker: bool = True
    visible_to_defender: bool = False
    detected_by_controls: list[str] = Field(default_factory=list)
    detection_delay_ticks: int = 0


class Event(BaseModel):
    id: str
    tick: int
    sequence: int = 0
    type: EventType
    actor_id: str | None = None
    target_id: str
    target_type: TargetType
    success: bool
    severity: Severity = Severity.info
    visibility: EventVisibility = Field(default_factory=EventVisibility)
    metadata: dict = Field(default_factory=dict)
    caused_by: str | None = None
