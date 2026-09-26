from pydantic import BaseModel, Field

from statecraft.model.actors import Session
from statecraft.model.identity import PrivilegeLevel


class HostState(BaseModel):
    id: str
    is_online: bool = True
    compromised: bool = False
    persistent_actors: list[str] = Field(default_factory=list)


class ServiceState(BaseModel):
    id: str
    is_running: bool = True


class ControlState(BaseModel):
    id: str
    is_active: bool = True


class ActorState(BaseModel):
    id: str
    reachable_networks: list[str] = Field(default_factory=list)
    known_host_ids: list[str] = Field(default_factory=list)
    enumerated_host_ids: list[str] = Field(default_factory=list)
    known_service_ids: list[str] = Field(default_factory=list)
    known_credential_ids: list[str] = Field(default_factory=list)
    known_data_asset_ids: list[str] = Field(default_factory=list)
    accessed_files: list[str] = Field(default_factory=list)
    accessed_assets: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)


class StateDelta(BaseModel):
    added_sessions: list[Session] = Field(default_factory=list)
    removed_session_ids: list[str] = Field(default_factory=list)
    updated_session_levels: dict[str, PrivilegeLevel] = Field(default_factory=dict)
    updated_host_states: dict[str, HostState] = Field(default_factory=dict)
    updated_service_states: dict[str, ServiceState] = Field(default_factory=dict)
    updated_actor_states: dict[str, ActorState] = Field(default_factory=dict)
    updated_control_states: dict[str, ControlState] = Field(default_factory=dict)
    achieved_objectives: list[str] = Field(default_factory=list)
    tick_advance: int = 1

    @classmethod
    def empty(cls) -> "StateDelta":
        return cls(tick_advance=0)


class EnvironmentState(BaseModel):
    tick: int = 0
    hosts: dict[str, HostState] = Field(default_factory=dict)
    services: dict[str, ServiceState] = Field(default_factory=dict)
    actors: dict[str, ActorState] = Field(default_factory=dict)
    sessions: dict[str, Session] = Field(default_factory=dict)
    controls: dict[str, ControlState] = Field(default_factory=dict)
    achieved_objectives: list[str] = Field(default_factory=list)
    event_count: int = 0
