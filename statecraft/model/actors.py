from enum import Enum
from pydantic import BaseModel, Field

from statecraft.model.identity import PrivilegeLevel
from statecraft.model.security import CapabilityType


class ActorRole(str, Enum):
    attacker = "attacker"
    defender = "defender"


class AgentType(str, Enum):
    human = "human"
    llm = "llm"
    scripted = "scripted"


class Session(BaseModel):
    id: str
    host_id: str
    actor_id: str
    privilege_level: PrivilegeLevel
    account_id: str | None = None
    created_at_tick: int = 0
    is_active: bool = True
    persistence_mechanism: str | None = None


class Actor(BaseModel):
    id: str
    role: ActorRole
    agent_type: AgentType = AgentType.scripted
    capabilities: list[CapabilityType] = Field(default_factory=list)
    sessions: list[Session] = Field(default_factory=list)
    known_hosts: list[str] = Field(default_factory=list)
    known_services: list[str] = Field(default_factory=list)
    known_credentials: list[str] = Field(default_factory=list)
    known_data_assets: list[str] = Field(default_factory=list)
    reachable_networks: list[str] = Field(default_factory=list)
    accessed_files: list[str] = Field(default_factory=list)
    accessed_assets: list[str] = Field(default_factory=list)
    persistent_hosts: list[str] = Field(default_factory=list)
