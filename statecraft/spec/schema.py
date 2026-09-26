from pydantic import BaseModel, Field

from statecraft.model.assets import DataAsset
from statecraft.model.environment import (
    AttackerPosition,
    EnvironmentMetadata,
    Host,
    Interface,
    Network,
)
from statecraft.model.identity import Credential, Group, Identity
from statecraft.model.objectives import Objective
from statecraft.model.security import (
    FirewallRule,
    SecurityControl,
    TrustRelationship,
    Vulnerability,
)


class EnvironmentSpec(BaseModel):
    id: str
    seed: int = 42
    draft: bool = False
    metadata: EnvironmentMetadata
    networks: list[Network] = Field(default_factory=list)
    hosts: list[Host] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)
    firewall_rules: list[FirewallRule] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    identities: list[Identity] = Field(default_factory=list)
    groups: list[Group] = Field(default_factory=list)
    trust_relationships: list[TrustRelationship] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    security_controls: list[SecurityControl] = Field(default_factory=list)
    data_assets: list[DataAsset] = Field(default_factory=list)
    objectives: list[Objective] = Field(default_factory=list)
    initial_attacker_position: AttackerPosition
