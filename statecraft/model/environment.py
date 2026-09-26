from enum import Enum
from pydantic import BaseModel, Field

from statecraft.model.assets import DataAsset, File
from statecraft.model.identity import Account, Credential, Group, Identity
from statecraft.model.objectives import Objective
from statecraft.model.security import (
    FirewallRule,
    SecurityControl,
    TrustRelationship,
    Vulnerability,
)


class NetworkZone(str, Enum):
    external = "external"
    dmz = "dmz"
    internal = "internal"
    restricted = "restricted"


class Network(BaseModel):
    id: str
    cidr: str
    zone: NetworkZone
    label: str


class OSProfile(BaseModel):
    family: str
    distro: str
    version: str


class SoftwareProfile(BaseModel):
    name: str
    version: str


class AuthSpec(BaseModel):
    type: str
    account_ids: list[str] = Field(default_factory=list)


class Service(BaseModel):
    id: str
    host_id: str
    port: int
    protocol: str = "tcp"
    software: SoftwareProfile
    is_running: bool = True
    vulnerabilities: list[str] = Field(default_factory=list)
    authentication: AuthSpec = Field(default_factory=lambda: AuthSpec(type="none"))
    banner: str = ""


class Host(BaseModel):
    id: str
    hostname: str
    network_id: str
    ip_address: str
    os: OSProfile
    services: list[Service] = Field(default_factory=list)
    accounts: list[Account] = Field(default_factory=list)
    files: list[File] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    is_online: bool = True
    security_controls: list[str] = Field(default_factory=list)


class Interface(BaseModel):
    id: str
    host_id: str
    network_id: str
    ip_address: str
    mac_address: str | None = None


class AttackerPosition(BaseModel):
    type: str
    network_id: str | None = None
    host_id: str | None = None


class EnvironmentMetadata(BaseModel):
    name: str
    description: str = ""
    difficulty: str = "medium"


class Environment(BaseModel):
    id: str
    seed: int = 42
    metadata: EnvironmentMetadata
    networks: list[Network] = Field(default_factory=list)
    hosts: list[Host] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)
    identities: list[Identity] = Field(default_factory=list)
    groups: list[Group] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    trust_relationships: list[TrustRelationship] = Field(default_factory=list)
    firewall_rules: list[FirewallRule] = Field(default_factory=list)
    security_controls: list[SecurityControl] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    data_assets: list[DataAsset] = Field(default_factory=list)
    objectives: list[Objective] = Field(default_factory=list)
    initial_attacker_position: AttackerPosition
