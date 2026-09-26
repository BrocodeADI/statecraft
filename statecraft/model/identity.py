from enum import Enum
from pydantic import BaseModel, Field


class PrivilegeLevel(str, Enum):
    user = "user"
    service = "service"
    admin = "admin"
    root = "root"
    system = "system"


class CredentialType(str, Enum):
    password = "password"
    hash = "hash"
    token = "token"
    certificate = "certificate"
    ssh_key = "ssh_key"


class Credential(BaseModel):
    id: str
    type: CredentialType
    value_hash: str
    is_weak: bool = False
    reuse_scope: list[str] = Field(default_factory=list)


class Account(BaseModel):
    id: str
    host_id: str
    username: str
    privilege_level: PrivilegeLevel
    credential_id: str | None = None
    is_active: bool = True


class Identity(BaseModel):
    id: str
    username: str
    display_name: str
    groups: list[str] = Field(default_factory=list)
    credential_id: str | None = None
    privilege_level: PrivilegeLevel = PrivilegeLevel.user


class Group(BaseModel):
    id: str
    name: str
    members: list[str] = Field(default_factory=list)
    privilege_level: PrivilegeLevel = PrivilegeLevel.user
