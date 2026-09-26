from enum import Enum
from pydantic import BaseModel, Field


class Sensitivity(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


class File(BaseModel):
    id: str
    host_id: str
    path: str
    content_label: str
    sensitivity: Sensitivity = Sensitivity.internal
    owner_account_id: str | None = None
    readable_by: list[str] = Field(default_factory=list)
    contains_credential_id: str | None = None


class DataAsset(BaseModel):
    id: str
    host_id: str
    service_id: str | None = None
    label: str
    sensitivity: Sensitivity = Sensitivity.internal
    accessible_by: list[str] = Field(default_factory=list)
    is_objective: bool = False
