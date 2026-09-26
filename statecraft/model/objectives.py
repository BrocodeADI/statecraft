from enum import Enum
from pydantic import BaseModel


class ObjectiveType(str, Enum):
    access_data_asset = "access_data_asset"
    compromise_host = "compromise_host"
    credential_harvest = "credential_harvest"
    persistence = "persistence"


class Objective(BaseModel):
    id: str
    label: str
    type: ObjectiveType
    target_id: str
    is_achieved: bool = False
    achieved_at_tick: int | None = None
