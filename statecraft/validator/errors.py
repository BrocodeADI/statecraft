from pydantic import BaseModel, Field

from statecraft.spec.schema import EnvironmentSpec


class ValidationError(BaseModel):
    stage: str
    error_type: str
    message: str
    entity_id: str | None = None


class ValidationResult(BaseModel):
    valid: bool
    errors: list[ValidationError] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    spec: EnvironmentSpec | None = None
