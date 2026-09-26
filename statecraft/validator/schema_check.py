from typing import Any
from pydantic import ValidationError as PydanticValidationError

from statecraft.spec.schema import EnvironmentSpec
from statecraft.validator.errors import ValidationError


def validate_schema(data_or_spec: Any) -> tuple[EnvironmentSpec | None, list[ValidationError]]:
    """Stage 1: Pydantic Schema Validation."""
    if isinstance(data_or_spec, EnvironmentSpec):
        return data_or_spec, []

    if not isinstance(data_or_spec, dict):
        return None, [
            ValidationError(
                stage="stage_1_schema",
                error_type="SchemaError",
                message=f"Expected dictionary input for spec, got {type(data_or_spec).__name__}",
            )
        ]

    try:
        spec = EnvironmentSpec.model_validate(data_or_spec)
        return spec, []
    except PydanticValidationError as e:
        errors = []
        for err in e.errors():
            loc = ".".join(str(x) for x in err.get("loc", []))
            msg = err.get("msg", "Schema validation failed")
            errors.append(
                ValidationError(
                    stage="stage_1_schema",
                    error_type="SchemaError",
                    message=f"{loc}: {msg}",
                    entity_id=loc,
                )
            )
        return None, errors
