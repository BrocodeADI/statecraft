from typing import Any

from statecraft.spec.schema import EnvironmentSpec
from statecraft.validator.capability_check import validate_capability_consistency
from statecraft.validator.cycle_check import validate_cycle_consistency
from statecraft.validator.errors import ValidationError, ValidationResult
from statecraft.validator.graph_check import validate_graph_consistency
from statecraft.validator.integrity_check import validate_referential_integrity
from statecraft.validator.reachability import validate_reachability
from statecraft.validator.schema_check import validate_schema
from statecraft.validator.solvability import validate_solvability


class ValidationPipeline:
    """Orchestrates all validation stages in order."""

    def validate(self, input_data: Any) -> ValidationResult:
        all_errors: list[ValidationError] = []

        # Stage 1: Schema Check
        spec, schema_errors = validate_schema(input_data)
        if schema_errors or spec is None:
            return ValidationResult(valid=False, errors=schema_errors)

        # Stage 2: Referential Integrity
        integrity_errors = validate_referential_integrity(spec)
        if integrity_errors:
            all_errors.extend(integrity_errors)
            return ValidationResult(valid=False, errors=all_errors)

        # Stage 3: Graph Consistency
        graph_errors = validate_graph_consistency(spec)
        if graph_errors:
            all_errors.extend(graph_errors)
            return ValidationResult(valid=False, errors=all_errors)

        # Stage 4: Reachability
        reachability_errors = validate_reachability(spec)
        if reachability_errors:
            all_errors.extend(reachability_errors)
            return ValidationResult(valid=False, errors=all_errors)

        # Stage 5: Capability Consistency
        capability_errors = validate_capability_consistency(spec)
        if capability_errors:
            all_errors.extend(capability_errors)
            return ValidationResult(valid=False, errors=all_errors)

        # Stage 6: Cycle Detection
        cycle_errors = validate_cycle_consistency(spec)
        if cycle_errors:
            all_errors.extend(cycle_errors)
            return ValidationResult(valid=False, errors=all_errors)

        # Stage 7: Solvability Probe (warnings only)
        warnings = validate_solvability(spec)

        # Approved: strip draft flag
        approved_spec = spec.model_copy(update={"draft": False})

        return ValidationResult(
            valid=True,
            errors=[],
            warnings=warnings,
            spec=approved_spec,
        )


def validate_environment(input_data: Any) -> ValidationResult:
    """Convenience function to run the full validation pipeline."""
    return ValidationPipeline().validate(input_data)
