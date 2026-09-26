from statecraft.model.actions import ActionVerb
from statecraft.model.security import CapabilityType, EffectPrimitive
from statecraft.spec.schema import EnvironmentSpec
from statecraft.validator.errors import ValidationError


def validate_capability_consistency(spec: EnvironmentSpec) -> list[ValidationError]:
    """Stage 5: Capability Consistency. Primitives in closed vocabulary, valid capabilities, valid verbs."""
    errors: list[ValidationError] = []

    valid_primitives = {p.value for p in EffectPrimitive}
    valid_capabilities = {c.value for c in CapabilityType}
    valid_verbs = {v.value for v in ActionVerb}

    for vuln in spec.vulnerabilities:
        for eff in vuln.effects:
            # Primitive is stored as an EffectPrimitive enum (or string)
            prim_val = eff.primitive.value if isinstance(eff.primitive, EffectPrimitive) else str(eff.primitive)
            if prim_val not in valid_primitives:
                errors.append(
                    ValidationError(
                        stage="stage_5_capability",
                        error_type="CapabilityError",
                        message=f"Vulnerability '{vuln.id}' effect uses unknown primitive '{prim_val}'",
                        entity_id=vuln.id,
                    )
                )

        for cap in vuln.required_capabilities:
            cap_val = cap.value if isinstance(cap, CapabilityType) else str(cap)
            if cap_val not in valid_capabilities:
                errors.append(
                    ValidationError(
                        stage="stage_5_capability",
                        error_type="CapabilityError",
                        message=f"Vulnerability '{vuln.id}' requires unknown capability '{cap_val}'",
                        entity_id=vuln.id,
                    )
                )

    for ctrl in spec.security_controls:
        for det in ctrl.detects:
            if det.action_verb and det.action_verb not in valid_verbs:
                errors.append(
                    ValidationError(
                        stage="stage_5_capability",
                        error_type="CapabilityError",
                        message=f"Security control '{ctrl.id}' detection rule references invalid action verb '{det.action_verb}'",
                        entity_id=ctrl.id,
                    )
                )

    return errors
