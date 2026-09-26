from statecraft.spec.schema import EnvironmentSpec


def validate_solvability(spec: EnvironmentSpec) -> list[str]:
    """Stage 7: Solvability (soft probe). Emits warnings if declared objectives have no path."""
    warnings: list[str] = []

    if not spec.objectives:
        warnings.append("No objectives declared in environment spec.")
        return warnings

    # Basic check: do target entities for objectives exist?
    host_ids = {h.id for h in spec.hosts}
    asset_ids = {a.id for a in spec.data_assets}
    for obj in spec.objectives:
        if obj.target_id not in host_ids and obj.target_id not in asset_ids:
            warnings.append(
                f"Objective '{obj.id}' targets '{obj.target_id}' which does not map to a known host or asset."
            )

    return warnings
