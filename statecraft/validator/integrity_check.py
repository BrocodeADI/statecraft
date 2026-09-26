from statecraft.spec.schema import EnvironmentSpec
from statecraft.validator.errors import ValidationError


def validate_referential_integrity(spec: EnvironmentSpec) -> list[ValidationError]:
    """Stage 2: Referential Integrity. Ensure all IDs referenced resolve to declared entities."""
    errors: list[ValidationError] = []

    network_ids = {n.id for n in spec.networks}
    host_ids = {h.id for h in spec.hosts}
    service_ids = {s.id for h in spec.hosts for s in h.services}
    account_ids = {a.id for h in spec.hosts for a in h.accounts}
    cred_ids = {c.id for c in spec.credentials}
    ident_ids = {i.id for i in spec.identities}
    group_ids = {g.id for g in spec.groups}
    control_ids = {c.id for c in spec.security_controls}
    vuln_ids = {v.id for v in spec.vulnerabilities}
    asset_ids = {a.id for a in spec.data_assets}

    # Initial attacker position
    if spec.initial_attacker_position.network_id and spec.initial_attacker_position.network_id not in network_ids:
        errors.append(
            ValidationError(
                stage="stage_2_integrity",
                error_type="IntegrityError",
                message=f"Initial attacker position references unknown network '{spec.initial_attacker_position.network_id}'",
                entity_id=spec.initial_attacker_position.network_id,
            )
        )
    if spec.initial_attacker_position.host_id and spec.initial_attacker_position.host_id not in host_ids:
        errors.append(
            ValidationError(
                stage="stage_2_integrity",
                error_type="IntegrityError",
                message=f"Initial attacker position references unknown host '{spec.initial_attacker_position.host_id}'",
                entity_id=spec.initial_attacker_position.host_id,
            )
        )

    # Hosts
    for host in spec.hosts:
        if host.network_id not in network_ids:
            errors.append(
                ValidationError(
                    stage="stage_2_integrity",
                    error_type="IntegrityError",
                    message=f"Host '{host.id}' references unknown network '{host.network_id}'",
                    entity_id=host.id,
                )
            )

        for ctrl_id in host.security_controls:
            if ctrl_id not in control_ids:
                errors.append(
                    ValidationError(
                        stage="stage_2_integrity",
                        error_type="IntegrityError",
                        message=f"Host '{host.id}' references unknown security control '{ctrl_id}'",
                        entity_id=host.id,
                    )
                )

        for v_id in host.vulnerabilities:
            if v_id not in vuln_ids:
                errors.append(
                    ValidationError(
                        stage="stage_2_integrity",
                        error_type="IntegrityError",
                        message=f"Host '{host.id}' references unknown vulnerability '{v_id}'",
                        entity_id=host.id,
                    )
                )

        for acct in host.accounts:
            if acct.credential_id and acct.credential_id not in cred_ids:
                errors.append(
                    ValidationError(
                        stage="stage_2_integrity",
                        error_type="IntegrityError",
                        message=f"Account '{acct.id}' on host '{host.id}' references unknown credential '{acct.credential_id}'",
                        entity_id=acct.id,
                    )
                )

        for svc in host.services:
            for v_id in svc.vulnerabilities:
                if v_id not in vuln_ids:
                    errors.append(
                        ValidationError(
                            stage="stage_2_integrity",
                            error_type="IntegrityError",
                            message=f"Service '{svc.id}' references unknown vulnerability '{v_id}'",
                            entity_id=svc.id,
                        )
                    )
            for a_id in svc.authentication.account_ids:
                if a_id not in account_ids:
                    errors.append(
                        ValidationError(
                            stage="stage_2_integrity",
                            error_type="IntegrityError",
                            message=f"Service '{svc.id}' authentication references unknown account '{a_id}'",
                            entity_id=svc.id,
                        )
                    )

        for f in host.files:
            if f.contains_credential_id and f.contains_credential_id not in cred_ids:
                errors.append(
                    ValidationError(
                        stage="stage_2_integrity",
                        error_type="IntegrityError",
                        message=f"File '{f.id}' references unknown credential '{f.contains_credential_id}'",
                        entity_id=f.id,
                    )
                )
            if f.owner_account_id and f.owner_account_id not in account_ids:
                errors.append(
                    ValidationError(
                        stage="stage_2_integrity",
                        error_type="IntegrityError",
                        message=f"File '{f.id}' references unknown owner account '{f.owner_account_id}'",
                        entity_id=f.id,
                    )
                )

    # Controls
    for ctrl in spec.security_controls:
        if ctrl.host_id and ctrl.host_id not in host_ids:
            errors.append(
                ValidationError(
                    stage="stage_2_integrity",
                    error_type="IntegrityError",
                    message=f"Security control '{ctrl.id}' references unknown host '{ctrl.host_id}'",
                    entity_id=ctrl.id,
                )
            )
        if ctrl.network_id and ctrl.network_id not in network_ids:
            errors.append(
                ValidationError(
                    stage="stage_2_integrity",
                    error_type="IntegrityError",
                    message=f"Security control '{ctrl.id}' references unknown network '{ctrl.network_id}'",
                    entity_id=ctrl.id,
                )
            )

    # Data Assets
    for asset in spec.data_assets:
        if asset.host_id not in host_ids:
            errors.append(
                ValidationError(
                    stage="stage_2_integrity",
                    error_type="IntegrityError",
                    message=f"Data asset '{asset.id}' references unknown host '{asset.host_id}'",
                    entity_id=asset.id,
                )
            )
        if asset.service_id and asset.service_id not in service_ids:
            errors.append(
                ValidationError(
                    stage="stage_2_integrity",
                    error_type="IntegrityError",
                    message=f"Data asset '{asset.id}' references unknown service '{asset.service_id}'",
                    entity_id=asset.id,
                )
            )

    # Identities and Groups
    for ident in spec.identities:
        if ident.credential_id and ident.credential_id not in cred_ids:
            errors.append(
                ValidationError(
                    stage="stage_2_integrity",
                    error_type="IntegrityError",
                    message=f"Identity '{ident.id}' references unknown credential '{ident.credential_id}'",
                    entity_id=ident.id,
                )
            )
        for g_id in ident.groups:
            if g_id not in group_ids:
                errors.append(
                    ValidationError(
                        stage="stage_2_integrity",
                        error_type="IntegrityError",
                        message=f"Identity '{ident.id}' references unknown group '{g_id}'",
                        entity_id=ident.id,
                    )
                )

    for grp in spec.groups:
        for m_id in grp.members:
            if m_id not in ident_ids:
                errors.append(
                    ValidationError(
                        stage="stage_2_integrity",
                        error_type="IntegrityError",
                        message=f"Group '{grp.id}' references unknown identity member '{m_id}'",
                        entity_id=grp.id,
                    )
                )

    # Credentials reuse scope
    valid_targets = account_ids | ident_ids
    for cred in spec.credentials:
        for target in cred.reuse_scope:
            if target not in valid_targets:
                errors.append(
                    ValidationError(
                        stage="stage_2_integrity",
                        error_type="IntegrityError",
                        message=f"Credential '{cred.id}' reuse_scope references unknown account/identity '{target}'",
                        entity_id=cred.id,
                    )
                )

    # Trust Relationships
    valid_entities = host_ids | service_ids | account_ids | ident_ids
    for trust in spec.trust_relationships:
        if trust.from_id not in valid_entities:
            errors.append(
                ValidationError(
                    stage="stage_2_integrity",
                    error_type="IntegrityError",
                    message=f"Trust relationship '{trust.id}' from_id references unknown entity '{trust.from_id}'",
                    entity_id=trust.id,
                )
            )
        if trust.to_id not in valid_entities:
            errors.append(
                ValidationError(
                    stage="stage_2_integrity",
                    error_type="IntegrityError",
                    message=f"Trust relationship '{trust.id}' to_id references unknown entity '{trust.to_id}'",
                    entity_id=trust.id,
                )
            )

    # Objectives
    valid_obj_targets = asset_ids | host_ids | cred_ids | account_ids
    for obj in spec.objectives:
        if obj.target_id not in valid_obj_targets:
            errors.append(
                ValidationError(
                    stage="stage_2_integrity",
                    error_type="IntegrityError",
                    message=f"Objective '{obj.id}' target_id references unknown target '{obj.target_id}'",
                    entity_id=obj.id,
                )
            )

    return errors
