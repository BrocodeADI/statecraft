import uuid

from statecraft.actions.base import ActionHandler
from statecraft.engine.rng import SeededRNG
from statecraft.model.actions import ActionVerb, FailureReason, ProposedAction
from statecraft.model.events import Event, EventType, EventVisibility, Severity, TargetType
from statecraft.model.identity import PrivilegeLevel
from statecraft.model.security import EffectPrimitive, EffectSpec
from statecraft.model.state import EnvironmentState
from statecraft.spec.schema import EnvironmentSpec
from statecraft.telemetry.visibility import create_detection_events, evaluate_controls_for_action


class AccessDataHandler(ActionHandler):
    verb = ActionVerb.access_data

    def _resolve_target(self, spec: EnvironmentSpec, target_id: str):
        for asset in spec.data_assets:
            if asset.id == target_id:
                return "asset", asset, asset.host_id
        for host in spec.hosts:
            for f in host.files:
                if f.id == target_id:
                    return "file", f, host.id
        return None, None, None

    def _get_active_session_on_host(self, state: EnvironmentState, actor_id: str, host_id: str):
        for sess in state.sessions.values():
            if sess.actor_id == actor_id and sess.host_id == host_id and sess.is_active:
                return sess
        return None

    def check_preconditions(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
    ) -> tuple[bool, FailureReason | None]:
        actor = state.actors.get(action.actor_id)
        if not actor:
            return False, FailureReason.forbidden_by_grammar

        target_type, target_obj, host_id = self._resolve_target(spec, action.target_id)
        if not target_obj or not host_id:
            return False, FailureReason.invalid_action

        session = self._get_active_session_on_host(state, action.actor_id, host_id)
        if not session:
            return False, FailureReason.no_session

        # Check access permission
        is_admin = session.privilege_level in (PrivilegeLevel.admin, PrivilegeLevel.root, PrivilegeLevel.system)
        if is_admin:
            return True, None

        if target_type == "asset":
            # Check accessible_by
            if session.account_id in target_obj.accessible_by:
                return True, None
            # Also check if session privilege is service and accessible_by includes service accounts
            for acc_id in target_obj.accessible_by:
                if session.account_id == acc_id:
                    return True, None
            # If not explicitly permitted and not admin
            return False, FailureReason.insufficient_privilege

        elif target_type == "file":
            if session.account_id in target_obj.readable_by or session.account_id == target_obj.owner_account_id:
                return True, None
            return False, FailureReason.insufficient_privilege

        return False, FailureReason.precondition_not_met

    def compute_effects(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        rng: SeededRNG,
    ) -> list[EffectSpec]:
        target_type, target_obj, host_id = self._resolve_target(spec, action.target_id)
        effects: list[EffectSpec] = []

        if target_type == "asset":
            effects.append(
                EffectSpec(
                    primitive=EffectPrimitive.read_data_asset,
                    params={"asset_id": target_obj.id},
                )
            )
            # Check if this asset is an objective
            for obj in spec.objectives:
                if obj.target_id == target_obj.id:
                    effects.append(
                        EffectSpec(
                            primitive=EffectPrimitive.achieve_objective,
                            params={"objective_id": obj.id},
                        )
                    )

        elif target_type == "file":
            effects.append(
                EffectSpec(
                    primitive=EffectPrimitive.read_file,
                    params={"file_id": target_obj.id},
                )
            )
            if target_obj.contains_credential_id:
                effects.append(
                    EffectSpec(
                        primitive=EffectPrimitive.obtain_credential,
                        params={"credential_id": target_obj.contains_credential_id},
                    )
                )

        return effects

    def build_telemetry(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        success: bool,
    ) -> list[Event]:
        events: list[Event] = []
        target_type, target_obj, host_id = self._resolve_target(spec, action.target_id)
        detecting_controls = evaluate_controls_for_action(state, spec, action, target_host_id=host_id)

        sensitivity = getattr(target_obj, "sensitivity", "internal")
        sens_val = sensitivity.value if hasattr(sensitivity, "value") else str(sensitivity)

        access_event = Event(
            id=f"evt-{uuid.uuid4().hex[:8]}",
            tick=state.tick,
            sequence=0,
            type=EventType.data_access,
            actor_id=action.actor_id,
            target_id=action.target_id,
            target_type=TargetType.asset,
            success=success,
            severity=Severity.high if sensitivity == "restricted" else Severity.medium,
            visibility=EventVisibility(
                visible_to_attacker=True,
                visible_to_defender=bool(detecting_controls),
                detected_by_controls=detecting_controls,
            ),
            metadata={"target_id": action.target_id, "host_id": host_id, "sensitivity": sens_val},
        )
        events.append(access_event)

        # Objective achieved event if applicable
        if success and target_type == "asset":
            seq = 1
            for obj in spec.objectives:
                if obj.target_id == target_obj.id:
                    obj_event = Event(
                        id=f"evt-{uuid.uuid4().hex[:8]}",
                        tick=state.tick,
                        sequence=seq,
                        type=EventType.objective_achieved,
                        actor_id=action.actor_id,
                        target_id=obj.id,
                        target_type=TargetType.asset,
                        success=True,
                        severity=Severity.critical,
                        visibility=EventVisibility(visible_to_attacker=True, visible_to_defender=True),
                        metadata={"objective_id": obj.id, "label": obj.label},
                        caused_by=access_event.id,
                    )
                    events.append(obj_event)
                    seq += 1

        if detecting_controls:
            events.extend(create_detection_events(access_event, detecting_controls, spec, state.tick))

        return events
