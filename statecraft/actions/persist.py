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


class PersistHandler(ActionHandler):
    verb = ActionVerb.persist

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

        target_host_id = action.target_id
        session = self._get_active_session_on_host(state, action.actor_id, target_host_id)
        if not session:
            return False, FailureReason.no_session

        # Actor needs privileged session (admin, root, system, or service)
        valid_privs = (PrivilegeLevel.admin, PrivilegeLevel.root, PrivilegeLevel.system, PrivilegeLevel.service)
        if session.privilege_level not in valid_privs:
            return False, FailureReason.insufficient_privilege

        return True, None

    def compute_effects(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        rng: SeededRNG,
    ) -> list[EffectSpec]:
        target_host_id = action.target_id
        mechanism = action.parameters.get("mechanism", "cron_job")

        return [
            EffectSpec(
                primitive=EffectPrimitive.create_persistence,
                params={"host_id": target_host_id, "mechanism_label": mechanism},
            )
        ]

    def build_telemetry(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        success: bool,
    ) -> list[Event]:
        events: list[Event] = []
        target_host_id = action.target_id
        detecting_controls = evaluate_controls_for_action(state, spec, action, target_host_id=target_host_id)

        persist_event = Event(
            id=f"evt-{uuid.uuid4().hex[:8]}",
            tick=state.tick,
            sequence=0,
            type=EventType.persistence_created,
            actor_id=action.actor_id,
            target_id=target_host_id,
            target_type=TargetType.host,
            success=success,
            severity=Severity.high,
            visibility=EventVisibility(
                visible_to_attacker=True,
                visible_to_defender=bool(detecting_controls),
                detected_by_controls=detecting_controls,
            ),
            metadata={"host_id": target_host_id},
        )
        events.append(persist_event)

        if detecting_controls:
            events.extend(create_detection_events(persist_event, detecting_controls, spec, state.tick))

        return events
