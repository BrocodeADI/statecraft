import uuid

from statecraft.actions.base import ActionHandler
from statecraft.engine.rng import SeededRNG
from statecraft.model.actions import ActionVerb, FailureReason, ProposedAction
from statecraft.model.events import Event, EventType, EventVisibility, Severity, TargetType
from statecraft.model.identity import PrivilegeLevel
from statecraft.model.security import EffectPrimitive, EffectSpec, VulnClass
from statecraft.model.state import EnvironmentState
from statecraft.spec.schema import EnvironmentSpec
from statecraft.telemetry.visibility import create_detection_events, evaluate_controls_for_action


class EscalatePrivilegeHandler(ActionHandler):
    verb = ActionVerb.escalate_privilege

    def _get_active_session(self, state: EnvironmentState, actor_id: str, host_id: str):
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
        session = self._get_active_session(state, action.actor_id, target_host_id)
        if not session:
            return False, FailureReason.no_session

        # Host has priv-esc vuln or admin cred known
        host_map = {h.id: h for h in spec.hosts}
        host = host_map.get(target_host_id)
        if not host:
            return False, FailureReason.invalid_action

        # Check for admin cred
        has_admin_cred = False
        for acct in host.accounts:
            if acct.privilege_level in (PrivilegeLevel.admin, PrivilegeLevel.root, PrivilegeLevel.system):
                if acct.credential_id and acct.credential_id in actor.known_credential_ids:
                    has_admin_cred = True
                    break

        # Check for priv-esc vuln on host or its services
        has_priv_esc_vuln = False
        vuln_map = {v.id: v for v in spec.vulnerabilities}
        for v_id in host.vulnerabilities:
            v = vuln_map.get(v_id)
            if v and v.vuln_class == VulnClass.priv_esc:
                has_priv_esc_vuln = True
                break

        if not has_admin_cred and not has_priv_esc_vuln:
            # Check if params specified a known vuln
            param_vuln = action.parameters.get("vuln_id")
            if param_vuln and param_vuln in vuln_map and vuln_map[param_vuln].vuln_class == VulnClass.priv_esc:
                has_priv_esc_vuln = True

        if not has_admin_cred and not has_priv_esc_vuln:
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
        session = self._get_active_session(state, action.actor_id, target_host_id)
        session_id = session.id if session else None

        return [
            EffectSpec(
                primitive=EffectPrimitive.elevate_privilege,
                params={
                    "session_id": session_id,
                    "host_id": target_host_id,
                    "new_privilege_level": "admin",
                },
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
        session = self._get_active_session(state, action.actor_id, target_host_id)
        from_level = session.privilege_level.value if session else "user"

        detecting_controls = evaluate_controls_for_action(state, spec, action, target_host_id=target_host_id)

        priv_event = Event(
            id=f"evt-{uuid.uuid4().hex[:8]}",
            tick=state.tick,
            sequence=0,
            type=EventType.privilege_change,
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
            metadata={
                "host_id": target_host_id,
                "from_privilege": from_level,
                "to_privilege": "admin",
            },
        )
        events.append(priv_event)

        if detecting_controls:
            events.extend(create_detection_events(priv_event, detecting_controls, spec, state.tick))

        return events
