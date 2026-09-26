import uuid

from statecraft.actions.base import ActionHandler
from statecraft.engine.firewall import is_traffic_allowed
from statecraft.engine.rng import SeededRNG
from statecraft.model.actions import ActionVerb, FailureReason, ProposedAction
from statecraft.model.events import Event, EventType, EventVisibility, Severity, TargetType
from statecraft.model.identity import PrivilegeLevel
from statecraft.model.security import EffectPrimitive, EffectSpec
from statecraft.model.state import EnvironmentState
from statecraft.spec.schema import EnvironmentSpec
from statecraft.telemetry.visibility import create_detection_events, evaluate_controls_for_action


class AuthenticateHandler(ActionHandler):
    verb = ActionVerb.authenticate

    def _resolve_service_and_host(self, spec: EnvironmentSpec, service_id: str):
        for h in spec.hosts:
            for s in h.services:
                if s.id == service_id:
                    return s, h
        return None, None

    def check_preconditions(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
    ) -> tuple[bool, FailureReason | None]:
        actor = state.actors.get(action.actor_id)
        if not actor:
            return False, FailureReason.forbidden_by_grammar

        target_service_id = action.target_id
        svc, host = self._resolve_service_and_host(spec, target_service_id)
        if not svc or not host:
            return False, FailureReason.invalid_action

        # Check service is known (directly enumerated or host discovered)
        if target_service_id not in actor.known_service_ids and host.id not in actor.known_host_ids:
            return False, FailureReason.target_not_discovered

        # Check service running
        svc_state = state.services.get(target_service_id)
        if svc_state and not svc_state.is_running:
            return False, FailureReason.service_not_running

        # Check network path from actor's reachable networks or host sessions
        path_exists = False
        for src_net in actor.reachable_networks:
            if is_traffic_allowed(
                spec.firewall_rules,
                src_network=src_net,
                src_host=None,
                dst_network=host.network_id,
                dst_host=host.id,
                dst_port=svc.port,
                dst_protocol=svc.protocol,
            ):
                path_exists = True
                break

        # Also check if actor has a session on a host that can reach this service
        if not path_exists:
            for sess in state.sessions.values():
                if sess.actor_id == action.actor_id and sess.is_active:
                    sess_host_map = {h.id: h for h in spec.hosts}
                    sess_host = sess_host_map.get(sess.host_id)
                    if sess_host:
                        if is_traffic_allowed(
                            spec.firewall_rules,
                            src_network=sess_host.network_id,
                            src_host=sess_host.id,
                            dst_network=host.network_id,
                            dst_host=host.id,
                            dst_port=svc.port,
                            dst_protocol=svc.protocol,
                        ):
                            path_exists = True
                            break

        if not path_exists:
            return False, FailureReason.not_reachable

        # Credential check
        cred_id = action.parameters.get("credential_id")
        if not cred_id or cred_id not in actor.known_credential_ids:
            return False, FailureReason.no_compatible_credential

        # Check credential matches service
        cred_map = {c.id: c for c in spec.credentials}
        cred = cred_map.get(cred_id)
        if not cred:
            return False, FailureReason.no_compatible_credential

        # Does credential map to an account for this service?
        matching_account = None
        for acct in host.accounts:
            if acct.credential_id == cred_id or acct.id in cred.reuse_scope:
                if not svc.authentication.account_ids or acct.id in svc.authentication.account_ids:
                    matching_account = acct
                    break

        if not matching_account:
            return False, FailureReason.no_compatible_credential

        return True, None

    def compute_effects(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        rng: SeededRNG,
    ) -> list[EffectSpec]:
        svc, host = self._resolve_service_and_host(spec, action.target_id)
        cred_id = action.parameters.get("credential_id")
        cred_map = {c.id: c for c in spec.credentials}
        cred = cred_map.get(cred_id)

        matching_account = None
        for acct in host.accounts:
            if acct.credential_id == cred_id or (cred and acct.id in cred.reuse_scope):
                if not svc.authentication.account_ids or acct.id in svc.authentication.account_ids:
                    matching_account = acct
                    break

        priv_level = matching_account.privilege_level if matching_account else PrivilegeLevel.user
        acct_id = matching_account.id if matching_account else None

        return [
            EffectSpec(
                primitive=EffectPrimitive.grant_session,
                params={
                    "host_id": host.id,
                    "account_id": acct_id,
                    "privilege_level": priv_level.value,
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
        svc, host = self._resolve_service_and_host(spec, action.target_id)
        host_id = host.id if host else None
        detecting_controls = evaluate_controls_for_action(state, spec, action, target_host_id=host_id)

        cred_id = action.parameters.get("credential_id")
        auth_event = Event(
            id=f"evt-{uuid.uuid4().hex[:8]}",
            tick=state.tick,
            sequence=0,
            type=EventType.authentication_success if success else EventType.authentication_failure,
            actor_id=action.actor_id,
            target_id=action.target_id,
            target_type=TargetType.service,
            success=success,
            severity=Severity.info if success else Severity.medium,
            visibility=EventVisibility(
                visible_to_attacker=True,
                visible_to_defender=bool(detecting_controls),
                detected_by_controls=detecting_controls,
            ),
            metadata={"service_id": action.target_id, "credential_id": cred_id, "host_id": host_id},
        )
        events.append(auth_event)

        if detecting_controls:
            events.extend(create_detection_events(auth_event, detecting_controls, spec, state.tick))

        return events
