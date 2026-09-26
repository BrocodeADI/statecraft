import uuid

from statecraft.actions.base import ActionHandler
from statecraft.engine.firewall import is_traffic_allowed
from statecraft.engine.rng import SeededRNG
from statecraft.model.actions import ActionVerb, FailureReason, ProposedAction
from statecraft.model.events import Event, EventType, EventVisibility, Severity, TargetType
from statecraft.model.security import EffectPrimitive, EffectSpec
from statecraft.model.state import EnvironmentState
from statecraft.spec.schema import EnvironmentSpec
from statecraft.telemetry.visibility import create_detection_events, evaluate_controls_for_action


class PivotHandler(ActionHandler):
    verb = ActionVerb.pivot

    def _resolve_via_host(self, state: EnvironmentState, action: ProposedAction):
        via_host_id = action.parameters.get("via_host_id") or action.parameters.get("via")
        if not via_host_id:
            # If not explicitly passed, see if attacker has an active session on any host
            for sess in state.sessions.values():
                if sess.actor_id == action.actor_id and sess.is_active:
                    return sess.host_id
        return via_host_id

    def check_preconditions(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
    ) -> tuple[bool, FailureReason | None]:
        actor = state.actors.get(action.actor_id)
        if not actor:
            return False, FailureReason.forbidden_by_grammar

        target_network_id = action.target_id
        network_ids = {n.id for n in spec.networks}
        if target_network_id not in network_ids:
            return False, FailureReason.invalid_action

        via_host_id = self._resolve_via_host(state, action)
        if not via_host_id:
            return False, FailureReason.no_session

        # Check actor has active session or compromised host
        has_access = False
        for sess in state.sessions.values():
            if sess.actor_id == action.actor_id and sess.host_id == via_host_id and sess.is_active:
                has_access = True
                break

        if not has_access:
            h_state = state.hosts.get(via_host_id)
            if h_state and h_state.compromised:
                has_access = True

        if not has_access:
            return False, FailureReason.no_session

        # Check if via_host can route to target_network per firewall rules
        host_map = {h.id: h for h in spec.hosts}
        pivot_host = host_map.get(via_host_id)
        if not pivot_host:
            return False, FailureReason.invalid_action

        can_route = False
        # Check direct network to network rule
        if is_traffic_allowed(
            spec.firewall_rules,
            src_network=pivot_host.network_id,
            src_host=pivot_host.id,
            dst_network=target_network_id,
            dst_host=None,
        ):
            can_route = True

        # Check if any host in target network is reachable from pivot host
        if not can_route:
            for h in spec.hosts:
                if h.network_id == target_network_id:
                    if is_traffic_allowed(
                        spec.firewall_rules,
                        src_network=pivot_host.network_id,
                        src_host=pivot_host.id,
                        dst_network=target_network_id,
                        dst_host=h.id,
                    ):
                        can_route = True
                        break
                    for svc in h.services:
                        if is_traffic_allowed(
                            spec.firewall_rules,
                            src_network=pivot_host.network_id,
                            src_host=pivot_host.id,
                            dst_network=target_network_id,
                            dst_host=h.id,
                            dst_port=svc.port,
                            dst_protocol=svc.protocol,
                        ):
                            can_route = True
                            break
                    if can_route:
                        break

        if not can_route:
            return False, FailureReason.not_reachable

        return True, None

    def compute_effects(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        rng: SeededRNG,
    ) -> list[EffectSpec]:
        target_network_id = action.target_id
        via_host_id = self._resolve_via_host(state, action)

        return [
            EffectSpec(
                primitive=EffectPrimitive.pivot_network,
                params={"network_id": target_network_id, "via_host_id": via_host_id},
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
        via_host_id = self._resolve_via_host(state, action)
        target_network_id = action.target_id

        detecting_controls = evaluate_controls_for_action(state, spec, action, target_host_id=via_host_id)

        pivot_event = Event(
            id=f"evt-{uuid.uuid4().hex[:8]}",
            tick=state.tick,
            sequence=0,
            type=EventType.lateral_movement,
            actor_id=action.actor_id,
            target_id=target_network_id,
            target_type=TargetType.network,
            success=success,
            severity=Severity.medium,
            visibility=EventVisibility(
                visible_to_attacker=True,
                visible_to_defender=bool(detecting_controls),
                detected_by_controls=detecting_controls,
            ),
            metadata={"from_host": via_host_id, "to_network": target_network_id},
        )
        events.append(pivot_event)

        if detecting_controls:
            events.extend(create_detection_events(pivot_event, detecting_controls, spec, state.tick))

        return events
