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


class EnumerateHandler(ActionHandler):
    verb = ActionVerb.enumerate

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
        host_map = {h.id: h for h in spec.hosts}
        if target_host_id not in host_map:
            return False, FailureReason.invalid_action

        # Host must be in known_host_ids
        if target_host_id not in actor.known_host_ids:
            return False, FailureReason.target_not_discovered

        # Host must be online
        host_state = state.hosts.get(target_host_id)
        if host_state and not host_state.is_online:
            return False, FailureReason.host_offline

        target_host = host_map[target_host_id]

        # Network path check
        path_exists = False
        for src_net in actor.reachable_networks:
            if is_traffic_allowed(
                spec.firewall_rules,
                src_network=src_net,
                src_host=None,
                dst_network=target_host.network_id,
                dst_host=target_host.id,
            ):
                path_exists = True
                break
            for svc in target_host.services:
                if is_traffic_allowed(
                    spec.firewall_rules,
                    src_network=src_net,
                    src_host=None,
                    dst_network=target_host.network_id,
                    dst_host=target_host.id,
                    dst_port=svc.port,
                    dst_protocol=svc.protocol,
                ):
                    path_exists = True
                    break
            if path_exists:
                break

        if not path_exists:
            return False, FailureReason.not_reachable

        return True, None

    def compute_effects(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        rng: SeededRNG,
    ) -> list[EffectSpec]:
        target_host_id = action.target_id
        host_map = {h.id: h for h in spec.hosts}
        target_host = host_map[target_host_id]
        effects: list[EffectSpec] = []

        for svc in target_host.services:
            svc_state = state.services.get(svc.id)
            if svc_state and not svc_state.is_running:
                continue
            effects.append(
                EffectSpec(
                    primitive=EffectPrimitive.discover_service,
                    params={"service_id": svc.id, "host_id": target_host.id, "banner": svc.banner},
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
        target_host_id = action.target_id
        detecting_controls = evaluate_controls_for_action(state, spec, action, target_host_id=target_host_id)

        host_map = {h.id: h for h in spec.hosts}
        target_host = host_map.get(target_host_id)

        if success and target_host:
            seq = 0
            for svc in target_host.services:
                svc_event = Event(
                    id=f"evt-{uuid.uuid4().hex[:8]}",
                    tick=state.tick,
                    sequence=seq,
                    type=EventType.service_discovered,
                    actor_id=action.actor_id,
                    target_id=svc.id,
                    target_type=TargetType.service,
                    success=True,
                    severity=Severity.info,
                    visibility=EventVisibility(
                        visible_to_attacker=True,
                        visible_to_defender=bool(detecting_controls),
                        detected_by_controls=detecting_controls,
                    ),
                    metadata={
                        "host_id": target_host.id,
                        "service_id": svc.id,
                        "port": svc.port,
                        "protocol": svc.protocol,
                        "banner": svc.banner,
                    },
                )
                events.append(svc_event)
                seq += 1

        if detecting_controls and events:
            events.extend(create_detection_events(events[0], detecting_controls, spec, state.tick))

        return events
