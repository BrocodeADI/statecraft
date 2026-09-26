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


class ScanHandler(ActionHandler):
    verb = ActionVerb.scan

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

        # Check if actor can reach target network from any currently reachable network
        can_reach_network = False
        for src_net in actor.reachable_networks:
            if src_net == target_network_id:
                can_reach_network = True
                break
            # Or if firewall permits traffic from src_net to target_network_id
            if is_traffic_allowed(
                spec.firewall_rules,
                src_network=src_net,
                src_host=None,
                dst_network=target_network_id,
                dst_host=None,
            ):
                can_reach_network = True
                break

        if not can_reach_network:
            return False, FailureReason.not_reachable

        return True, None

    def compute_effects(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        rng: SeededRNG,
    ) -> list[EffectSpec]:
        actor = state.actors.get(action.actor_id)
        target_network_id = action.target_id
        effects: list[EffectSpec] = []

        hosts_in_net = [h for h in spec.hosts if h.network_id == target_network_id and h.is_online]
        for host in hosts_in_net:
            # Check reachability from any reachable network
            reachable = False
            for src_net in actor.reachable_networks:
                if is_traffic_allowed(
                    spec.firewall_rules,
                    src_network=src_net,
                    src_host=None,
                    dst_network=host.network_id,
                    dst_host=host.id,
                ):
                    reachable = True
                    break
                # Or if any service on host is reachable
                for svc in host.services:
                    if is_traffic_allowed(
                        spec.firewall_rules,
                        src_network=src_net,
                        src_host=None,
                        dst_network=host.network_id,
                        dst_host=host.id,
                        dst_port=svc.port,
                        dst_protocol=svc.protocol,
                    ):
                        reachable = True
                        break
                if reachable:
                    break

            if reachable:
                effects.append(
                    EffectSpec(
                        primitive=EffectPrimitive.discover_asset,
                        params={"asset_id": host.id, "asset_type": "host"},
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
        detecting_controls = evaluate_controls_for_action(state, spec, action, target_host_id=None)

        scan_event = Event(
            id=f"evt-{uuid.uuid4().hex[:8]}",
            tick=state.tick,
            sequence=0,
            type=EventType.scan_attempt,
            actor_id=action.actor_id,
            target_id=action.target_id,
            target_type=TargetType.network,
            success=success,
            severity=Severity.info,
            visibility=EventVisibility(
                visible_to_attacker=True,
                visible_to_defender=bool(detecting_controls),
                detected_by_controls=detecting_controls,
            ),
            metadata={"target_network": action.target_id},
        )
        events.append(scan_event)

        if success:
            actor = state.actors.get(action.actor_id)
            target_network_id = action.target_id
            seq = 1
            for host in spec.hosts:
                if host.network_id == target_network_id and host.is_online:
                    disc_event = Event(
                        id=f"evt-{uuid.uuid4().hex[:8]}",
                        tick=state.tick,
                        sequence=seq,
                        type=EventType.host_discovered,
                        actor_id=action.actor_id,
                        target_id=host.id,
                        target_type=TargetType.host,
                        success=True,
                        severity=Severity.info,
                        visibility=EventVisibility(visible_to_attacker=True, visible_to_defender=False),
                        metadata={"host_id": host.id, "ip": host.ip_address, "hostname": host.hostname},
                    )
                    events.append(disc_event)
                    seq += 1

        if detecting_controls:
            events.extend(create_detection_events(scan_event, detecting_controls, spec, state.tick))

        return events
