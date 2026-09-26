from statecraft.model.actors import CapabilityType
from statecraft.model.state import (
    ActorState,
    ControlState,
    EnvironmentState,
    HostState,
    ServiceState,
)
from statecraft.spec.schema import EnvironmentSpec


def build_initial_state(spec: EnvironmentSpec, attacker_id: str = "actor_attacker") -> EnvironmentState:
    """Builds initial ground-truth EnvironmentState from a validated EnvironmentSpec."""
    # Build host states
    host_states = {
        h.id: HostState(
            id=h.id,
            is_online=h.is_online,
            compromised=False,
            persistent_actors=[],
        )
        for h in spec.hosts
    }

    # Build service states
    service_states = {
        s.id: ServiceState(
            id=s.id,
            is_running=s.is_running,
        )
        for h in spec.hosts
        for s in h.services
    }

    # Build control states
    control_states = {
        c.id: ControlState(
            id=c.id,
            is_active=c.is_active,
        )
        for c in spec.security_controls
    }

    # Resolve initial reachable network for attacker
    initial_networks: list[str] = []
    if spec.initial_attacker_position.network_id:
        initial_networks.append(spec.initial_attacker_position.network_id)
    elif spec.initial_attacker_position.host_id:
        for h in spec.hosts:
            if h.id == spec.initial_attacker_position.host_id:
                initial_networks.append(h.network_id)
                break

    # Build attacker state
    attacker_state = ActorState(
        id=attacker_id,
        reachable_networks=initial_networks,
        known_host_ids=[],
        enumerated_host_ids=[],
        known_service_ids=[],
        known_credential_ids=[],
        known_data_asset_ids=[],
        accessed_files=[],
        accessed_assets=[],
        capabilities=[c.value for c in CapabilityType],
    )

    return EnvironmentState(
        tick=0,
        hosts=host_states,
        services=service_states,
        actors={attacker_id: attacker_state},
        sessions={},
        controls=control_states,
        achieved_objectives=[],
        event_count=0,
    )
