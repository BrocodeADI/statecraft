from statecraft.engine.firewall import is_traffic_allowed
from statecraft.spec.schema import EnvironmentSpec
from statecraft.validator.errors import ValidationError


def validate_reachability(spec: EnvironmentSpec) -> list[ValidationError]:
    """Stage 4: Reachability.

    - Attacker's initial position can reach at least one host
    - At least one host has at least one running service
    - At least one service is reachable from the attacker's position
    """
    errors: list[ValidationError] = []

    src_network = spec.initial_attacker_position.network_id
    src_host = spec.initial_attacker_position.host_id

    # If starting on a host, look up that host's network
    if src_host and not src_network:
        for h in spec.hosts:
            if h.id == src_host:
                src_network = h.network_id
                break

    # 1. Can reach at least one host
    reachable_hosts = []
    for host in spec.hosts:
        # Check general reachability to host or any of its services
        if is_traffic_allowed(
            spec.firewall_rules,
            src_network=src_network,
            src_host=src_host,
            dst_network=host.network_id,
            dst_host=host.id,
        ):
            reachable_hosts.append(host)
        else:
            # Check if any service on the host allows traffic through port-specific rules
            for svc in host.services:
                if is_traffic_allowed(
                    spec.firewall_rules,
                    src_network=src_network,
                    src_host=src_host,
                    dst_network=host.network_id,
                    dst_host=host.id,
                    dst_port=svc.port,
                    dst_protocol=svc.protocol,
                ):
                    reachable_hosts.append(host)
                    break

    if not reachable_hosts:
        errors.append(
            ValidationError(
                stage="stage_4_reachability",
                error_type="ReachabilityError",
                message="Attacker cannot reach any host from the initial position per firewall rules",
                entity_id=spec.initial_attacker_position.network_id or spec.initial_attacker_position.host_id,
            )
        )

    # 2. At least one host has at least one running service
    running_services = [
        (h, s)
        for h in spec.hosts
        if h.is_online
        for s in h.services
        if s.is_running
    ]
    if not running_services:
        errors.append(
            ValidationError(
                stage="stage_4_reachability",
                error_type="ReachabilityError",
                message="No running services found on any online host in the environment",
            )
        )

    # 3. At least one service is reachable from attacker position
    reachable_services = []
    for host, svc in running_services:
        if is_traffic_allowed(
            spec.firewall_rules,
            src_network=src_network,
            src_host=src_host,
            dst_network=host.network_id,
            dst_host=host.id,
            dst_port=svc.port,
            dst_protocol=svc.protocol,
        ):
            reachable_services.append(svc)

    if not reachable_services:
        errors.append(
            ValidationError(
                stage="stage_4_reachability",
                error_type="ReachabilityError",
                message="No running service is reachable from the attacker's initial position",
            )
        )

    return errors
