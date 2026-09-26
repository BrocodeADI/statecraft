import ipaddress

from statecraft.spec.schema import EnvironmentSpec
from statecraft.validator.errors import ValidationError


def validate_graph_consistency(spec: EnvironmentSpec) -> list[ValidationError]:
    """Stage 3: Graph Consistency. IP in CIDR, no duplicate IP per network, valid firewall refs."""
    errors: list[ValidationError] = []

    network_map = {n.id: n for n in spec.networks}
    host_map = {h.id: h for h in spec.hosts}
    seen_ips: dict[tuple[str, str], str] = {}  # (network_id, ip) -> host_id

    # Check network CIDR validity
    parsed_cidrs: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
    for net in spec.networks:
        try:
            parsed_cidrs[net.id] = ipaddress.ip_network(net.cidr, strict=False)
        except ValueError as e:
            errors.append(
                ValidationError(
                    stage="stage_3_graph",
                    error_type="GraphError",
                    message=f"Network '{net.id}' has invalid CIDR '{net.cidr}': {e}",
                    entity_id=net.id,
                )
            )

    # Check host IPs
    for host in spec.hosts:
        net = network_map.get(host.network_id)
        if not net or net.id not in parsed_cidrs:
            continue

        cidr_net = parsed_cidrs[net.id]
        try:
            ip = ipaddress.ip_address(host.ip_address)
            if ip not in cidr_net:
                errors.append(
                    ValidationError(
                        stage="stage_3_graph",
                        error_type="GraphError",
                        message=f"Host '{host.id}' IP '{host.ip_address}' is not within network '{net.id}' CIDR '{net.cidr}'",
                        entity_id=host.id,
                    )
                )
        except ValueError as e:
            errors.append(
                ValidationError(
                    stage="stage_3_graph",
                    error_type="GraphError",
                    message=f"Host '{host.id}' has invalid IP address '{host.ip_address}': {e}",
                    entity_id=host.id,
                )
            )

        # Duplicate IP check
        key = (host.network_id, host.ip_address)
        if key in seen_ips:
            errors.append(
                ValidationError(
                    stage="stage_3_graph",
                    error_type="GraphError",
                    message=f"Duplicate IP address '{host.ip_address}' in network '{host.network_id}' shared by '{seen_ips[key]}' and '{host.id}'",
                    entity_id=host.id,
                )
            )
        else:
            seen_ips[key] = host.id

    # Firewall rule endpoint checks
    for fw in spec.firewall_rules:
        if fw.from_network and fw.from_network not in network_map:
            errors.append(
                ValidationError(
                    stage="stage_3_graph",
                    error_type="GraphError",
                    message=f"Firewall rule '{fw.id}' references unknown from_network '{fw.from_network}'",
                    entity_id=fw.id,
                )
            )
        if fw.to_network and fw.to_network not in network_map:
            errors.append(
                ValidationError(
                    stage="stage_3_graph",
                    error_type="GraphError",
                    message=f"Firewall rule '{fw.id}' references unknown to_network '{fw.to_network}'",
                    entity_id=fw.id,
                )
            )
        if fw.from_host and fw.from_host not in host_map:
            errors.append(
                ValidationError(
                    stage="stage_3_graph",
                    error_type="GraphError",
                    message=f"Firewall rule '{fw.id}' references unknown from_host '{fw.from_host}'",
                    entity_id=fw.id,
                )
            )
        if fw.to_host and fw.to_host not in host_map:
            errors.append(
                ValidationError(
                    stage="stage_3_graph",
                    error_type="GraphError",
                    message=f"Firewall rule '{fw.id}' references unknown to_host '{fw.to_host}'",
                    entity_id=fw.id,
                )
            )

    return errors
