from statecraft.model.security import FirewallRule, RuleAction


def is_traffic_allowed(
    firewall_rules: list[FirewallRule],
    src_network: str | None,
    src_host: str | None,
    dst_network: str | None,
    dst_host: str | None,
    dst_port: int | None = None,
    dst_protocol: str | None = None,
) -> bool:
    """Evaluate ordered firewall rules (lower priority number = evaluated first).

    Same-network traffic is allowed by default unless an explicit deny rule matches.
    Cross-network traffic defaults to deny unless an explicit allow rule matches.
    """
    # Host-specific rules override broad network rules (per spec Section 4 line 594)
    def rule_sort_key(r: FirewallRule):
        specificity = 0 if (r.from_host is not None or r.to_host is not None) else 1
        return (specificity, r.priority)

    sorted_rules = sorted(firewall_rules, key=rule_sort_key)

    for rule in sorted_rules:
        # Check source match
        if rule.from_host is not None:
            if src_host is None or rule.from_host != src_host:
                continue
        elif rule.from_network is not None:
            if src_network is None or rule.from_network != src_network:
                continue

        # Check destination match
        if rule.to_host is not None:
            if dst_host is None or rule.to_host != dst_host:
                continue
        elif rule.to_network is not None:
            if dst_network is None or rule.to_network != dst_network:
                continue

        # Check port
        if rule.port is not None and dst_port is not None:
            if rule.port != dst_port:
                continue

        # Check protocol
        if rule.protocol is not None and dst_protocol is not None:
            if rule.protocol.lower() != dst_protocol.lower():
                continue

        # First matching rule wins
        return rule.action == RuleAction.allow

    # Default rule: if within same network segment, allow; if cross-network, deny
    if src_network and dst_network and src_network == dst_network:
        return True

    return False
