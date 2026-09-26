"""
Adapter that converts real Statecraft engine runtime data into visualization-ready JSON.

This is the bridge between the authoritative engine and the visual presentation layer.
Every visualization event originates from real engine execution - nothing is fabricated.
"""

from __future__ import annotations

import json
from typing import Any

from statecraft.model.actions import ProposedAction
from statecraft.model.events import Event, EventType
from statecraft.spec.schema import EnvironmentSpec


def spec_to_topology(spec: EnvironmentSpec) -> dict[str, Any]:
    """Convert EnvironmentSpec into a topology descriptor for the SVG network map."""
    networks = []
    for n in spec.networks:
        networks.append({
            "id": n.id,
            "label": n.label,
            "zone": n.zone.value,
            "cidr": n.cidr,
        })

    hosts = []
    for h in spec.hosts:
        services = []
        for s in h.services:
            services.append({
                "id": s.id,
                "port": s.port,
                "software": s.software.name,
                "version": s.software.version,
                "banner": s.banner,
                "vulnerabilities": list(s.vulnerabilities),
            })
        hosts.append({
            "id": h.id,
            "hostname": h.hostname,
            "network_id": h.network_id,
            "ip": h.ip_address,
            "os": f"{h.os.distro} {h.os.version}",
            "services": services,
            "controls": list(h.security_controls),
        })

    controls = []
    for c in spec.security_controls:
        controls.append({
            "id": c.id,
            "type": c.type.value,
            "host_id": c.host_id,
            "is_active": c.is_active,
        })

    assets = []
    for a in spec.data_assets:
        assets.append({
            "id": a.id,
            "host_id": a.host_id,
            "label": a.label,
            "sensitivity": a.sensitivity.value,
        })

    objectives = []
    for o in spec.objectives:
        objectives.append({
            "id": o.id,
            "label": o.label,
            "target_id": o.target_id,
        })

    return {
        "name": spec.metadata.name,
        "description": spec.metadata.description,
        "seed": spec.seed,
        "networks": networks,
        "hosts": hosts,
        "controls": controls,
        "assets": assets,
        "objectives": objectives,
        "attacker_start": {
            "type": spec.initial_attacker_position.type,
            "network_id": spec.initial_attacker_position.network_id,
        },
    }


def action_to_viz(tick: int, action: ProposedAction) -> dict[str, Any]:
    """Convert a ProposedAction into a visualization-ready dictionary."""
    return {
        "tick": tick,
        "actor_id": action.actor_id,
        "verb": action.verb.value,
        "target_id": action.target_id,
        "parameters": dict(action.parameters) if action.parameters else {},
    }


def event_to_viz(event: Event) -> dict[str, Any]:
    """Convert a real engine Event into a visualization-ready dictionary."""
    return {
        "id": event.id,
        "tick": event.tick,
        "sequence": event.sequence,
        "type": event.type.value,
        "actor_id": event.actor_id,
        "target_id": event.target_id,
        "target_type": event.target_type.value,
        "success": event.success,
        "severity": event.severity.value,
        "metadata": dict(event.metadata),
        "caused_by": event.caused_by,
        "category": _event_category(event.type),
    }


def _event_category(event_type: EventType) -> str:
    """Classify event type into a visual category for rendering."""
    discovery = {EventType.scan_attempt, EventType.host_discovered, EventType.service_discovered}
    auth = {EventType.authentication_attempt, EventType.authentication_success, EventType.authentication_failure}
    exploit = {EventType.exploit_attempt, EventType.exploit_success, EventType.exploit_failure}
    movement = {EventType.lateral_movement, EventType.credential_acquired}
    data = {EventType.data_access}
    defense = {EventType.detection_triggered, EventType.control_disabled}
    objective = {EventType.objective_achieved}

    if event_type in discovery:
        return "discovery"
    if event_type in auth:
        return "auth"
    if event_type in exploit:
        return "exploit"
    if event_type in movement:
        return "movement"
    if event_type in data:
        return "data"
    if event_type in defense:
        return "defense"
    if event_type in objective:
        return "objective"
    return "other"


def build_run_payload(
    spec: EnvironmentSpec,
    ticks: list[dict[str, Any]],
    replay_match: bool,
    replay_stats: dict[str, Any] | None = None,
    fast: bool = False,
    ai_demo: dict[str, Any] | None = None,
) -> str:
    """Build the complete JSON payload that the visual dashboard will consume.

    Args:
        spec: The EnvironmentSpec used in the simulation.
        ticks: List of tick data dicts, each with 'action' and 'result' keys.
        replay_match: Whether deterministic replay matched.
        replay_stats: Optional replay comparison stats.
        fast: Whether fast mode was requested (skips narration delays).
        ai_demo: Optional AI Action Proposer demonstration results.

    Returns:
        JSON string for embedding in the HTML dashboard.
    """
    payload = {
        "topology": spec_to_topology(spec),
        "ticks": ticks,
        "replay": {
            "match": replay_match,
            "stats": replay_stats or {},
        },
        "fast": fast,
        "ai_demo": ai_demo,
    }
    return json.dumps(payload, indent=None, default=str)
