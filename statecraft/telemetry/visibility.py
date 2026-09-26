import uuid
from typing import Any

from statecraft.model.actions import ProposedAction
from statecraft.model.events import Event, EventType, EventVisibility, Severity, TargetType
from statecraft.model.security import VulnClass
from statecraft.model.state import EnvironmentState
from statecraft.spec.schema import EnvironmentSpec


def evaluate_controls_for_action(
    state: EnvironmentState,
    spec: EnvironmentSpec,
    action: ProposedAction,
    target_host_id: str | None,
    vuln_class: VulnClass | None = None,
) -> list[str]:
    """Find all active control IDs that detect this action."""
    detecting_control_ids: list[str] = []

    for ctrl in spec.security_controls:
        # Check if control is active in current state
        ctrl_state = state.controls.get(ctrl.id)
        if ctrl_state and not ctrl_state.is_active:
            continue
        if not ctrl.is_active:
            continue

        # Check detection rules
        for rule in ctrl.detects:
            if rule.action_verb and rule.action_verb != action.verb.value:
                continue

            if rule.target_host and target_host_id and rule.target_host != target_host_id:
                continue

            if rule.vuln_class and vuln_class and rule.vuln_class != vuln_class:
                continue

            # Matched rule!
            detecting_control_ids.append(ctrl.id)
            break

    return detecting_control_ids


def create_detection_events(
    parent_event: Event,
    detecting_control_ids: list[str],
    spec: EnvironmentSpec,
    tick: int,
) -> list[Event]:
    """Generate derivative detection_triggered events for each detecting control."""
    events: list[Event] = []
    ctrl_map = {c.id: c for c in spec.security_controls}

    for ctrl_id in detecting_control_ids:
        ctrl = ctrl_map.get(ctrl_id)
        ctrl_type = ctrl.type.value if ctrl else "unknown"
        delay = ctrl.alert_delay_ticks if ctrl else 0

        det_event = Event(
            id=f"evt-det-{uuid.uuid4().hex[:8]}",
            tick=tick,
            type=EventType.detection_triggered,
            actor_id=parent_event.actor_id,
            target_id=ctrl_id,
            target_type=TargetType.host,
            success=True,
            severity=Severity.high,
            visibility=EventVisibility(
                visible_to_attacker=False,
                visible_to_defender=True,
                detected_by_controls=[ctrl_id],
                detection_delay_ticks=delay,
            ),
            metadata={
                "control_id": ctrl_id,
                "control_type": ctrl_type,
                "detected_event_id": parent_event.id,
                "detected_action": parent_event.type.value,
            },
            caused_by=parent_event.id,
        )
        events.append(det_event)

    return events
