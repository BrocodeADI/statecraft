from statecraft.effects.primitives import PRIMITIVE_HANDLERS
from statecraft.engine.state_store import apply_delta_to_state
from statecraft.model.security import EffectPrimitive, EffectSpec
from statecraft.model.state import EnvironmentState, StateDelta


class EffectComposer:
    """Composes a sequence of EffectSpec objects into a cumulative StateDelta."""

    def compose(
        self,
        state: EnvironmentState,
        effect_specs: list[EffectSpec],
        actor_id: str,
        tick_advance: int = 1,
    ) -> StateDelta:
        current_state = state
        cumulative_delta = StateDelta(tick_advance=tick_advance)

        for spec in effect_specs:
            prim = spec.primitive
            if not isinstance(prim, EffectPrimitive):
                try:
                    prim = EffectPrimitive(prim)
                except ValueError:
                    raise ValueError(f"Unknown effect primitive: {spec.primitive}")

            handler = PRIMITIVE_HANDLERS.get(prim)
            if not handler:
                raise ValueError(f"No handler found for primitive: {prim}")

            # Check condition if present (simple predicate evaluation)
            if spec.condition:
                # In v1, conditions are simple state predicates or None
                pass

            step_delta = handler(current_state, actor_id, spec.params)

            # Merge step_delta into cumulative_delta
            cumulative_delta.added_sessions.extend(step_delta.added_sessions)
            cumulative_delta.removed_session_ids.extend(step_delta.removed_session_ids)
            cumulative_delta.updated_session_levels.update(step_delta.updated_session_levels)
            cumulative_delta.updated_host_states.update(step_delta.updated_host_states)
            cumulative_delta.updated_service_states.update(step_delta.updated_service_states)
            cumulative_delta.updated_actor_states.update(step_delta.updated_actor_states)
            cumulative_delta.updated_control_states.update(step_delta.updated_control_states)
            for obj_id in step_delta.achieved_objectives:
                if obj_id not in cumulative_delta.achieved_objectives:
                    cumulative_delta.achieved_objectives.append(obj_id)

            # Advance running state so subsequent effects see changes
            current_state = apply_delta_to_state(current_state, step_delta)

        return cumulative_delta
