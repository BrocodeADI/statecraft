import copy

from statecraft.model.state import EnvironmentState, StateDelta


def apply_delta_to_state(current_state: EnvironmentState, delta: StateDelta) -> EnvironmentState:
    """Pure function: takes current EnvironmentState and StateDelta, returns a new EnvironmentState."""
    new_state = current_state.model_copy(deep=True)

    # Apply sessions
    for session in delta.added_sessions:
        new_state.sessions[session.id] = session.model_copy(deep=True)
        # Marking host compromised if session added
        if session.host_id in new_state.hosts:
            new_state.hosts[session.host_id].compromised = True

    for sess_id in delta.removed_session_ids:
        if sess_id in new_state.sessions:
            new_state.sessions[sess_id].is_active = False

    for sess_id, new_level in delta.updated_session_levels.items():
        if sess_id in new_state.sessions:
            new_state.sessions[sess_id].privilege_level = new_level

    # Apply host updates
    for h_id, h_state in delta.updated_host_states.items():
        new_state.hosts[h_id] = h_state.model_copy(deep=True)

    # Apply service updates
    for s_id, s_state in delta.updated_service_states.items():
        new_state.services[s_id] = s_state.model_copy(deep=True)

    # Apply actor updates
    for a_id, a_state in delta.updated_actor_states.items():
        new_state.actors[a_id] = a_state.model_copy(deep=True)

    # Apply control updates
    for c_id, c_state in delta.updated_control_states.items():
        new_state.controls[c_id] = c_state.model_copy(deep=True)

    # Apply objectives
    for obj_id in delta.achieved_objectives:
        if obj_id not in new_state.achieved_objectives:
            new_state.achieved_objectives.append(obj_id)

    # Tick advance
    new_state.tick += delta.tick_advance

    return new_state


class StateStore:
    """Manages immutable snapshots of EnvironmentState."""

    def __init__(self, initial_state: EnvironmentState):
        self._snapshots: list[EnvironmentState] = [initial_state.model_copy(deep=True)]
        self._current_index: int = 0

    def apply_delta(self, delta: StateDelta) -> EnvironmentState:
        """Creates a new snapshot by applying delta. Never mutates existing snapshots."""
        current = self._snapshots[self._current_index]
        new_state = apply_delta_to_state(current, delta)
        self._snapshots.append(new_state)
        self._current_index += 1
        return new_state

    def state_at(self, tick: int) -> EnvironmentState:
        """Read-only access to historical state snapshot at tick."""
        if 0 <= tick < len(self._snapshots):
            return self._snapshots[tick].model_copy(deep=True)
        # Otherwise find nearest
        nearest = max(s for s in self._snapshots if s.tick <= tick)
        return nearest.model_copy(deep=True)

    def current(self) -> EnvironmentState:
        """Returns read-only copy of current state snapshot."""
        return self._snapshots[self._current_index].model_copy(deep=True)

    @property
    def snapshot_count(self) -> int:
        return len(self._snapshots)
