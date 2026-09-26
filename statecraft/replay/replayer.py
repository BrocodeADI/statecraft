from statecraft.engine.executor import ActionExecutor
from statecraft.engine.rng import SeededRNG
from statecraft.engine.state_builder import build_initial_state
from statecraft.engine.state_store import StateStore
from statecraft.model.events import Event
from statecraft.model.state import EnvironmentState
from statecraft.persistence.run import Run


class Replayer:
    """Replays an event or action sequence deterministically to reconstruct past states."""

    def replay_run(self, run: Run) -> tuple[EnvironmentState, list[Event]]:
        """Re-executes the exact action sequence against the spec to reproduce state and events."""
        spec = run.environment_spec
        rng = SeededRNG(run.seed)
        initial_state = build_initial_state(spec)
        store = StateStore(initial_state)
        executor = ActionExecutor(spec=spec, state_store=store, rng=rng)

        replayed_events: list[Event] = []

        for action in run.actions:
            result = executor.execute(action)
            replayed_events.extend(result.events)

        return store.current(), replayed_events

    def replay_to(self, run: Run, target_tick: int) -> EnvironmentState:
        """Reconstructs state at or up to a specific simulation tick."""
        spec = run.environment_spec
        rng = SeededRNG(run.seed)
        initial_state = build_initial_state(spec)
        store = StateStore(initial_state)
        executor = ActionExecutor(spec=spec, state_store=store, rng=rng)

        current_tick = 0
        for action in run.actions:
            if current_tick >= target_tick:
                break
            result = executor.execute(action)
            current_tick = store.current().tick

        return store.current()
