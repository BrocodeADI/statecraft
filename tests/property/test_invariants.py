import copy

from statecraft.agents.scripted_attacker import get_university_attack_path
from statecraft.effects.primitives import PRIMITIVE_HANDLERS
from statecraft.engine.executor import ActionExecutor
from statecraft.engine.rng import SeededRNG
from statecraft.engine.simulator import Simulator
from statecraft.engine.state_builder import build_initial_state
from statecraft.engine.state_store import StateStore
from statecraft.model.actions import ActionVerb, ProposedAction
from statecraft.model.security import EffectPrimitive
from statecraft.replay.replayer import Replayer
from statecraft.spec.loader import load_spec


def test_deterministic_simulation_invariant():
    """For any (EnvironmentSpec, seed, action_sequence) tuple, resulting state and event log are always identical."""
    spec = load_spec("scenarios/university-network.yaml")
    actions = get_university_attack_path()

    sim1 = Simulator(spec, seed=42)
    for a in actions:
        sim1.step(a)

    sim2 = Simulator(spec, seed=42)
    for a in actions:
        sim2.step(a)

    assert sim1.current_state.tick == sim2.current_state.tick
    assert sim1.current_state.achieved_objectives == sim2.current_state.achieved_objectives
    assert len(sim1._recorded_events) == len(sim2._recorded_events)
    for e1, e2 in zip(sim1._recorded_events, sim2._recorded_events):
        assert e1.type == e2.type
        assert e1.target_id == e2.target_id
        assert e1.success == e2.success


def test_action_never_mutates_previous_snapshots_invariant():
    """Applying any action never modifies existing state snapshots."""
    spec = load_spec("scenarios/university-network.yaml")
    initial_state = build_initial_state(spec)
    store = StateStore(initial_state)
    executor = ActionExecutor(spec, store, SeededRNG(42))

    actions = get_university_attack_path()
    snapshots_before = []

    for action in actions:
        current_before = copy.deepcopy(store.current())
        snapshots_before.append((store.current().tick, current_before))
        executor.execute(action)

        # Verify all previous snapshots in store remain identical to their historical copies
        for tick, historical_copy in snapshots_before:
            store_snapshot = store.state_at(tick)
            assert store_snapshot.tick == historical_copy.tick
            assert store_snapshot.achieved_objectives == historical_copy.achieved_objectives
            assert set(store_snapshot.sessions.keys()) == set(historical_copy.sessions.keys())


def test_effects_stay_within_closed_vocabulary():
    """All 12 primitives in EffectPrimitive are recognized in PRIMITIVE_HANDLERS."""
    for primitive in EffectPrimitive:
        assert primitive in PRIMITIVE_HANDLERS
    assert len(EffectPrimitive) == 12
