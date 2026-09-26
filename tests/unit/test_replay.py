from pathlib import Path

from statecraft.agents.scripted_attacker import get_university_attack_path
from statecraft.engine.simulator import Simulator
from statecraft.persistence.export import export_run, import_run
from statecraft.replay.replayer import Replayer
from statecraft.spec.loader import load_spec


def test_deterministic_replay():
    spec = load_spec("scenarios/university-network.yaml")
    sim = Simulator(spec, seed=42)
    actions = get_university_attack_path()

    for act in actions:
        sim.step(act)

    original_run = sim.to_run()
    replayer = Replayer()

    replayed_state, replayed_events = replayer.replay_run(original_run)

    # Invariant: final state matches exactly
    assert sim.current_state.tick == replayed_state.tick
    assert sim.current_state.achieved_objectives == replayed_state.achieved_objectives
    assert len(original_run.events) == len(replayed_events)
    assert set(sim.current_state.sessions.keys()) == set(replayed_state.sessions.keys())


def test_mid_run_replay():
    spec = load_spec("scenarios/university-network.yaml")
    sim = Simulator(spec, seed=42)
    actions = get_university_attack_path()

    for act in actions:
        sim.step(act)

    run = sim.to_run()
    replayer = Replayer()

    # Replay up to tick 3
    state_at_3 = replayer.replay_to(run, target_tick=3)
    assert state_at_3.tick == 3
    assert "host.web01" in state_at_3.actors["actor_attacker"].known_host_ids
    assert "cred.db01.app_user" in state_at_3.actors["actor_attacker"].known_credential_ids
    # Not yet pivoted to net.internal
    assert "net.internal" not in state_at_3.actors["actor_attacker"].reachable_networks


def test_export_import_roundtrip(tmp_path: Path):
    spec = load_spec("scenarios/university-network.yaml")
    sim = Simulator(spec, seed=42)
    for act in get_university_attack_path():
        sim.step(act)

    run = sim.to_run()
    scr_file = tmp_path / "university_run.scr"

    export_run(run, scr_file)
    assert scr_file.is_file()

    imported = import_run(scr_file)
    assert imported.id == run.id
    assert len(imported.actions) == len(run.actions)
    assert len(imported.events) == len(run.events)

    replayer = Replayer()
    replayed_state, _ = replayer.replay_run(imported)
    assert replayed_state.tick == sim.current_state.tick
    assert replayed_state.achieved_objectives == sim.current_state.achieved_objectives
