from statecraft.agents.scripted_attacker import get_university_attack_path
from statecraft.engine.simulator import Simulator
from statecraft.model.events import EventType
from statecraft.replay.replayer import Replayer
from statecraft.spec.loader import load_spec


def test_university_scenario_full_attack_path():
    spec = load_spec("scenarios/university-network.yaml")
    sim = Simulator(spec, seed=42)
    actions = get_university_attack_path()

    for idx, act in enumerate(actions, 1):
        result = sim.step(act)
        assert result.success is True, f"Action at step {idx} ({act.verb.value}) failed: {result.failure_reason}"

    # Verify final state
    state = sim.current_state
    assert state.tick == 7
    assert "obj.exfiltrate_pii" in state.achieved_objectives

    # Verify WAF triggered on Tick 3 (exploit on WEB01)
    waf_detections = [
        e for e in sim._recorded_events
        if e.type == EventType.detection_triggered and e.metadata.get("control_id") == "ctrl.waf.web01"
    ]
    assert len(waf_detections) >= 1

    # Verify deterministic replay bit-for-bit
    run = sim.to_run()
    replayer = Replayer()
    replayed_state, replayed_events = replayer.replay_run(run)

    assert replayed_state.tick == state.tick
    assert replayed_state.achieved_objectives == state.achieved_objectives
    assert len(replayed_events) == len(sim._recorded_events)
