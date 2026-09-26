from statecraft.engine.executor import ActionExecutor
from statecraft.engine.rng import SeededRNG
from statecraft.engine.state_builder import build_initial_state
from statecraft.engine.state_store import StateStore
from statecraft.model.actions import ActionVerb, FailureReason, ProposedAction
from statecraft.spec.loader import load_spec


def test_executor_immutability():
    spec = load_spec("scenarios/university-network.yaml")
    initial_state = build_initial_state(spec)
    store = StateStore(initial_state)
    executor = ActionExecutor(spec, store, SeededRNG(42))

    action = ProposedAction(actor_id="actor_attacker", verb=ActionVerb.scan, target_id="net.dmz")
    result = executor.execute(action)
    assert result.success is True

    # Confirm snapshot 0 was NOT mutated
    snap0 = store.state_at(0)
    snap1 = store.state_at(1)
    assert snap0.tick == 0
    assert snap1.tick == 1
    assert "host.web01" not in snap0.actors["actor_attacker"].known_host_ids
    assert "host.web01" in snap1.actors["actor_attacker"].known_host_ids


def test_action_fails_when_target_not_discovered():
    spec = load_spec("scenarios/university-network.yaml")
    initial_state = build_initial_state(spec)
    store = StateStore(initial_state)
    executor = ActionExecutor(spec, store, SeededRNG(42))

    # Attempting to enumerate WEB01 before scanning
    action = ProposedAction(actor_id="actor_attacker", verb=ActionVerb.enumerate, target_id="host.web01")
    result = executor.execute(action)

    assert result.success is False
    assert result.failure_reason == FailureReason.target_not_discovered
    assert store.current().tick == 0  # No state change


def test_action_fails_when_not_reachable():
    spec = load_spec("scenarios/university-network.yaml")
    initial_state = build_initial_state(spec)
    store = StateStore(initial_state)
    executor = ActionExecutor(spec, store, SeededRNG(42))

    # Attacker starting at external tries to scan internal network directly (blocked by firewall fw.003)
    action = ProposedAction(actor_id="actor_attacker", verb=ActionVerb.scan, target_id="net.internal")
    result = executor.execute(action)

    assert result.success is False
    assert result.failure_reason == FailureReason.not_reachable
    assert store.current().tick == 0


def test_failed_authenticate_invalid_cred():
    spec = load_spec("scenarios/university-network.yaml")
    initial_state = build_initial_state(spec)
    store = StateStore(initial_state)
    executor = ActionExecutor(spec, store, SeededRNG(42))

    # Scan and enumerate web01 first
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.scan, target_id="net.dmz"))
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.enumerate, target_id="host.web01"))

    # Authenticate with unowned cred
    action = ProposedAction(
        actor_id="actor_attacker",
        verb=ActionVerb.authenticate,
        target_id="svc.web01.app",
        parameters={"credential_id": "cred.nonexistent"},
    )
    result = executor.execute(action)
    assert result.success is False
    assert result.failure_reason == FailureReason.no_compatible_credential


def test_persist_and_escalate_privilege():
    spec = load_spec("scenarios/university-network.yaml")
    initial_state = build_initial_state(spec)
    store = StateStore(initial_state)
    executor = ActionExecutor(spec, store, SeededRNG(42))

    # Follow steps to compromise DB01
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.scan, target_id="net.dmz"))
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.enumerate, target_id="host.web01"))
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.exploit, target_id="svc.web01.app", parameters={"vuln_id": "vuln.sqli-studentportal"}))
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.pivot, target_id="net.internal", parameters={"via": "host.web01"}))
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.scan, target_id="net.internal"))
    auth_res = executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.authenticate, target_id="svc.db01.postgres", parameters={"credential_id": "cred.db01.app_user"}))
    assert auth_res.success is True

    # Test persist action on DB01
    persist_res = executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.persist, target_id="host.db01"))
    assert persist_res.success is True
    assert "actor_attacker" in store.current().hosts["host.db01"].persistent_actors

    # Test escalate_privilege on DB01 (cred.db01.postgres is known or weak admin cred)
    # Apply delta to give actor the admin cred
    actor_state = store.current().actors["actor_attacker"].model_copy(deep=True)
    actor_state.known_credential_ids.append("cred.db01.postgres")
    from statecraft.model.state import StateDelta
    store.apply_delta(StateDelta(updated_actor_states={"actor_attacker": actor_state}, tick_advance=0))

    esc_res = executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.escalate_privilege, target_id="host.db01"))
    assert esc_res.success is True
