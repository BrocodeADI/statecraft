from statecraft.engine.executor import ActionExecutor
from statecraft.engine.rng import SeededRNG
from statecraft.engine.state_builder import build_initial_state
from statecraft.engine.state_store import StateStore
from statecraft.model.actions import ActionVerb, ProposedAction
from statecraft.observation.attacker_view import ObservationEngine
from statecraft.spec.loader import load_spec


def test_fog_of_war_observation():
    spec = load_spec("scenarios/university-network.yaml")
    initial_state = build_initial_state(spec)
    store = StateStore(initial_state)
    executor = ActionExecutor(spec, store, SeededRNG(42))
    obs_engine = ObservationEngine()

    # Initial observation: no hosts or services known
    obs0 = obs_engine.attacker_view(store.current(), spec, "actor_attacker")
    assert len(obs0.known_hosts) == 0
    assert len(obs0.known_services) == 0
    assert len(obs0.known_credentials) == 0

    # Step 1: Scan DMZ
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.scan, target_id="net.dmz"))
    obs1 = obs_engine.attacker_view(store.current(), spec, "actor_attacker")

    # Discovered WEB01, but services are still not enumerated!
    assert len(obs1.known_hosts) == 1
    assert obs1.known_hosts[0].id == "host.web01"
    assert len(obs1.known_services) == 0  # Still fog of war!

    # Attacker CANNOT see DC01 or DB01
    known_host_ids = [h.id for h in obs1.known_hosts]
    assert "host.dc01" not in known_host_ids
    assert "host.db01" not in known_host_ids

    # Step 2: Enumerate WEB01
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.enumerate, target_id="host.web01"))
    obs2 = obs_engine.attacker_view(store.current(), spec, "actor_attacker")
    assert len(obs2.known_services) == 2

    # Step 3: Exploit SQLi
    executor.execute(ProposedAction(actor_id="actor_attacker", verb=ActionVerb.exploit, target_id="svc.web01.app", parameters={"vuln_id": "vuln.sqli-studentportal"}))
    obs3 = obs_engine.attacker_view(store.current(), spec, "actor_attacker")
    assert "cred.db01.app_user" in obs3.known_credentials
