import pytest

from statecraft.effects.composer import EffectComposer
from statecraft.engine.state_builder import build_initial_state
from statecraft.engine.state_store import apply_delta_to_state
from statecraft.model.identity import PrivilegeLevel
from statecraft.model.security import EffectPrimitive, EffectSpec
from statecraft.spec.loader import load_spec


@pytest.fixture
def base_state():
    spec = load_spec("scenarios/university-network.yaml")
    return build_initial_state(spec)


def test_grant_session_and_elevate(base_state):
    composer = EffectComposer()
    effects = [
        EffectSpec(
            primitive=EffectPrimitive.grant_session,
            params={
                "session_id": "sess-123",
                "host_id": "host.web01",
                "privilege_level": "user",
            },
        ),
        EffectSpec(
            primitive=EffectPrimitive.elevate_privilege,
            params={
                "session_id": "sess-123",
                "new_privilege_level": "root",
            },
        ),
    ]

    delta = composer.compose(base_state, effects, actor_id="actor_attacker")
    new_state = apply_delta_to_state(base_state, delta)

    assert "sess-123" in new_state.sessions
    assert new_state.sessions["sess-123"].privilege_level == PrivilegeLevel.root
    assert new_state.hosts["host.web01"].compromised is True


def test_obtain_credential(base_state):
    composer = EffectComposer()
    effects = [
        EffectSpec(
            primitive=EffectPrimitive.obtain_credential,
            params={"credential_id": "cred.secret"},
        )
    ]
    delta = composer.compose(base_state, effects, actor_id="actor_attacker")
    new_state = apply_delta_to_state(base_state, delta)
    assert "cred.secret" in new_state.actors["actor_attacker"].known_credential_ids


def test_discover_asset_and_service(base_state):
    composer = EffectComposer()
    effects = [
        EffectSpec(
            primitive=EffectPrimitive.discover_asset,
            params={"asset_id": "host.db01", "asset_type": "host"},
        ),
        EffectSpec(
            primitive=EffectPrimitive.discover_service,
            params={"service_id": "svc.db01.postgres", "host_id": "host.db01"},
        ),
    ]
    delta = composer.compose(base_state, effects, actor_id="actor_attacker")
    new_state = apply_delta_to_state(base_state, delta)
    attacker = new_state.actors["actor_attacker"]
    assert "host.db01" in attacker.known_host_ids
    assert "host.db01" in attacker.enumerated_host_ids
    assert "svc.db01.postgres" in attacker.known_service_ids


def test_pivot_network(base_state):
    composer = EffectComposer()
    effects = [
        EffectSpec(
            primitive=EffectPrimitive.pivot_network,
            params={"network_id": "net.internal"},
        )
    ]
    delta = composer.compose(base_state, effects, actor_id="actor_attacker")
    new_state = apply_delta_to_state(base_state, delta)
    assert "net.internal" in new_state.actors["actor_attacker"].reachable_networks


def test_read_file_and_data_asset(base_state):
    composer = EffectComposer()
    effects = [
        EffectSpec(
            primitive=EffectPrimitive.read_file,
            params={"file_id": "file.env"},
        ),
        EffectSpec(
            primitive=EffectPrimitive.read_data_asset,
            params={"asset_id": "asset.pii"},
        ),
    ]
    delta = composer.compose(base_state, effects, actor_id="actor_attacker")
    new_state = apply_delta_to_state(base_state, delta)
    attacker = new_state.actors["actor_attacker"]
    assert "file.env" in attacker.accessed_files
    assert "asset.pii" in attacker.accessed_assets


def test_create_persistence(base_state):
    composer = EffectComposer()
    effects = [
        EffectSpec(
            primitive=EffectPrimitive.create_persistence,
            params={"host_id": "host.web01"},
        )
    ]
    delta = composer.compose(base_state, effects, actor_id="actor_attacker")
    new_state = apply_delta_to_state(base_state, delta)
    assert "actor_attacker" in new_state.hosts["host.web01"].persistent_actors


def test_disable_control(base_state):
    composer = EffectComposer()
    effects = [
        EffectSpec(
            primitive=EffectPrimitive.disable_control,
            params={"control_id": "ctrl.waf.web01"},
        )
    ]
    delta = composer.compose(base_state, effects, actor_id="actor_attacker")
    new_state = apply_delta_to_state(base_state, delta)
    assert new_state.controls["ctrl.waf.web01"].is_active is False


def test_achieve_objective(base_state):
    composer = EffectComposer()
    effects = [
        EffectSpec(
            primitive=EffectPrimitive.achieve_objective,
            params={"objective_id": "obj.exfiltrate_pii"},
        )
    ]
    delta = composer.compose(base_state, effects, actor_id="actor_attacker")
    new_state = apply_delta_to_state(base_state, delta)
    assert "obj.exfiltrate_pii" in new_state.achieved_objectives


def test_unknown_primitive_raises_error(base_state):
    composer = EffectComposer()
    # Construct invalid EffectSpec bypassing type checking
    raw_spec = EffectSpec.model_construct(primitive="arbitrary_code_exec", params={})
    with pytest.raises(ValueError, match="Unknown effect primitive"):
        composer.compose(base_state, [raw_spec], actor_id="actor_attacker")
