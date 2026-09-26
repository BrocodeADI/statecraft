import uuid
from typing import Any

from statecraft.model.actors import Session
from statecraft.model.identity import PrivilegeLevel
from statecraft.model.security import EffectPrimitive
from statecraft.model.state import (
    ActorState,
    ControlState,
    EnvironmentState,
    HostState,
    StateDelta,
)


def apply_grant_session(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    host_id = params["host_id"]
    account_id = params.get("account_id")
    priv_level_str = params.get("privilege_level", "user")
    priv_level = PrivilegeLevel(priv_level_str) if isinstance(priv_level_str, str) else priv_level_str

    session_id = params.get("session_id") or f"sess-{host_id}-{account_id or 'default'}"
    session = Session(
        id=session_id,
        host_id=host_id,
        actor_id=actor_id,
        privilege_level=priv_level,
        account_id=account_id,
        created_at_tick=state.tick,
        is_active=True,
    )

    delta = StateDelta.empty()
    delta.added_sessions.append(session)
    return delta


def apply_elevate_privilege(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    session_id = params.get("session_id")
    new_priv_str = params.get("new_privilege_level", "root")
    new_priv = PrivilegeLevel(new_priv_str) if isinstance(new_priv_str, str) else new_priv_str

    # If session_id not given, elevate active session on host
    if not session_id and "host_id" in params:
        for sess in state.sessions.values():
            if sess.actor_id == actor_id and sess.host_id == params["host_id"] and sess.is_active:
                session_id = sess.id
                break

    delta = StateDelta.empty()
    if session_id:
        delta.updated_session_levels[session_id] = new_priv
    return delta


def apply_revoke_session(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    session_id = params.get("session_id")
    delta = StateDelta.empty()
    if session_id:
        delta.removed_session_ids.append(session_id)
    return delta


def apply_obtain_credential(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    cred_id = params["credential_id"]
    actor = state.actors.get(actor_id, ActorState(id=actor_id))

    delta = StateDelta.empty()
    if cred_id not in actor.known_credential_ids:
        updated_actor = actor.model_copy(deep=True)
        updated_actor.known_credential_ids.append(cred_id)
        delta.updated_actor_states[actor_id] = updated_actor
    return delta


def apply_discover_asset(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    asset_id = params.get("asset_id") or params.get("host_id")
    asset_type = params.get("asset_type")

    actor = state.actors.get(actor_id, ActorState(id=actor_id))
    delta = StateDelta.empty()
    updated_actor = actor.model_copy(deep=True)
    changed = False

    if asset_id and (asset_type == "host" or asset_id.startswith("host.")):
        if asset_id not in updated_actor.known_host_ids:
            updated_actor.known_host_ids.append(asset_id)
            changed = True
    elif asset_id:
        if asset_id not in updated_actor.known_data_asset_ids:
            updated_actor.known_data_asset_ids.append(asset_id)
            changed = True

    if changed:
        delta.updated_actor_states[actor_id] = updated_actor
    return delta


def apply_discover_service(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    svc_id = params["service_id"]
    host_id = params.get("host_id")
    actor = state.actors.get(actor_id, ActorState(id=actor_id))

    delta = StateDelta.empty()
    updated_actor = actor.model_copy(deep=True)
    changed = False

    if svc_id not in updated_actor.known_service_ids:
        updated_actor.known_service_ids.append(svc_id)
        changed = True
    if host_id and host_id not in updated_actor.enumerated_host_ids:
        updated_actor.enumerated_host_ids.append(host_id)
        changed = True

    if changed:
        delta.updated_actor_states[actor_id] = updated_actor
    return delta


def apply_pivot_network(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    net_id = params["network_id"]
    actor = state.actors.get(actor_id, ActorState(id=actor_id))

    delta = StateDelta.empty()
    if net_id not in actor.reachable_networks:
        updated_actor = actor.model_copy(deep=True)
        updated_actor.reachable_networks.append(net_id)
        delta.updated_actor_states[actor_id] = updated_actor
    return delta


def apply_read_file(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    file_id = params["file_id"]
    actor = state.actors.get(actor_id, ActorState(id=actor_id))

    delta = StateDelta.empty()
    if file_id not in actor.accessed_files:
        updated_actor = actor.model_copy(deep=True)
        updated_actor.accessed_files.append(file_id)
        delta.updated_actor_states[actor_id] = updated_actor
    return delta


def apply_read_data_asset(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    asset_id = params["asset_id"]
    actor = state.actors.get(actor_id, ActorState(id=actor_id))

    delta = StateDelta.empty()
    if asset_id not in actor.accessed_assets:
        updated_actor = actor.model_copy(deep=True)
        updated_actor.accessed_assets.append(asset_id)
        delta.updated_actor_states[actor_id] = updated_actor
    return delta


def apply_create_persistence(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    host_id = params["host_id"]
    delta = StateDelta.empty()

    if host_id in state.hosts:
        h_state = state.hosts[host_id].model_copy(deep=True)
        if actor_id not in h_state.persistent_actors:
            h_state.persistent_actors.append(actor_id)
            delta.updated_host_states[host_id] = h_state
    return delta


def apply_disable_control(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    control_id = params["control_id"]
    delta = StateDelta.empty()

    if control_id in state.controls:
        c_state = state.controls[control_id].model_copy(deep=True)
        c_state.is_active = False
        delta.updated_control_states[control_id] = c_state
    return delta


def apply_achieve_objective(state: EnvironmentState, actor_id: str, params: dict[str, Any]) -> StateDelta:
    obj_id = params["objective_id"]
    delta = StateDelta.empty()
    if obj_id not in state.achieved_objectives:
        delta.achieved_objectives.append(obj_id)
    return delta


PRIMITIVE_HANDLERS = {
    EffectPrimitive.grant_session: apply_grant_session,
    EffectPrimitive.elevate_privilege: apply_elevate_privilege,
    EffectPrimitive.revoke_session: apply_revoke_session,
    EffectPrimitive.obtain_credential: apply_obtain_credential,
    EffectPrimitive.discover_asset: apply_discover_asset,
    EffectPrimitive.discover_service: apply_discover_service,
    EffectPrimitive.pivot_network: apply_pivot_network,
    EffectPrimitive.read_file: apply_read_file,
    EffectPrimitive.read_data_asset: apply_read_data_asset,
    EffectPrimitive.create_persistence: apply_create_persistence,
    EffectPrimitive.disable_control: apply_disable_control,
    EffectPrimitive.achieve_objective: apply_achieve_objective,
}
