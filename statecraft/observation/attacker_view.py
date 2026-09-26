from pydantic import BaseModel, Field

from statecraft.model.state import EnvironmentState
from statecraft.spec.schema import EnvironmentSpec


class HostObservation(BaseModel):
    id: str
    hostname: str
    ip: str
    os_distro: str | None = None
    is_compromised: bool = False


class ServiceObservation(BaseModel):
    id: str
    host_id: str
    port: int
    protocol: str
    software: str
    banner: str = ""


class SessionObservation(BaseModel):
    id: str
    host_id: str
    privilege_level: str
    account_id: str | None = None
    is_active: bool = True


class AttackerObservation(BaseModel):
    tick: int
    reachable_networks: list[str] = Field(default_factory=list)
    known_hosts: list[HostObservation] = Field(default_factory=list)
    known_services: list[ServiceObservation] = Field(default_factory=list)
    known_credentials: list[str] = Field(default_factory=list)
    active_sessions: list[SessionObservation] = Field(default_factory=list)
    accessed_files: list[str] = Field(default_factory=list)
    accessed_assets: list[str] = Field(default_factory=list)
    achieved_objectives: list[str] = Field(default_factory=list)


class ObservationEngine:
    """Projects ground truth through an actor's discovered knowledge (Fog of War)."""

    @staticmethod
    def attacker_view(
        ground_truth: EnvironmentState,
        spec: EnvironmentSpec,
        actor_id: str = "actor_attacker",
    ) -> AttackerObservation:
        actor = ground_truth.actors.get(actor_id)
        if not actor:
            return AttackerObservation(tick=ground_truth.tick)

        host_map = {h.id: h for h in spec.hosts}
        service_map = {s.id: s for h in spec.hosts for s in h.services}

        # 1. Known hosts
        obs_hosts: list[HostObservation] = []
        for h_id in actor.known_host_ids:
            h = host_map.get(h_id)
            if h:
                is_comp = False
                h_state = ground_truth.hosts.get(h_id)
                if h_state:
                    is_comp = h_state.compromised

                is_enum = h_id in actor.enumerated_host_ids
                obs_hosts.append(
                    HostObservation(
                        id=h.id,
                        hostname=h.hostname,
                        ip=h.ip_address,
                        os_distro=f"{h.os.distro} {h.os.version}" if is_enum else None,
                        is_compromised=is_comp,
                    )
                )

        # 2. Known services
        obs_services: list[ServiceObservation] = []
        for s_id in actor.known_service_ids:
            s = service_map.get(s_id)
            if s:
                obs_services.append(
                    ServiceObservation(
                        id=s.id,
                        host_id=s.host_id,
                        port=s.port,
                        protocol=s.protocol,
                        software=f"{s.software.name} {s.software.version}",
                        banner=s.banner,
                    )
                )

        # 3. Active sessions
        obs_sessions: list[SessionObservation] = []
        for sess in ground_truth.sessions.values():
            if sess.actor_id == actor_id and sess.is_active:
                obs_sessions.append(
                    SessionObservation(
                        id=sess.id,
                        host_id=sess.host_id,
                        privilege_level=sess.privilege_level.value,
                        account_id=sess.account_id,
                        is_active=sess.is_active,
                    )
                )

        return AttackerObservation(
            tick=ground_truth.tick,
            reachable_networks=list(actor.reachable_networks),
            known_hosts=obs_hosts,
            known_services=obs_services,
            known_credentials=list(actor.known_credential_ids),
            active_sessions=obs_sessions,
            accessed_files=list(actor.accessed_files),
            accessed_assets=list(actor.accessed_assets),
            achieved_objectives=list(ground_truth.achieved_objectives),
        )
