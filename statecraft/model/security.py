from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


class VulnClass(str, Enum):
    rce = "rce"
    sqli = "sqli"
    xxe = "xxe"
    auth_bypass = "auth_bypass"
    misconfig = "misconfig"
    weak_cred = "weak_cred"
    priv_esc = "priv_esc"
    info_disclosure = "info_disclosure"
    path_traversal = "path_traversal"


class CapabilityType(str, Enum):
    network_scan = "network_scan"
    service_enum = "service_enum"
    credential_use = "credential_use"
    code_execution = "code_execution"
    privilege_escalation = "privilege_escalation"
    lateral_movement = "lateral_movement"
    data_access = "data_access"
    persistence = "persistence"
    control_disable = "control_disable"


class EffectPrimitive(str, Enum):
    grant_session = "grant_session"
    elevate_privilege = "elevate_privilege"
    revoke_session = "revoke_session"
    obtain_credential = "obtain_credential"
    discover_asset = "discover_asset"
    discover_service = "discover_service"
    pivot_network = "pivot_network"
    read_file = "read_file"
    read_data_asset = "read_data_asset"
    create_persistence = "create_persistence"
    disable_control = "disable_control"
    achieve_objective = "achieve_objective"


class Precondition(BaseModel):
    type: str
    service_id: str | None = None
    host_id: str | None = None
    network_id: str | None = None
    credential_id: str | None = None


class EffectSpec(BaseModel):
    primitive: EffectPrimitive
    params: dict = Field(default_factory=dict)
    condition: str | None = None


class Vulnerability(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    cve: str | None = None
    label: str
    vuln_class: VulnClass = Field(alias="class")
    preconditions: list[Precondition] = Field(default_factory=list)
    required_capabilities: list[CapabilityType] = Field(default_factory=list)
    effects: list[EffectSpec] = Field(default_factory=list)
    detection_probability: float = 0.0
    reliability: float = 1.0


class TrustType(str, Enum):
    network_reachable = "network_reachable"
    credential_reuse = "credential_reuse"
    trust_delegation = "trust_delegation"
    ssh_trust = "ssh_trust"
    service_account_access = "service_account_access"


class TrustRelationship(BaseModel):
    id: str
    from_id: str
    to_id: str
    type: TrustType
    conditions: list[str] = Field(default_factory=list)
    is_directional: bool = True


class RuleAction(str, Enum):
    allow = "allow"
    deny = "deny"


class FirewallRule(BaseModel):
    id: str
    priority: int
    from_network: str | None = None
    from_host: str | None = None
    to_network: str | None = None
    to_host: str | None = None
    port: int | None = None
    protocol: str | None = None
    action: RuleAction = RuleAction.allow


class ControlType(str, Enum):
    edr = "edr"
    ids = "ids"
    nids = "nids"
    siem_rule = "siem_rule"
    dlp = "dlp"
    waf = "waf"


class DetectionRule(BaseModel):
    action_verb: str | None = None
    target_host: str | None = None
    vuln_class: VulnClass | None = None
    condition: str | None = None
    detection_probability_override: float | None = None


class SecurityControl(BaseModel):
    id: str
    type: ControlType
    host_id: str | None = None
    network_id: str | None = None
    detects: list[DetectionRule] = Field(default_factory=list)
    is_active: bool = True
    alert_delay_ticks: int = 0
