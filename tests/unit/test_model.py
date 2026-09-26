import pytest
from pydantic import ValidationError

from statecraft.model.actions import ActionVerb, FailureReason, ProposedAction
from statecraft.model.actors import Actor, ActorRole, AgentType, CapabilityType, Session
from statecraft.model.assets import DataAsset, File, Sensitivity
from statecraft.model.environment import Host, Network, NetworkZone, OSProfile, Service, SoftwareProfile
from statecraft.model.events import Event, EventType, Severity, TargetType
from statecraft.model.identity import Account, Credential, CredentialType, Group, Identity, PrivilegeLevel
from statecraft.model.objectives import Objective, ObjectiveType
from statecraft.model.security import FirewallRule, RuleAction, SecurityControl, VulnClass, Vulnerability


def test_credential_round_trip():
    cred = Credential(
        id="cred.test",
        type=CredentialType.password,
        value_hash="sha256:12345",
        is_weak=True,
        reuse_scope=["acct.1"],
    )
    json_data = cred.model_dump_json()
    loaded = Credential.model_validate_json(json_data)
    assert loaded.id == cred.id
    assert loaded.type == CredentialType.password
    assert loaded.is_weak is True
    assert loaded.reuse_scope == ["acct.1"]


def test_host_and_service_model():
    service = Service(
        id="svc.web",
        host_id="host.web",
        port=80,
        protocol="tcp",
        software=SoftwareProfile(name="nginx", version="1.18"),
        banner="nginx 1.18",
    )
    host = Host(
        id="host.web",
        hostname="WEB01",
        network_id="net.dmz",
        ip_address="10.0.1.10",
        os=OSProfile(family="linux", distro="ubuntu", version="22.04"),
        services=[service],
    )
    dumped = host.model_dump_json()
    loaded = Host.model_validate_json(dumped)
    assert loaded.id == "host.web"
    assert len(loaded.services) == 1
    assert loaded.services[0].port == 80


def test_vulnerability_alias_class():
    vuln_data = {
        "id": "vuln.sqli",
        "label": "SQL Injection",
        "class": "sqli",
        "reliability": 1.0,
        "detection_probability": 0.5,
    }
    vuln = Vulnerability.model_validate(vuln_data)
    assert vuln.vuln_class == VulnClass.sqli
    assert vuln.reliability == 1.0


def test_event_serialization():
    event = Event(
        id="evt-1",
        tick=3,
        type=EventType.exploit_success,
        actor_id="actor_1",
        target_id="svc.web",
        target_type=TargetType.service,
        success=True,
        severity=Severity.high,
    )
    data = event.model_dump_json()
    loaded = Event.model_validate_json(data)
    assert loaded.id == "evt-1"
    assert loaded.type == EventType.exploit_success
    assert loaded.target_type == TargetType.service


def test_objective_model():
    obj = Objective(
        id="obj.pii",
        label="Exfiltrate PII",
        type=ObjectiveType.access_data_asset,
        target_id="asset.student_pii",
    )
    assert obj.is_achieved is False
    assert obj.achieved_at_tick is None


def test_proposed_action_validation():
    action = ProposedAction(
        actor_id="attacker",
        verb=ActionVerb.scan,
        target_id="net.dmz",
    )
    assert action.verb == ActionVerb.scan
    assert action.parameters == {}


def test_invalid_privilege_level():
    with pytest.raises(ValidationError):
        Account(
            id="acct.1",
            host_id="host.1",
            username="admin",
            privilege_level="superadmin",  # Invalid enum value
        )
