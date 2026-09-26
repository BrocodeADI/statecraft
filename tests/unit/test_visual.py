"""Tests for the visual presentation adapter (statecraft.visual.adapter).

These tests verify that real engine data is correctly converted into
visualization-ready JSON. No engine logic is tested here -- only the
adapter transformation layer.
"""

import json
from pathlib import Path

import pytest

from statecraft.agents.scripted_attacker import get_university_attack_path
from statecraft.engine.simulator import Simulator
from statecraft.model.actions import ActionVerb, ProposedAction
from statecraft.model.events import Event, EventType, Severity, TargetType
from statecraft.spec.loader import load_spec
from statecraft.validator.pipeline import validate_environment
from statecraft.visual.adapter import (
    action_to_viz,
    build_run_payload,
    event_to_viz,
    spec_to_topology,
    _event_category,
)


SCENARIO_PATH = Path("scenarios/university-network.yaml")


@pytest.fixture
def spec():
    return load_spec(SCENARIO_PATH)


@pytest.fixture
def run_result(spec):
    """Execute a full simulation and return (spec, tick_data, events_total)."""
    sim = Simulator(spec, seed=spec.seed)
    actions = get_university_attack_path()
    tick_data = []
    for tick_num, action in enumerate(actions, 1):
        res = sim.step(action)
        tick_data.append({
            "action": action_to_viz(tick_num, action),
            "events": [event_to_viz(e) for e in res.events],
            "success": res.success,
        })
    return spec, tick_data, len(sim._recorded_events)


class TestSpecToTopology:
    def test_contains_required_keys(self, spec):
        topo = spec_to_topology(spec)
        assert "networks" in topo
        assert "hosts" in topo
        assert "controls" in topo
        assert "assets" in topo
        assert "objectives" in topo
        assert "attacker_start" in topo
        assert "name" in topo

    def test_network_count(self, spec):
        topo = spec_to_topology(spec)
        assert len(topo["networks"]) == 3  # external, dmz, internal

    def test_host_count(self, spec):
        topo = spec_to_topology(spec)
        assert len(topo["hosts"]) == 4  # web01, db01, dc01, client01

    def test_host_has_services(self, spec):
        topo = spec_to_topology(spec)
        web01 = next(h for h in topo["hosts"] if h["hostname"] == "WEB01")
        assert len(web01["services"]) == 2  # nginx + StudentPortal

    def test_controls_mapped(self, spec):
        topo = spec_to_topology(spec)
        assert len(topo["controls"]) == 3  # waf, ids, edr

    def test_json_serializable(self, spec):
        topo = spec_to_topology(spec)
        # Must not raise
        result = json.dumps(topo)
        assert isinstance(result, str)


class TestActionToViz:
    def test_scan_action(self):
        action = ProposedAction(
            actor_id="actor_attacker",
            verb=ActionVerb.scan,
            target_id="net.dmz",
        )
        viz = action_to_viz(1, action)
        assert viz["tick"] == 1
        assert viz["verb"] == "scan"
        assert viz["target_id"] == "net.dmz"
        assert viz["actor_id"] == "actor_attacker"

    def test_exploit_with_params(self):
        action = ProposedAction(
            actor_id="actor_attacker",
            verb=ActionVerb.exploit,
            target_id="svc.web01.app",
            parameters={"vuln_id": "vuln.sqli-studentportal"},
        )
        viz = action_to_viz(3, action)
        assert viz["verb"] == "exploit"
        assert viz["parameters"]["vuln_id"] == "vuln.sqli-studentportal"

    def test_json_serializable(self):
        action = ProposedAction(
            actor_id="actor_attacker",
            verb=ActionVerb.scan,
            target_id="net.dmz",
        )
        viz = action_to_viz(1, action)
        result = json.dumps(viz)
        assert isinstance(result, str)


class TestEventToViz:
    def test_host_discovered_event(self):
        event = Event(
            id="evt-001",
            tick=1,
            type=EventType.host_discovered,
            target_id="host.web01",
            target_type=TargetType.host,
            success=True,
            metadata={"hostname": "WEB01", "ip": "10.0.1.10"},
        )
        viz = event_to_viz(event)
        assert viz["type"] == "host_discovered"
        assert viz["category"] == "discovery"
        assert viz["metadata"]["hostname"] == "WEB01"

    def test_detection_event(self):
        event = Event(
            id="evt-det-001",
            tick=3,
            type=EventType.detection_triggered,
            target_id="ctrl.waf.web01",
            target_type=TargetType.host,
            success=True,
            severity=Severity.high,
            metadata={"control_id": "ctrl.waf.web01"},
        )
        viz = event_to_viz(event)
        assert viz["category"] == "defense"
        assert viz["severity"] == "high"

    def test_objective_event(self):
        event = Event(
            id="evt-obj-001",
            tick=7,
            type=EventType.objective_achieved,
            target_id="asset.student_pii",
            target_type=TargetType.asset,
            success=True,
            metadata={"label": "Access student PII database"},
        )
        viz = event_to_viz(event)
        assert viz["category"] == "objective"

    def test_json_serializable(self):
        event = Event(
            id="evt-001",
            tick=1,
            type=EventType.host_discovered,
            target_id="host.web01",
            target_type=TargetType.host,
            success=True,
        )
        viz = event_to_viz(event)
        result = json.dumps(viz)
        assert isinstance(result, str)


class TestEventCategory:
    @pytest.mark.parametrize("event_type,expected", [
        (EventType.scan_attempt, "discovery"),
        (EventType.host_discovered, "discovery"),
        (EventType.service_discovered, "discovery"),
        (EventType.authentication_success, "auth"),
        (EventType.authentication_failure, "auth"),
        (EventType.exploit_success, "exploit"),
        (EventType.lateral_movement, "movement"),
        (EventType.credential_acquired, "movement"),
        (EventType.data_access, "data"),
        (EventType.detection_triggered, "defense"),
        (EventType.objective_achieved, "objective"),
        (EventType.privilege_change, "other"),
    ])
    def test_category_mapping(self, event_type, expected):
        assert _event_category(event_type) == expected


class TestBuildRunPayload:
    def test_payload_structure(self, run_result):
        spec, tick_data, _ = run_result
        payload_str = build_run_payload(spec, tick_data, True, {"actions": 7})
        payload = json.loads(payload_str)
        assert "topology" in payload
        assert "ticks" in payload
        assert "replay" in payload

    def test_payload_tick_count(self, run_result):
        spec, tick_data, _ = run_result
        payload_str = build_run_payload(spec, tick_data, True)
        payload = json.loads(payload_str)
        assert len(payload["ticks"]) == 7

    def test_replay_match_flag(self, run_result):
        spec, tick_data, _ = run_result
        payload_str = build_run_payload(spec, tick_data, True)
        payload = json.loads(payload_str)
        assert payload["replay"]["match"] is True

    def test_replay_fail_flag(self, run_result):
        spec, tick_data, _ = run_result
        payload_str = build_run_payload(spec, tick_data, False)
        payload = json.loads(payload_str)
        assert payload["replay"]["match"] is False

    def test_events_from_real_engine(self, run_result):
        """Verify all events in the payload originate from the real engine."""
        spec, tick_data, total_events = run_result
        payload_str = build_run_payload(spec, tick_data, True)
        payload = json.loads(payload_str)
        payload_events = sum(len(t["events"]) for t in payload["ticks"])
        assert payload_events == total_events


    def test_payload_fast_mode(self, run_result):
        spec, tick_data, _ = run_result
        payload_str = build_run_payload(spec, tick_data, True, fast=True)
        payload = json.loads(payload_str)
        assert payload["fast"] is True

    def test_payload_ai_demo(self, run_result):
        spec, tick_data, _ = run_result
        ai_demo = {
            "steps": [
                {"prompt": "Scan DMZ", "engine_status": "accepted"},
                {"prompt": "Access PII", "engine_status": "rejected"},
            ]
        }
        payload_str = build_run_payload(spec, tick_data, True, ai_demo=ai_demo)
        payload = json.loads(payload_str)
        assert payload["ai_demo"] is not None
        assert len(payload["ai_demo"]["steps"]) == 2


class TestDashboardHTML:
    def test_html_exists(self):
        html_path = Path("statecraft/visual/static/index.html")
        assert html_path.is_file()

    def test_html_has_injection_point(self):
        html_path = Path("statecraft/visual/static/index.html")
        content = html_path.read_text(encoding="utf-8")
        assert "<!-- PAYLOAD_INJECTION_POINT -->" in content


class TestPresentationFlowHTML:
    @pytest.fixture
    def html_content(self):
        return Path("statecraft/visual/static/index.html").read_text(encoding="utf-8")

    def test_has_ready_overlay(self, html_content):
        assert 'id="phase-overlay"' in html_content
        assert 'class="visible"' in html_content
        assert 'GUIDED DEMONSTRATION' in html_content
        assert 'id="btn-start-demo"' in html_content
        assert 'BEGIN MISSION' in html_content

    def test_has_scenario_card_metadata(self, html_content):
        assert 'Simulated Orbital Research Station' in html_content
        assert 'Simulated University Network' in html_content
        assert 'id="ready-scenario-meta"' in html_content

    def test_has_voice_toggle_button(self, html_content):
        assert 'id="btn-voice"' in html_content
        assert 'Voice: ON' in html_content

    def test_has_narration_subtitle_bar(self, html_content):
        assert 'id="narration-bar"' in html_content
        assert 'id="narration-text"' in html_content

    def test_has_ai_section(self, html_content):
        assert 'id="ai-section"' in html_content
        assert 'id="ai-container"' in html_content

    def test_has_web_speech_api_implementation(self, html_content):
        assert 'speechSynthesis' in html_content
        assert 'SpeechSynthesisUtterance' in html_content
        assert 'class Narrator' in html_content

    def test_exact_narration_texts_present(self, html_content):
        # Intro
        assert "Welcome to Statecraft Orbital, a deterministic cybersecurity simulation presented as a controlled orbital station." in html_content
        # Environment
        assert "The orbital station comprises open space, docking sector, and restricted core modules" in html_content
        # Validation
        assert "Before execution begins, Statecraft validates the station environment" in html_content
        # Tick 1
        assert "The attacker begins outside the station with no knowledge of the internal environment and scans the DMZ." in html_content
        # Tick 2
        assert "The web module is now enumerated and the station's student portal is identified." in html_content
        # Tick 3
        assert "The attacker now exploits the simulated student portal using SQL injection" in html_content
        assert "The station's web security control simultaneously generates a detection event." in html_content
        # Tick 4
        assert "Using the resulting access, the attacker pivots through the compromised web module into the restricted internal core." in html_content
        # Tick 5
        assert "The internal network is scanned and additional station systems become visible." in html_content
        # Tick 6
        assert "The attacker authenticates to the simulated PostgreSQL service and establishes a database session." in html_content
        # Tick 7
        assert "The protected student PII asset has now been accessed. The predefined simulation objective has been achieved." in html_content
        # Persistence
        assert "Statecraft persists the execution so that the complete run can be reproduced." in html_content
        # Replay
        assert "Statecraft now replays the mission using the same deterministic simulation." in html_content
        # Replay Verified
        assert "The replay matches the original execution." in html_content
        # Final Architecture
        assert "The core Statecraft architecture is unchanged. A user or AI may propose an action, but only the deterministic Statecraft engine can validate and execute it." in html_content
        # AI Proposer
        assert "Statecraft can optionally accept an action proposed by an AI layer" in html_content
        assert "AI proposes. Statecraft decides." in html_content

    def test_orbital_station_elements_and_technical_identifiers(self, html_content):
        """Verify Orbital space-station visual metaphor and technical identifiers."""
        # Orbital sectors & elements
        assert "OPEN SPACE" in html_content
        assert "DOCKING" in html_content
        assert "RESTRICTED STATION CORE" in html_content
        assert "SECURE DATA VAULT" in html_content
        assert "SECURITY CHECKPOINT" in html_content
        assert "intruder-craft" in html_content
        # Technical identifiers preserved
        assert "WEB01" in html_content
        assert "DB01" in html_content
        assert "DC01" in html_content
        assert "FACULTY-PC-01" in html_content
        assert "WAF" in html_content
        assert "Student PII" in html_content
        assert "ENGINE IS AUTHORITATIVE" in html_content

