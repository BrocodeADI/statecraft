"""Tests for Statecraft Presentation Layer: demo orchestration and AI action proposer."""

import pytest
from typer.testing import CliRunner

from statecraft.ai.pipeline import AIEngineSession
from statecraft.ai.provider import RuleBasedNLPProvider
from statecraft.cli.main import app
from statecraft.model.actions import ActionVerb, ProposedAction
from statecraft.spec.loader import load_spec

runner = CliRunner()


def test_demo_command_execution():
    """Verify statecraft demo runs the real engine and succeeds."""
    result = runner.invoke(app, ["demo", "--scenario", "scenarios/university-network.yaml"])
    assert result.exit_code == 0
    assert "STATECRAFT" in result.stdout
    assert "[1/5] ENVIRONMENT" in result.stdout
    assert "[2/5] VALIDATION" in result.stdout
    assert "[3/5] SIMULATION" in result.stdout
    assert "[4/5] PERSISTENCE" in result.stdout
    assert "[5/5] REPLAY" in result.stdout
    assert "Final state matches" in result.stdout
    assert "ARCHITECTURE GUARANTEE" in result.stdout
    assert "STATECRAFT DEMO COMPLETE" in result.stdout


def test_demo_command_invalid_scenario():
    """Verify statecraft demo fails cleanly on non-existent scenario."""
    result = runner.invoke(app, ["demo", "--scenario", "scenarios/non_existent.yaml"])
    assert result.exit_code == 1
    assert "Error: File not found" in result.stdout


def test_ai_provider_proposes_valid_action():
    """Verify natural language translates into typed ProposedAction."""
    spec = load_spec("scenarios/university-network.yaml")
    session = AIEngineSession(spec)

    # 1. Valid proposal: Find entry point -> scan net.dmz
    turn = session.process_message("Find an entry point into the university network")
    assert turn.proposed_action is not None
    assert turn.proposed_action.verb == ActionVerb.scan
    assert turn.proposed_action.target_id == "net.dmz"
    assert turn.engine_result is not None
    assert turn.engine_result.success is True
    assert turn.rejected is False


def test_ai_provider_invalid_action_rejected_by_engine():
    """Verify invalid action proposal is rejected by authoritative engine without mutating state."""
    spec = load_spec("scenarios/university-network.yaml")
    session = AIEngineSession(spec)

    # State initially has 0 ticks and no sessions
    initial_tick = session.current_state.tick
    assert len(session.current_state.sessions) == 0

    # User prompts to access data without prerequisite session
    turn = session.process_message("Access student PII")
    assert turn.proposed_action is not None
    assert turn.proposed_action.verb == ActionVerb.access_data
    assert turn.engine_result is not None
    assert turn.engine_result.success is False
    assert turn.rejected is True
    assert "No active session on target host" in turn.narrative_response

    # Verify authoritative state was NOT mutated to advance tick or achieve objective
    assert session.current_state.tick == initial_tick
    assert len(session.current_state.sessions) == 0
    assert "obj.exfiltrate_pii" not in session.current_state.achieved_objectives


def test_ai_unrecognized_prompt():
    """Verify unrecognizable commands do not generate an action and do not touch engine."""
    spec = load_spec("scenarios/university-network.yaml")
    session = AIEngineSession(spec)
    initial_tick = session.current_state.tick

    turn = session.process_message("deploy a web server on AWS")
    assert turn.proposed_action is None
    assert turn.engine_result is None
    assert turn.rejected is True
    # Engine tick must remain unchanged
    assert session.current_state.tick == initial_tick


def test_ai_cli_prompt_mode():
    """Verify statecraft ai --prompt CLI execution."""
    result = runner.invoke(app, ["ai", "--prompt", "scan dmz"])
    assert result.exit_code == 0
    assert "STATECRAFT AI INTERFACE" in result.stdout
    assert "ProposedAction: verb=scan, target=net.dmz" in result.stdout
    assert "Discovered host: WEB01" in result.stdout
