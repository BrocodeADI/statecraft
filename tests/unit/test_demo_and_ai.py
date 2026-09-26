"""Tests for Statecraft Presentation Layer: story-driven demo orchestration and AI action proposer."""

import pytest
from typer.testing import CliRunner

from statecraft.ai.pipeline import AIEngineSession
from statecraft.ai.provider import RuleBasedNLPProvider
from statecraft.cli.main import app
from statecraft.model.actions import ActionVerb, ProposedAction
from statecraft.spec.loader import load_spec

runner = CliRunner()


def test_demo_command_execution_fast():
    """Verify statecraft demo --fast runs the real engine and succeeds."""
    result = runner.invoke(app, ["demo", "--scenario", "scenarios/university-network.yaml", "--fast"])
    assert result.exit_code == 0
    assert "STATECRAFT" in result.stdout
    assert "1. ENVIRONMENT SPECIFICATION" in result.stdout
    assert "2. ENVIRONMENT VALIDATION" in result.stdout
    assert "3. ATTACK SIMULATION" in result.stdout
    assert "4. EXECUTION PERSISTENCE" in result.stdout
    assert "5. DETERMINISTIC REPLAY" in result.stdout
    assert "Final state matches bit-for-bit" in result.stdout
    assert "CORE GUARANTEE" in result.stdout
    assert "STATECRAFT RESULT" in result.stdout
    assert "Only the Statecraft engine is authoritative." in result.stdout


def test_demo_command_with_ai():
    """Verify statecraft demo --fast --ai runs demo and includes the AI architectural section."""
    result = runner.invoke(app, ["demo", "--scenario", "scenarios/university-network.yaml", "--fast", "--ai"])
    assert result.exit_code == 0
    assert "6. AI ACTION PROPOSER (ARCHITECTURAL DEMO)" in result.stdout
    assert "AI PROPOSAL: scan(net.dmz)" in result.stdout
    assert "ENGINE:      Accepted" in result.stdout
    assert "AI PROPOSAL: access_data(asset.student_pii)" in result.stdout
    assert "ENGINE:      Rejected -- No active session on target host" in result.stdout
    assert "The AI is an unprivileged Action Proposer." in result.stdout


def test_demo_command_invalid_scenario_file():
    """Verify statecraft demo fails cleanly on non-existent scenario."""
    result = runner.invoke(app, ["demo", "--scenario", "scenarios/non_existent.yaml", "--fast"])
    assert result.exit_code == 1
    assert "Scenario file not found" in result.stdout


def test_demo_command_validation_failure():
    """Verify statecraft demo halts cleanly if an invalid scenario is supplied."""
    result = runner.invoke(app, ["demo", "--scenario", "tests/fixtures/broken_envs/01_schema_error.yaml", "--fast"])
    assert result.exit_code == 1


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
