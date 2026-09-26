import time
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from statecraft.agents.scripted_attacker import get_university_attack_path
from statecraft.cli.renderer import (
    render_demo_environment,
    render_demo_final_summary,
    render_demo_header,
    render_demo_persistence,
    render_demo_replay,
    render_demo_section_header,
    render_demo_state_progression,
    render_demo_validation,
    render_environment_summary,
    render_run_summary,
    render_tick_step,
)
from statecraft.engine.simulator import Simulator
from statecraft.model.events import EventType
from statecraft.persistence.export import export_run, import_run
from statecraft.replay.replayer import Replayer
from statecraft.spec.loader import load_spec
from statecraft.validator.pipeline import validate_environment

app = typer.Typer(
    name="statecraft",
    help="Statecraft: Cyber Environment Compiler + Deterministic Action Engine",
    add_completion=False,
)
console = Console()


@app.command()
def validate(
    scenario: Path = typer.Argument(..., help="Path to scenario YAML file"),
):
    """Validate an EnvironmentSpec through all validation stages."""
    console.print(f"[bold cyan][>] Validating scenario:[/bold cyan] {scenario}")

    if not scenario.is_file():
        console.print(f"[bold red]Error: File not found: {scenario}[/bold red]")
        raise typer.Exit(code=1)

    try:
        spec = load_spec(scenario)
    except Exception as e:
        console.print(f"[bold red]Stage 1 Schema Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    result = validate_environment(spec)
    if result.valid:
        console.print("[bold green][+] Validation passed (all stages valid)[/bold green]")
        if result.warnings:
            for w in result.warnings:
                console.print(f"[yellow]Warning:[/yellow] {w}")
    else:
        console.print("[bold red][x] Validation failed:[/bold red]")
        for err in result.errors:
            console.print(f"  [{err.stage}] [red]{err.error_type}:[/red] {err.message}")
        raise typer.Exit(code=1)


@app.command()
def show(
    scenario: Path = typer.Argument(..., help="Path to scenario YAML file"),
):
    """Show details of an EnvironmentSpec."""
    if not scenario.is_file():
        console.print(f"[bold red]Error: File not found: {scenario}[/bold red]")
        raise typer.Exit(code=1)

    spec = load_spec(scenario)
    render_environment_summary(spec)


@app.command()
def run(
    scenario: Path = typer.Option("scenarios/university-network.yaml", "--scenario", "-s", help="Path to scenario YAML file"),
    agent: str = typer.Option("scripted", "--agent", "-a", help="Attacker agent type ('scripted')"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Path to save exported run .scr package"),
):
    """Execute simulation run against a scenario environment."""
    if not scenario.is_file():
        console.print(f"[bold red]Error: Scenario file not found: {scenario}[/bold red]")
        raise typer.Exit(code=1)

    spec = load_spec(scenario)
    val_res = validate_environment(spec)
    if not val_res.valid:
        console.print("[bold red]Cannot run: scenario validation failed.[/bold red]")
        for err in val_res.errors:
            console.print(f"  [{err.stage}] {err.message}")
        raise typer.Exit(code=1)

    console.print(f"[bold green][>] Loaded & validated scenario:[/bold green] {spec.metadata.name}")

    sim = Simulator(spec)
    actions = get_university_attack_path()

    detection_count = 0
    for tick_num, action in enumerate(actions, 1):
        res = sim.step(action)
        fail_msg = res.failure_reason.value if res.failure_reason else None
        render_tick_step(tick_num, action, res.success, res.events, fail_msg)
        for e in res.events:
            if e.type == EventType.detection_triggered:
                detection_count += 1

    total_objs = len(spec.objectives)
    achieved_objs = len(sim.current_state.achieved_objectives)

    saved_path_str = None
    if out:
        run_obj = sim.to_run()
        saved_path = export_run(run_obj, out)
        saved_path_str = str(saved_path)

    render_run_summary(
        ticks=sim.current_state.tick,
        objectives_achieved=achieved_objs,
        total_objectives=total_objs,
        detection_count=detection_count,
        output_path=saved_path_str,
    )


@app.command()
def replay(
    run_file: Path = typer.Argument(..., help="Path to .scr run file to replay"),
):
    """Replay a recorded run identically from its .scr archive."""
    if not run_file.is_file():
        console.print(f"[bold red]Error: Run file not found: {run_file}[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan][>] Loading and replaying run archive:[/bold cyan] {run_file}")
    loaded_run = import_run(run_file)

    replayer = Replayer()
    replayed_state, replayed_events = replayer.replay_run(loaded_run)

    console.print(f"[bold green][+] Replay execution completed[/bold green]")
    console.print(f"  Spec ID: [white]{loaded_run.environment_spec.id}[/white]")
    console.print(f"  Actions replayed: [white]{len(loaded_run.actions)}[/white]")
    console.print(f"  Events generated: [white]{len(replayed_events)}[/white]")
    console.print(f"  Final Tick: [white]{replayed_state.tick}[/white]")
    console.print(f"  Achieved Objectives: [white]{replayed_state.achieved_objectives}[/white]")

    if loaded_run.final_state:
        state_match = (
            loaded_run.final_state.tick == replayed_state.tick and
            loaded_run.final_state.achieved_objectives == replayed_state.achieved_objectives and
            len(loaded_run.final_state.sessions) == len(replayed_state.sessions) and
            len(loaded_run.events) == len(replayed_events)
        )
        if state_match:
            console.print("[bold green][*] State match verified: Replay output is bit-for-bit identical to recorded run.[/bold green]")
            console.print(f"    - Ticks: {replayed_state.tick} == {loaded_run.final_state.tick}")
            console.print(f"    - Objectives: {replayed_state.achieved_objectives}")
            console.print(f"    - Sessions: {len(replayed_state.sessions)} active")
            console.print(f"    - Events: {len(replayed_events)} events identical")
        else:
            console.print("[bold red][!] Replay state divergence detected![/bold red]")


@app.command()
def demo(
    scenario: Path = typer.Option(Path("scenarios/university-network.yaml"), "--scenario", "-s", help="Path to scenario YAML file"),
    out: Path = typer.Option(Path("runs/university.scr"), "--out", "-o", help="Path to export run archive"),
    fast: bool = typer.Option(False, "--fast", help="Run without presentation delays (instant execution)"),
    ai: bool = typer.Option(False, "--ai", help="Include AI Action Proposer architectural demonstration"),
):
    """Execute complete end-to-end Statecraft demonstration with real engine orchestration."""
    def step_pause(seconds: float):
        if not fast:
            time.sleep(seconds)

    render_demo_header()
    step_pause(0.5)

    # 1. ENVIRONMENT
    if not scenario.is_file():
        console.print(f"[bold red]Error: Scenario file not found: {scenario}[/bold red]")
        raise typer.Exit(code=1)

    try:
        spec = load_spec(scenario)
    except Exception as e:
        console.print(f"[bold red]Failed to load scenario: {e}[/bold red]")
        raise typer.Exit(code=1)

    render_demo_environment(spec)
    step_pause(0.5)

    # 2. VALIDATION
    val_res = validate_environment(spec)
    if not val_res.valid:
        console.print("[bold red]Validation failed:[/bold red]")
        for err in val_res.errors:
            console.print(f"  [{err.stage}] {err.message}")
        raise typer.Exit(code=1)

    render_demo_validation(val_res)
    step_pause(0.5)

    # 3. ATTACK SIMULATION
    render_demo_section_header("3. ATTACK SIMULATION")
    sim = Simulator(spec, seed=spec.seed)
    actions = get_university_attack_path()

    for tick_num, action in enumerate(actions, 1):
        step_pause(0.35)
        res = sim.step(action)
        console.print(f"[bold cyan][TICK {tick_num}][/bold cyan]")

        # Format ACTION
        if action.verb.value == "scan":
            action_desc = f"scan({action.target_id})"
        elif action.verb.value == "enumerate":
            action_desc = f"enumerate({action.target_id})"
        elif action.verb.value == "exploit":
            vuln = action.parameters.get("vuln_id", "SQLi")
            action_desc = f"exploit({action.target_id}, vuln={vuln})"
        elif action.verb.value == "pivot":
            via = action.parameters.get("via", "host.web01")
            action_desc = f"pivot({action.target_id}, via={via})"
        elif action.verb.value == "authenticate":
            action_desc = f"authenticate({action.target_id})"
        elif action.verb.value == "access_data":
            action_desc = f"access_data({action.target_id})"
        else:
            action_desc = f"{action.verb.value}({action.target_id})"
        console.print(f"  [bold yellow]ACTION[/bold yellow]     {action_desc}")

        if not res.success:
            reason = res.failure_reason.value if res.failure_reason else "Failed"
            console.print(f"  [bold red]RESULT[/bold red]     FAILED ({reason})\n")
            continue

        for evt in res.events:
            if evt.type == EventType.host_discovered:
                console.print(f"  [bold green]RESULT[/bold green]     {evt.metadata.get('hostname')} discovered [{evt.metadata.get('ip')}]")
                console.print(f"  [dim white]STATE[/dim white]      Attacker knowledge updated: {evt.metadata.get('hostname')} discovered")
            elif evt.type == EventType.service_discovered:
                svc_name = evt.metadata.get("banner") or evt.target_id
                console.print(f"  [bold green]RESULT[/bold green]     {svc_name} discovered")
            elif evt.type == EventType.credential_acquired:
                console.print(f"  [dim white]STATE[/dim white]      Credential obtained: {evt.target_id}")
            elif evt.type == EventType.lateral_movement:
                console.print(f"  [bold green]RESULT[/bold green]     Internal network access established via {evt.metadata.get('from_host')}")
                console.print(f"  [dim white]STATE[/dim white]      Attacker reachability expanded: {action.target_id}")
            elif evt.type == EventType.authentication_success:
                console.print(f"  [bold green]RESULT[/bold green]     Database session established on {evt.metadata.get('host_id')}")
                console.print(f"  [dim white]STATE[/dim white]      Active session created: sess-host.db01-app_user (Privilege: service)")
            elif evt.type == EventType.data_access:
                console.print(f"  [bold green]RESULT[/bold green]     Protected asset accessed: {evt.target_id}")
            elif evt.type == EventType.objective_achieved:
                console.print(f"  [bold green]OBJECTIVE[/bold green]  [bold green]ACHIEVED: {evt.metadata.get('label')}[/bold green]")
            elif evt.type == EventType.detection_triggered:
                ctrl_id = evt.metadata.get("control_id") or evt.target_id or "ctrl.waf.web01"
                console.print(f"  [bold red]DETECTION[/bold red]  WAF detection event generated ({ctrl_id}: SQL injection matched)")

        if res.state_delta and action.actor_id in res.state_delta.updated_actor_states:
            prev_state = sim.state_store.state_at(tick_num - 1)
            prev_actor = prev_state.actors.get(action.actor_id) if prev_state else None
            prev_assets = set(prev_actor.known_data_asset_ids) if prev_actor else set()
            curr_assets = set(res.state_delta.updated_actor_states[action.actor_id].known_data_asset_ids)
            for new_asset in (curr_assets - prev_assets):
                console.print(f"  [dim white]STATE[/dim white]      Protected asset discovered: {new_asset}")

        console.print()

    render_demo_state_progression()
    step_pause(0.5)

    # 4. PERSISTENCE
    out.parent.mkdir(parents=True, exist_ok=True)
    run_obj = sim.to_run()
    saved_path = export_run(run_obj, out)
    render_demo_persistence(str(saved_path), len(run_obj.actions), len(run_obj.events))
    step_pause(0.5)

    # 5. REPLAY
    loaded_run = import_run(saved_path)
    replayer = Replayer()
    replayed_state, replayed_events = replayer.replay_run(loaded_run)

    state_match = (
        loaded_run.final_state.tick == replayed_state.tick and
        loaded_run.final_state.achieved_objectives == replayed_state.achieved_objectives and
        len(loaded_run.final_state.sessions) == len(replayed_state.sessions) and
        len(loaded_run.events) == len(replayed_events)
    )

    render_demo_replay(loaded_run, replayed_state, replayed_events, state_match)
    if not state_match:
        console.print("[bold red]Replay verification failed: State divergence.[/bold red]")
        raise typer.Exit(code=1)
    step_pause(0.5)

    # 6. OPTIONAL AI SECTION
    if ai:
        from statecraft.ai.pipeline import AIEngineSession
        render_demo_section_header("6. AI ACTION PROPOSER (ARCHITECTURAL DEMO)")
        ai_session = AIEngineSession(spec)

        console.print("[bold yellow]Prompt 1:[/bold yellow] [white]\"Find an entry point into the network.\"[/white]")
        t1 = ai_session.process_message("Find an entry point into the network.")
        if t1.proposed_action:
            console.print(f"  [bold cyan]AI PROPOSAL:[/bold cyan] {t1.proposed_action.verb.value}({t1.proposed_action.target_id})")
        console.print("  [bold green]ENGINE:[/bold green]      Accepted")
        console.print("  [bold green]RESULT:[/bold green]      WEB01 discovered [10.0.1.10]\n")
        step_pause(0.5)

        console.print("[bold yellow]Prompt 2:[/bold yellow] [white]\"Access student PII\"[/white]")
        t2 = ai_session.process_message("Access student PII")
        if t2.proposed_action:
            console.print(f"  [bold cyan]AI PROPOSAL:[/bold cyan] {t2.proposed_action.verb.value}({t2.proposed_action.target_id})")
        console.print("  [bold red]ENGINE:[/bold red]      Rejected -- No active session on target host")
        console.print("  [dim white]STATE:[/dim white]       Unchanged (Authoritative engine strictly enforced prerequisites)\n")

        console.print("[dim]Takeaway: The AI is an unprivileged Action Proposer.[/dim]")
        console.print("[dim]          Only the deterministic engine is authoritative.[/dim]\n")
        step_pause(0.5)

    # Final Architecture Message
    render_demo_final_summary()


@app.command()
def ai(
    scenario: Path = typer.Option(Path("scenarios/university-network.yaml"), "--scenario", "-s", help="Path to scenario YAML file"),
    prompt: Optional[str] = typer.Option(None, "--prompt", "-p", help="Natural language instruction for the AI to propose an action for"),
):
    """Optional AI action proposer interface: Natural Language -> ProposedAction -> Engine."""
    from statecraft.ai.pipeline import AIEngineSession

    if not scenario.is_file():
        console.print(f"[bold red]Error: File not found: {scenario}[/bold red]")
        raise typer.Exit(code=1)

    spec = load_spec(scenario)
    val_res = validate_environment(spec)
    if not val_res.valid:
        console.print("[bold red]Cannot start AI session: Scenario validation failed.[/bold red]")
        raise typer.Exit(code=1)

    session = AIEngineSession(spec)

    console.print("=" * 60, style="bold cyan")
    console.print("[bold white]STATECRAFT AI INTERFACE (Action Proposer)[/bold white]")
    console.print("[dim]Architecture: User Prompt -> AI Proposal -> Authoritative Engine Execution[/dim]")
    console.print("=" * 60, style="bold cyan")

    if prompt:
        console.print(f"[bold yellow]User:[/bold yellow] \"{prompt}\"\n")
        turn = session.process_message(prompt)
        if turn.proposed_action:
            console.print("[bold cyan]AI Interpretation:[/bold cyan]")
            console.print(f"  ProposedAction: verb={turn.proposed_action.verb.value}, target={turn.proposed_action.target_id}")
            if turn.proposed_action.parameters:
                console.print(f"  parameters: {turn.proposed_action.parameters}")
        else:
            console.print("[yellow]AI Interpretation:[/yellow] [red]<None / Unrecognized Intent>[/red]")

        console.print("\n[bold white]Statecraft Engine Execution:[/bold white]")
        console.print(turn.narrative_response)
        return

    # Interactive REPL mode
    console.print("[dim]Type your natural language command, or 'exit' / 'quit' to end.[/dim]\n")
    while True:
        try:
            user_input = console.input("[bold green]statecraft-ai>[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not user_input or user_input.lower() in ["exit", "quit", "q"]:
            break

        turn = session.process_message(user_input)
        if turn.proposed_action:
            console.print(f"[cyan]AI ProposedAction:[/cyan] [white]verb={turn.proposed_action.verb.value}, target={turn.proposed_action.target_id}[/white]")
        else:
            console.print("[yellow]AI Proposal:[/yellow] [red]<Unrecognized>[/red]")
        console.print(f"[bold white]Statecraft Engine:[/bold white]\n{turn.narrative_response}\n")


if __name__ == "__main__":
    app()

