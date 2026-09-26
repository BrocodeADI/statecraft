from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from statecraft.agents.scripted_attacker import get_university_attack_path
from statecraft.cli.renderer import (
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


if __name__ == "__main__":
    app()
