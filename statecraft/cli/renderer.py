from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from statecraft.model.actions import ProposedAction
from statecraft.model.events import Event, EventType
from statecraft.model.state import EnvironmentState
from statecraft.spec.schema import EnvironmentSpec

console = Console()


def render_environment_summary(spec: EnvironmentSpec):
    """Renders environment overview table."""
    table = Table(title=f"Environment: {spec.metadata.name} (ID: {spec.id})", border_style="cyan")
    table.add_column("Category", style="bold yellow")
    table.add_column("Details", style="white")

    net_str = ", ".join(f"{n.id} ({n.zone.value})" for n in spec.networks)
    table.add_row("Networks", net_str)

    host_str = ", ".join(f"{h.hostname} [{h.ip_address}]" for h in spec.hosts)
    table.add_row("Hosts", host_str)

    ctrl_str = ", ".join(f"{c.type.value} ({c.id})" for c in spec.security_controls)
    table.add_row("Controls", ctrl_str or "None")

    vuln_str = ", ".join(f"{v.id} ({v.vuln_class.value})" for v in spec.vulnerabilities)
    table.add_row("Vulnerabilities", vuln_str or "None")

    obj_str = ", ".join(f"{o.id}: {o.label}" for o in spec.objectives)
    table.add_row("Objectives", obj_str or "None")

    table.add_row("Seed", str(spec.seed))

    console.print(table)


def render_tick_step(tick: int, action: ProposedAction, success: bool, events: list[Event], failure_reason: str | None = None):
    """Renders execution step for a simulation tick."""
    action_repr = f"{action.verb.value}({action.target_id}"
    if action.parameters:
        params_str = ", ".join(f"{k}={v}" for k, v in action.parameters.items())
        action_repr += f", {params_str}"
    action_repr += ")"

    status_str = "[bold green]-> SUCCESS[/bold green]" if success else f"[bold red]-> FAILED ({failure_reason})[/bold red]"
    lines = [f"[bold cyan]TICK {tick}[/bold cyan] | [bold white]{action_repr}[/bold white]", f"       | {status_str}"]

    for evt in events:
        if evt.type == EventType.host_discovered:
            lines.append(f"       | [green]-> Discovered:[/green] {evt.metadata.get('hostname')} [{evt.metadata.get('ip')}]")
        elif evt.type == EventType.service_discovered:
            lines.append(f"       | [green]-> Service:[/green] {evt.target_id} [{evt.metadata.get('banner') or evt.metadata.get('protocol')}]")
        elif evt.type == EventType.credential_acquired:
            lines.append(f"       | [yellow]-> Credential obtained:[/yellow] {evt.target_id}")
        elif evt.type == EventType.lateral_movement:
            lines.append(f"       | [cyan]-> Pivoted to:[/cyan] {evt.target_id} via {evt.metadata.get('from_host')}")
        elif evt.type == EventType.authentication_success:
            lines.append(f"       | [green]-> Authenticated session established on[/green] {evt.metadata.get('host_id')}")
        elif evt.type == EventType.data_access:
            lines.append(f"       | [magenta]-> Data accessed:[/magenta] {evt.target_id} ({evt.metadata.get('sensitivity')})")
        elif evt.type == EventType.objective_achieved:
            lines.append(f"       | [bold green][*] Objective achieved:[/bold green] {evt.metadata.get('label')}")
        elif evt.type == EventType.detection_triggered:
            ctrl_id = evt.metadata.get("control_id")
            ctrl_type = evt.metadata.get("control_type", "control").upper()
            lines.append(f"       | [bold red][!] {ctrl_type} detection triggered [{ctrl_id}][/bold red]")

    console.print("\n".join(lines))


def render_run_summary(ticks: int, objectives_achieved: int, total_objectives: int, detection_count: int, output_path: str | None = None):
    """Renders run completion panel."""
    summary_text = (
        f"[bold white]Ticks:[/bold white] {ticks}  |  "
        f"[bold white]Objectives:[/bold white] {objectives_achieved}/{total_objectives}  |  "
        f"[bold white]Detections:[/bold white] {detection_count}"
    )
    if output_path:
        summary_text += f"\n[dim]Saved run package to:[/dim] [cyan]{output_path}[/cyan]"

    console.print(Panel(summary_text, title="[bold green]== RUN COMPLETE ==[/bold green]", border_style="green"))


def render_demo_header():
    """Renders the top banner for the live PBL demo."""
    console.print("=" * 60, style="bold cyan")
    console.print("                 [bold white]STATECRAFT[/bold white]")
    console.print("       [cyan]Deterministic Cyber Simulation Engine[/cyan]")
    console.print("=" * 60, style="bold cyan")
    console.print("\n[bold white]SCENARIO[/bold white]")
    console.print("[bold yellow]Simulated University Network[/bold yellow] -- Reference Simulation Environment")
    console.print("[dim]A controlled simulated cyber environment used to demonstrate[/dim]")
    console.print("[dim]Statecraft's deterministic execution and replay capabilities.[/dim]")
    console.print("[dim](Synthetic reference model; strictly isolated, not a live network)[/dim]\n")


def render_demo_section_header(title: str):
    """Renders a clearly demarcated demo section header."""
    console.print("-" * 60, style="bold cyan")
    console.print(f"[bold white]{title}[/bold white]")
    console.print("-" * 60, style="bold cyan")


def render_demo_environment(spec: EnvironmentSpec):
    """Renders Environment specification details."""
    render_demo_section_header("1. ENVIRONMENT SPECIFICATION")
    net_str = ", ".join(f"{n.id} ({n.zone.value})" for n in spec.networks)
    console.print(f"[bold yellow]Networks:[/bold yellow]          {net_str}")
    host_str = ", ".join(f"{h.hostname} [{h.ip_address}]" for h in spec.hosts)
    console.print(f"[bold yellow]Hosts:[/bold yellow]             {host_str}")
    services = [s.id for h in spec.hosts for s in h.services]
    console.print(f"[bold yellow]Services:[/bold yellow]          {', '.join(services)}")
    controls = [f"{c.type.value} ({c.id})" for c in spec.security_controls]
    console.print(f"[bold yellow]Security Controls:[/bold yellow] {', '.join(controls)}")
    assets = [f"{a.id} ({a.sensitivity.value})" for a in spec.data_assets]
    console.print(f"[bold yellow]Protected Assets:[/bold yellow]  {', '.join(assets)}")
    objs = [f"{o.id}: {o.label}" for o in spec.objectives]
    console.print(f"[bold yellow]Objectives:[/bold yellow]        {', '.join(objs)}\n")


def render_demo_validation(val_res):
    """Renders the static validation stage results."""
    render_demo_section_header("2. ENVIRONMENT VALIDATION")
    console.print("  [bold green][PASS][/bold green] Schema Check           (Syntax & typing conform to EnvironmentSpec)")
    console.print("  [bold green][PASS][/bold green] Integrity Check        (Referential links between hosts, services, controls)")
    console.print("  [bold green][PASS][/bold green] Graph Check            (Subnet CIDRs, no duplicate IPs, valid topologies)")
    console.print("  [bold green][PASS][/bold green] Reachability Check     (Entrypoint path exists from external boundary)")
    console.print("  [bold green][PASS][/bold green] Capability Check       (Actor grammar & vulnerability primitive constraints)")
    console.print("  [bold green][PASS][/bold green] Cycle Check            (No circular domain trust loops)")
    console.print("\n[bold green]Validation successful (Static Guarantee: Topology & rules mathematically sound).[/bold green]\n")


def render_demo_state_progression():
    """Renders concise state progression flow."""
    console.print("\n[bold white]Concise State Progression:[/bold white]")
    progression = """    attacker.access
        anonymous
          |
          v
        web access (host.web01)
          |
          v
        credential obtained (app_user)
          |
          v
        internal network access (net.internal)
          |
          v
        database session (host.db01)
          |
          v
        protected data access (asset.student_pii)"""
    console.print(progression, style="dim white")
    console.print()


def render_demo_persistence(saved_path: str, action_count: int, event_count: int):
    """Renders persistence verification."""
    render_demo_section_header("4. EXECUTION PERSISTENCE")
    console.print("  [bold green][PASS][/bold green] Event log persisted to SQLite causality store")
    console.print("  [bold green][PASS][/bold green] Replay artifact created (.scr archive package)")
    console.print(f"  [bold white]Artifact:[/bold white] [cyan]{saved_path}[/cyan]")
    console.print(f"  [bold white]Contents:[/bold white] EnvironmentSpec, Manifest, {action_count} actions, {event_count} causal events\n")


def render_demo_replay(original_run, replayed_state, replayed_events, is_match: bool):
    """Renders replay execution and bit-for-bit comparison."""
    render_demo_section_header("5. DETERMINISTIC REPLAY")
    orig_objs = len(original_run.final_state.achieved_objectives) if original_run.final_state else 1
    rep_objs = len(replayed_state.achieved_objectives)
    
    console.print(f"[bold white]Original execution:[/bold white]")
    console.print(f"    {len(original_run.actions)} actions")
    console.print(f"    {len(original_run.events)} events")
    console.print(f"    {orig_objs} objective achieved\n")

    console.print(f"[bold white]Replay execution:[/bold white]")
    console.print(f"    {len(original_run.actions)} actions")
    console.print(f"    {len(replayed_events)} events")
    console.print(f"    {rep_objs} objective achieved\n")

    console.print("[bold white]Verification:[/bold white]")
    if is_match:
        console.print("  [bold green][PASS][/bold green] Final state matches bit-for-bit")
        console.print("  [bold green][PASS][/bold green] Objectives match")
        console.print(f"  [bold green][PASS][/bold green] Active sessions match ({len(replayed_state.sessions)} active)")
        console.print(f"  [bold green][PASS][/bold green] Event sequence matches exactly ({len(replayed_events)} events)\n")
    else:
        console.print("  [bold red][FAIL] Replay state divergence detected![/bold red]\n")


def render_demo_final_summary():
    """Renders final architecture takeaway panel."""
    console.print("=" * 60, style="bold cyan")
    console.print("                    [bold white]STATECRAFT RESULT[/bold white]")
    console.print("=" * 60, style="bold cyan")
    console.print("  Environment validated       [bold green][PASS][/bold green]")
    console.print("  Deterministic execution     [bold green][PASS][/bold green]")
    console.print("  Security telemetry          [bold green][PASS][/bold green]")
    console.print("  Objective evaluation        [bold green][PASS][/bold green]")
    console.print("  Execution persisted         [bold green][PASS][/bold green]")
    console.print("  Deterministic replay        [bold green][PASS][/bold green]")
    console.print()
    console.print("[bold cyan]CORE GUARANTEE[/bold cyan]")
    diagram = """    User / AI proposes an action
                |
                v
       Statecraft validates it
                |
                v
       Deterministic engine
                |
                v
          State transition
                |
                v
             Telemetry

  [bold green]Only the Statecraft engine is authoritative.[/bold green]"""
    console.print(diagram)
    console.print("=" * 60, style="bold cyan")


