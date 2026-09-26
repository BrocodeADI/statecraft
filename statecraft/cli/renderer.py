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
