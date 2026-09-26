from pathlib import Path
from typing import Union

from statecraft.engine.executor import ActionExecutor
from statecraft.engine.rng import SeededRNG
from statecraft.engine.state_builder import build_initial_state
from statecraft.engine.state_store import StateStore
from statecraft.model.actions import ActionResult, ProposedAction
from statecraft.model.events import Event
from statecraft.model.state import EnvironmentState
from statecraft.observation.attacker_view import AttackerObservation, ObservationEngine
from statecraft.persistence.event_log import EventLog
from statecraft.persistence.export import export_run
from statecraft.persistence.run import Run
from statecraft.spec.schema import EnvironmentSpec
from statecraft.telemetry.bus import TelemetryBus


class Simulator:
    """The authoritative Statecraft Simulation Engine entry point."""

    def __init__(
        self,
        spec: EnvironmentSpec,
        seed: int | None = None,
        event_log_path: Union[str, Path] = ":memory:",
    ):
        self.spec = spec
        self.seed = seed if seed is not None else spec.seed
        self.rng = SeededRNG(self.seed)
        self.initial_state = build_initial_state(self.spec)
        self.state_store = StateStore(self.initial_state)

        self.telemetry_bus = TelemetryBus()
        self.event_log = EventLog(event_log_path)
        self.telemetry_bus.subscribe(self.event_log.append)

        self.executor = ActionExecutor(
            spec=self.spec,
            state_store=self.state_store,
            rng=self.rng,
        )
        self.observation_engine = ObservationEngine()

        self._recorded_actions: list[ProposedAction] = []
        self._recorded_events: list[Event] = []

    @property
    def current_state(self) -> EnvironmentState:
        return self.state_store.current()

    def get_attacker_observation(self, actor_id: str = "actor_attacker") -> AttackerObservation:
        return self.observation_engine.attacker_view(self.current_state, self.spec, actor_id)

    def step(self, action: ProposedAction) -> ActionResult:
        """Executes a single action on the simulation engine."""
        result = self.executor.execute(action)

        self._recorded_actions.append(action)
        self._recorded_events.extend(result.events)
        self.telemetry_bus.emit_all(result.events)

        return result

    def to_run(self) -> Run:
        """Constructs a Run object capturing the completed simulation."""
        return Run(
            environment_spec=self.spec,
            seed=self.seed,
            actions=list(self._recorded_actions),
            events=list(self._recorded_events),
            final_state=self.current_state,
        )

    def save_run(self, export_path: Union[str, Path]) -> Path:
        """Exports the run to a .scr file."""
        run = self.to_run()
        return export_run(run, export_path)
