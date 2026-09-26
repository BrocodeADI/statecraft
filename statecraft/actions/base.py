from abc import ABC, abstractmethod

from statecraft.engine.rng import SeededRNG
from statecraft.model.actions import ActionVerb, FailureReason, ProposedAction
from statecraft.model.events import Event
from statecraft.model.security import EffectSpec
from statecraft.model.state import EnvironmentState
from statecraft.spec.schema import EnvironmentSpec


class ActionHandler(ABC):
    """Abstract base class for all action handlers."""

    verb: ActionVerb

    @abstractmethod
    def check_preconditions(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
    ) -> tuple[bool, FailureReason | None]:
        """Pure function. No side effects. Returns (ok, reason_if_failed)."""
        pass

    @abstractmethod
    def compute_effects(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        rng: SeededRNG,
    ) -> list[EffectSpec]:
        """Pure function. Returns effect list. Does not apply effects."""
        pass

    @abstractmethod
    def build_telemetry(
        self,
        state: EnvironmentState,
        action: ProposedAction,
        spec: EnvironmentSpec,
        success: bool,
    ) -> list[Event]:
        """Pure function. Returns events."""
        pass
