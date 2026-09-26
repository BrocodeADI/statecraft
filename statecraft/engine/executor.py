from statecraft.actions.registry import ActionRegistry
from statecraft.effects.composer import EffectComposer
from statecraft.engine.rng import SeededRNG
from statecraft.engine.state_store import StateStore
from statecraft.model.actions import ActionResult, ActionVerb, FailureReason, ProposedAction
from statecraft.model.state import StateDelta
from statecraft.spec.schema import EnvironmentSpec


class ActionExecutor:
    """The authoritative action execution transaction.

    (State, Action, Spec) -> (State', [Event], ActionResult)
    """

    def __init__(
        self,
        spec: EnvironmentSpec,
        state_store: StateStore,
        rng: SeededRNG,
        action_registry: ActionRegistry | None = None,
        effect_composer: EffectComposer | None = None,
    ):
        self.spec = spec
        self.state_store = state_store
        self.rng = rng
        self.action_registry = action_registry or ActionRegistry()
        self.effect_composer = effect_composer or EffectComposer()

    def execute(self, action: ProposedAction) -> ActionResult:
        """Executes one action atomically and deterministically."""
        state = self.state_store.current()

        # Stage 1: Grammar check
        if not self.action_registry.is_valid_verb(action.verb, action.actor_id):
            return ActionResult(
                success=False,
                failure_reason=FailureReason.forbidden_by_grammar,
                state_delta=StateDelta.empty(),
                events=[],
                narrative_hint="Action verb forbidden by grammar",
            )

        handler = self.action_registry.get(action.verb)

        # Stage 2: Check preconditions
        ok, reason = handler.check_preconditions(state, action, self.spec)
        if not ok:
            events = handler.build_telemetry(state, action, self.spec, success=False)
            return ActionResult(
                success=False,
                failure_reason=reason,
                state_delta=StateDelta.empty(),
                events=events,
                narrative_hint=f"{action.verb.value} failed: {reason.value if reason else 'unknown'}",
            )

        # Stage 3: Compute effects
        effect_specs = handler.compute_effects(state, action, self.spec, self.rng)

        # Stage 4: Compose effects into StateDelta
        delta = self.effect_composer.compose(
            state=state,
            effect_specs=effect_specs,
            actor_id=action.actor_id,
            tick_advance=1,
        )

        # If exploit succeeded, ensure target host is marked compromised
        if action.verb == ActionVerb.exploit:
            for h in self.spec.hosts:
                for s in h.services:
                    if s.id == action.target_id:
                        h_state = delta.updated_host_states.get(h.id) or state.hosts.get(h.id)
                        if h_state:
                            up_h = h_state.model_copy(deep=True)
                            up_h.compromised = True
                            delta.updated_host_states[h.id] = up_h
                        break

        # Stage 5: Apply delta to state store (creates immutable new snapshot)
        self.state_store.apply_delta(delta)

        # Stage 6: Build telemetry
        events = handler.build_telemetry(state, action, self.spec, success=True)

        return ActionResult(
            success=True,
            failure_reason=None,
            state_delta=delta,
            events=events,
            narrative_hint=f"{action.verb.value} succeeded",
        )
