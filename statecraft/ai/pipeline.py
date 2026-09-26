"""AI Interaction Pipeline for Statecraft.

ARCHITECTURAL PRINCIPLE:
User Natural Language -> AI Provider -> ProposedAction -> Statecraft Engine (Authoritative) -> ActionResult -> Presentation

The AI has NO direct access to modify simulation state. All state mutations must be evaluated
and applied strictly by the deterministic ActionExecutor in the Simulator.
"""

from dataclasses import dataclass
from typing import Any

from statecraft.ai.provider import BaseAIProvider, RuleBasedNLPProvider
from statecraft.engine.simulator import Simulator
from statecraft.model.actions import ActionResult, ProposedAction
from statecraft.model.events import EventType
from statecraft.observation.attacker_view import ObservationEngine
from statecraft.spec.schema import EnvironmentSpec


@dataclass
class AITurnResult:
    user_prompt: str
    proposed_action: ProposedAction | None
    engine_result: ActionResult | None
    narrative_response: str
    rejected: bool = False


class AIEngineSession:
    """Manages an interactive session where natural language is converted to

    ProposedActions and mediated by the authoritative Statecraft Simulator.
    """

    def __init__(self, spec: EnvironmentSpec, provider: BaseAIProvider | None = None, seed: int = 42):
        self.spec = spec
        self.simulator = Simulator(spec, seed=seed)
        self.provider = provider or RuleBasedNLPProvider()
        self.history: list[AITurnResult] = []

    @property
    def current_state(self):
        return self.simulator.current_state

    def process_message(self, user_message: str) -> AITurnResult:
        """Process a user message through the AI proposal and deterministic engine boundary."""
        obs = ObservationEngine.attacker_view(self.current_state, self.spec)

        # 1. AI Proposes an Action (Unprivileged Proposal)
        proposed_action = self.provider.propose_action(
            prompt=user_message,
            observation=obs,
            actor_id="actor_attacker",
        )

        if not proposed_action:
            narrative = (
                "AI was unable to translate this prompt into any valid Statecraft action verb "
                "(scan, enumerate, authenticate, exploit, escalate_privilege, pivot, access_data, persist)."
            )
            res = AITurnResult(
                user_prompt=user_message,
                proposed_action=None,
                engine_result=None,
                narrative_response=narrative,
                rejected=True,
            )
            self.history.append(res)
            return res

        # 2. Statecraft Engine Evaluates & Executes the Action (Authoritative Boundary)
        action_res: ActionResult = self.simulator.step(proposed_action)

        # 3. Format Narrative Response strictly grounded in actual ActionResult
        narrative_parts = []
        if action_res.success:
            narrative_parts.append(f"[+] Engine accepted action: {proposed_action.verb.value} on {proposed_action.target_id}.")
            for evt in action_res.events:
                if evt.type == EventType.host_discovered:
                    narrative_parts.append(f"  -> Discovered host: {evt.metadata.get('hostname')} [{evt.metadata.get('ip')}]")
                elif evt.type == EventType.service_discovered:
                    narrative_parts.append(f"  -> Discovered service: {evt.target_id}")
                elif evt.type == EventType.credential_acquired:
                    narrative_parts.append(f"  -> Obtained credential: {evt.target_id}")
                elif evt.type == EventType.lateral_movement:
                    narrative_parts.append(f"  -> Pivoted to: {evt.target_id} via {evt.metadata.get('from_host')}")
                elif evt.type == EventType.authentication_success:
                    narrative_parts.append(f"  -> Authenticated session established on {evt.metadata.get('host_id')}")
                elif evt.type == EventType.data_access:
                    narrative_parts.append(f"  -> Accessed data asset: {evt.target_id}")
                elif evt.type == EventType.objective_achieved:
                    narrative_parts.append(f"  [*] Objective achieved: {evt.metadata.get('label')}")
                elif evt.type == EventType.detection_triggered:
                    narrative_parts.append(f"  [!] Alert: {evt.metadata.get('control_type', 'Control')} triggered [{evt.metadata.get('control_id')}]")
        else:
            reason = action_res.failure_reason.value if action_res.failure_reason else "Execution failed"
            narrative_parts.append(f"[!] Engine REJECTED action: {reason}")

        turn_result = AITurnResult(
            user_prompt=user_message,
            proposed_action=proposed_action,
            engine_result=action_res,
            narrative_response="\n".join(narrative_parts),
            rejected=not action_res.success,
        )
        self.history.append(turn_result)
        return turn_result
