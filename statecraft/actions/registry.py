from statecraft.actions.access_data import AccessDataHandler
from statecraft.actions.authenticate import AuthenticateHandler
from statecraft.actions.base import ActionHandler
from statecraft.actions.enumerate import EnumerateHandler
from statecraft.actions.escalate_privilege import EscalatePrivilegeHandler
from statecraft.actions.exploit import ExploitHandler
from statecraft.actions.persist import PersistHandler
from statecraft.actions.pivot import PivotHandler
from statecraft.actions.scan import ScanHandler
from statecraft.model.actions import ActionVerb


class ActionRegistry:
    """Canonical registry mapping ActionVerb to ActionHandler."""

    def __init__(self):
        self._handlers: dict[ActionVerb, ActionHandler] = {
            ActionVerb.scan: ScanHandler(),
            ActionVerb.enumerate: EnumerateHandler(),
            ActionVerb.authenticate: AuthenticateHandler(),
            ActionVerb.exploit: ExploitHandler(),
            ActionVerb.escalate_privilege: EscalatePrivilegeHandler(),
            ActionVerb.pivot: PivotHandler(),
            ActionVerb.access_data: AccessDataHandler(),
            ActionVerb.persist: PersistHandler(),
        }

    def is_valid_verb(self, verb: ActionVerb, actor_id: str | None = None) -> bool:
        return verb in self._handlers

    def get(self, verb: ActionVerb) -> ActionHandler:
        handler = self._handlers.get(verb)
        if not handler:
            raise KeyError(f"No handler registered for verb: {verb}")
        return handler
