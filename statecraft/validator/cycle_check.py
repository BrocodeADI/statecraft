from collections import defaultdict

from statecraft.model.security import TrustType
from statecraft.spec.schema import EnvironmentSpec
from statecraft.validator.errors import ValidationError


def validate_cycle_consistency(spec: EnvironmentSpec) -> list[ValidationError]:
    """Stage 6: Cycle Detection. Check for cycles in credential_reuse trust relationships."""
    errors: list[ValidationError] = []

    adj = defaultdict(list)
    for trust in spec.trust_relationships:
        if trust.type == TrustType.credential_reuse:
            adj[trust.from_id].append(trust.to_id)
            if not trust.is_directional:
                adj[trust.to_id].append(trust.from_id)

    visited: dict[str, int] = {}  # 0 = unvisited, 1 = visiting (in stack), 2 = visited

    def dfs(node: str, path: list[str]) -> bool:
        visited[node] = 1
        path.append(node)

        for neighbor in adj[node]:
            if visited.get(neighbor, 0) == 1:
                # Cycle found!
                cycle_str = " -> ".join(path + [neighbor])
                errors.append(
                    ValidationError(
                        stage="stage_6_cycle",
                        error_type="CycleError",
                        message=f"Circular credential dependency detected: {cycle_str}",
                        entity_id=node,
                    )
                )
                return True
            elif visited.get(neighbor, 0) == 0:
                if dfs(neighbor, path):
                    return True

        path.pop()
        visited[node] = 2
        return False

    for node in list(adj.keys()):
        if visited.get(node, 0) == 0:
            dfs(node, [])

    return errors
