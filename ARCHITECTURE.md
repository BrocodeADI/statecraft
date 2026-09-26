# Statecraft Architecture Summary

This document describes the actual architecture of Statecraft as implemented in the Day-1 MVP.

---

## Architecture Flow Diagram

```text
Scenario YAML
     ↓
EnvironmentSpec
     ↓
Validation Pipeline
     ↓
State Builder
     ↓
Simulation / Executor
     ↓
Actions + Effects
     ↓
Telemetry
     ↓
Persistence
     ↓
Replay
```

---

## Layer Responsibilities

### 1. Scenario YAML
- Human-readable declarative specification format defining networks, hosts, services, accounts, identities, credentials, firewall rules, security controls, data assets, and objectives.
- Stored as version-controlled YAML files under `scenarios/`.

### 2. EnvironmentSpec (`statecraft/spec/`, `statecraft/model/`)
- Strongly-typed Pydantic model representation of the scenario.
- Performs schema coercion, validates value types, aliases, and structure.
- Serves as the immutable static blueprint of the target environment.

### 3. Validation Pipeline (`statecraft/validator/`)
- Pure-code, 6-stage fail-fast static analysis pipeline + Stage 7 solvability probe.
- Operates prior to any state initialization.
- **Stages:**
  1. `schema_check`: Validates basic syntactic and typing constraints.
  2. `integrity_check`: Enforces referential integrity (e.g., firewall targets reference valid host/network IDs).
  3. `graph_check`: Ensures subnet/CIDR validity, detects duplicate IP assignments, and verifies network definitions.
  4. `reachability`: Confirms that initial attacker foothold has a valid path into the network.
  5. `capability_check`: Ensures actions specify allowed primitives and valid vulnerability IDs.
  6. `cycle_check`: Detects and flags invalid circular trust loops between domains.
  7. `solvability`: Verifies graph paths exist from entry points to defined scenario objectives.

### 4. State Builder (`statecraft/engine/state_builder.py`)
- Transforms the static `EnvironmentSpec` into the authoritative runtime `SimulationState`.
- Seeds the initial state: initializes discovered hosts, starting attacker footholds, and registers initial conditions.

### 5. Simulation / Executor (`statecraft/engine/simulator.py`, `statecraft/engine/executor.py`)
- **Authoritative Execution Engine:** Holds authoritative control over simulation progression.
- Evaluates proposed actions submitted by agents against firewall rules, routing reachability, active sessions, and credential requirements.
- Uses `StateStore` to manage state transitions via immutable snapshots (`apply_delta`, `state_at`), preventing in-place state corruption.

### 6. Actions & Effects (`statecraft/actions/`, `statecraft/effects/`)
- **Actions (Verbs):** Closed set of 8 actions (`scan`, `enumerate`, `authenticate`, `exploit`, `escalate_privilege`, `pivot`, `access_data`, `persist`).
- **Effect Primitives (Atoms):** Closed vocabulary of 12 atomic state transitions (`grant_session`, `elevate_privilege`, `revoke_session`, `obtain_credential`, `discover_asset`, `discover_service`, `pivot_network`, `read_file`, `read_data_asset`, `create_persistence`, `disable_control`, `achieve_objective`).
- All state changes are mediated strictly through composer-applied effect primitives.

### 7. Telemetry & Observation (`statecraft/telemetry/`, `statecraft/observation/`)
- **Telemetry Bus (`TelemetryBus`):** Emits synchronous domain events (`action_executed`, `state_transitioned`, `objective_completed`, `detection_triggered`).
- **Security Controls:** Evaluates WAF, IDS, and EDR rules on every executed action to emit real-time detection events.
- **Attacker Observation Plane (`AttackerObservation`):** Filters ground truth through the fog of war, ensuring external agents only receive the perspective of discovered nodes and harvested credentials.

### 8. Persistence (`statecraft/persistence/`)
- **Event Log (`EventLog`):** Append-only SQLite database storing all causal events and snapshots.
- **Run Exporter (`export_run`):** Bundles the complete simulation into a portable `.scr` archive containing `manifest.json`, `spec.yaml`, `events.jsonl`, and `run.json`.

### 9. Replay (`statecraft/replay/`)
- **Deterministic Replayer (`Replayer`):** Reads `.scr` run archives, initializes a clean simulation state from the embedded specification, and re-executes recorded action sequences.
- Verifies deterministic reproducibility by performing field-by-field verification of final state, objectives, active sessions, and event sequences.
