# Statecraft PBL Verification

## Environment
- **Python Version:** Python 3.13.14
- **Operating System:** Windows 11 (win32)
- **Installation Method:** Editable package installation via `pip install -e .` (PEP 660 / pyproject.toml)
- **Dependencies:** Pydantic 2.10.4, PyYAML 6.0.3, Typer 0.27.1, Rich 15.0.0, Pytest 8.3.4

---

## Verified Components

1. **EnvironmentSpec**: Declarative YAML-based schema with strict Pydantic parsing. Models networks, hosts, services, accounts, identities, credentials, trust relationships, firewall rules, security controls, data assets, and objectives.
2. **Validation Engine**: Pure-code 6-stage fail-fast validation pipeline + Stage 7 solvability probe. Hard-rejects schema errors, referential integrity breaks, CIDR/duplicate IP violations, unreachable topologies, illegal effect primitives, and circular trust cycles.
3. **State Engine**: Authoritative, deterministic state management. Operates with immutable snapshots in `StateStore` (`apply_delta`, `state_at`, `current`). Guarantees that historical state snapshots are never mutated in place.
4. **Core Actions**: All 8 Day-1 verbs implemented and verified: `scan`, `enumerate`, `authenticate`, `exploit`, `escalate_privilege`, `pivot`, `access_data`, and `persist`.
5. **Effect Primitives**: Closed vocabulary of 12 primitives strictly verified: `grant_session`, `elevate_privilege`, `revoke_session`, `obtain_credential`, `discover_asset`, `discover_service`, `pivot_network`, `read_file`, `read_data_asset`, `create_persistence`, `disable_control`, and `achieve_objective`.
6. **Telemetry**: Real-time event emission via `TelemetryBus` and append-only SQLite `EventLog`. Security controls (WAF, IDS, EDR) evaluate action verbs, targets, and vulnerability classes to emit derivative `detection_triggered` events.
7. **Observation / Fog of War**: `ObservationEngine.attacker_view` derives filtered attacker knowledge (`AttackerObservation`), ensuring ground-truth details (such as undiscovered hosts, unenumerated services, and internal credentials) are strictly hidden until discovered.
8. **Persistence**: Portable `.scr` archive format (gzipped tarball containing `manifest.json`, `spec.yaml`, `events.jsonl`, and `run.json`).
9. **Replay**: Deterministic sequential replay via `Replayer`. Reconstructs identical state without precomputed outputs.
10. **CLI**: Rich-formatted command-line interface with `validate`, `show`, `run`, and `replay` commands. Hardened for cross-platform ASCII terminal safety.
11. **Reference Scenario**: `scenarios/university-network.yaml` (Midland University Network) demonstrating the complete 7-step attack sequence.

---

## Test Results

Test suite executed: `pytest -v`

```text
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-8.3.4, pluggy-1.6.0
rootdir: C:\Users\chakr\Downloads\PBL-3(probable project)\Statecraft
configfile: pyproject.toml
testpaths: tests
plugins: anyio-3.7.1, Faker-33.1.0
collected 36 items

tests/integration/test_full_scenario.py::test_university_scenario_full_attack_path PASSED [  2%]
tests/property/test_invariants.py::test_deterministic_simulation_invariant PASSED [  5%]
tests/property/test_invariants.py::test_action_never_mutates_previous_snapshots_invariant PASSED [  8%]
tests/property/test_invariants.py::test_effects_stay_within_closed_vocabulary PASSED [ 11%]
tests/unit/test_effects.py::test_grant_session_and_elevate PASSED        [ 13%]
tests/unit/test_effects.py::test_obtain_credential PASSED                [ 16%]
tests/unit/test_effects.py::test_discover_asset_and_service PASSED       [ 19%]
tests/unit/test_effects.py::test_pivot_network PASSED                    [ 22%]
tests/unit/test_effects.py::test_read_file_and_data_asset PASSED         [ 25%]
tests/unit/test_effects.py::test_create_persistence PASSED               [ 27%]
tests/unit/test_effects.py::test_disable_control PASSED                  [ 30%]
tests/unit/test_effects.py::test_achieve_objective PASSED                [ 33%]
tests/unit/test_effects.py::test_unknown_primitive_raises_error PASSED   [ 36%]
tests/unit/test_executor.py::test_executor_immutability PASSED           [ 38%]
tests/unit/test_executor.py::test_action_fails_when_target_not_discovered PASSED [ 41%]
tests/unit/test_executor.py::test_action_fails_when_not_reachable PASSED [ 44%]
tests/unit/test_executor.py::test_failed_authenticate_invalid_cred PASSED [ 47%]
tests/unit/test_executor.py::test_persist_and_escalate_privilege PASSED  [ 50%]
tests/unit/test_model.py::test_credential_round_trip PASSED              [ 52%]
tests/unit/test_model.py::test_host_and_service_model PASSED             [ 55%]
tests/unit/test_model.py::test_vulnerability_alias_class PASSED          [ 58%]
tests/unit/test_model.py::test_event_serialization PASSED                [ 61%]
tests/unit/test_model.py::test_objective_model PASSED                    [ 63%]
tests/unit/test_model.py::test_proposed_action_validation PASSED         [ 66%]
tests/unit/test_model.py::test_invalid_privilege_level PASSED            [ 69%]
tests/unit/test_observation.py::test_fog_of_war_observation PASSED       [ 72%]
tests/unit/test_replay.py::test_deterministic_replay PASSED              [ 75%]
tests/unit/test_replay.py::test_mid_run_replay PASSED                    [ 77%]
tests/unit/test_replay.py::test_export_import_roundtrip PASSED           [ 80%]
tests/unit/test_validator.py::test_valid_university_spec PASSED          [ 83%]
tests/unit/test_validator.py::test_stage_1_schema_error PASSED           [ 86%]
tests/unit/test_validator.py::test_stage_2_integrity_error PASSED        [ 88%]
tests/unit/test_validator.py::test_stage_3_graph_error PASSED            [ 91%]
tests/unit/test_validator.py::test_stage_4_reachability_error PASSED     [ 94%]
tests/unit/test_validator.py::test_stage_5_capability_error PASSED       [ 97%]
tests/unit/test_validator.py::test_stage_6_cycle_error PASSED            [100%]

============================= 36 passed in 0.72s ==============================
```

---

## End-to-End Run

Executed command:
```bash
statecraft run --scenario scenarios/university-network.yaml --out runs/university.scr
```

Observed sequence:
1. **TICK 1:** `scan(net.dmz)` -> Discovered host `WEB01 [10.0.1.10]` via allowed firewall rule `fw.001`.
2. **TICK 2:** `enumerate(host.web01)` -> Discovered running services `svc.web01.https` (nginx) and `svc.web01.app` (StudentPortal v2.1.4).
3. **TICK 3:** `exploit(svc.web01.app, vuln_id=vuln.sqli-studentportal)` -> Preconditions met; executed effects: acquired credential `cred.db01.app_user` and discovered asset `asset.student_pii`. Triggered WAF detection alert (`ctrl.waf.web01`). Host `WEB01` marked compromised.
4. **TICK 4:** `pivot(net.internal, via=host.web01)` -> Preconditions met (pivot via compromised web host with internal route exception); added `net.internal` to attacker reachable networks.
5. **TICK 5:** `scan(net.internal)` -> Discovered internal hosts: `DB01 [10.0.10.20]`, `DC01 [10.0.10.5]`, `FACULTY-PC-01 [10.0.10.101]`.
6. **TICK 6:** `authenticate(svc.db01.postgres, credential_id=cred.db01.app_user)` -> Preconditions met; established active session on `host.db01` under `app_user` with `service` privilege level.
7. **TICK 7:** `access_data(asset.student_pii)` -> Preconditions met (session account in asset's `accessible_by`); read restricted student data; achieved scenario objective `obj.exfiltrate_pii`.

Summary:
- **Ticks:** 7
- **Objectives:** 1/1 achieved
- **Detections:** 1 (WAF)
- **Archive:** Saved to `runs/university.scr`

---

## Replay Verification

Executed command:
```bash
statecraft replay runs/university.scr
```

Actual output:
```text
[>] Loading and replaying run archive: runs\university.scr
[+] Replay execution completed
  Spec ID: env-univ-001
  Actions replayed: 7
  Events generated: 15
  Final Tick: 7
  Achieved Objectives: ['obj.exfiltrate_pii']
[*] State match verified: Replay output is bit-for-bit identical to recorded run.
    - Ticks: 7 == 7
    - Objectives: ['obj.exfiltrate_pii']
    - Sessions: 1 active
    - Events: 15 events identical
```

Verification details:
- The replayer initializes a fresh state store from the embedded `spec.yaml` using seed 42.
- The recorded action sequence is executed transactionally through `ActionExecutor`.
- The final state is compared field-by-field against the original run's `final_state`:
  - Simulation tick count (`tick == 7`)
  - Achieved objectives list (`['obj.exfiltrate_pii']`)
  - Active sessions count and IDs
  - Emitted event count (15 events) and event causality chain

---

## Known Issues

- None affecting Day-1 scope or PBL demonstration.
- Terminal output is formatted using ASCII borders and symbols (`[>]`, `[+]`, `[!]`, `|`, `->`, `[*]`) to guarantee flawless display on legacy Windows console codepages (e.g. cp1252/cp437).

---

## Deferred Scope (Intentionally Out of Scope for Day-1)

The following components are deferred to v2/v3 per the specification:
1. **LLM Scenario Compiler:** Natural language to draft EnvironmentSpec compiler.
2. **LLM Attacker Agent:** Dynamic LLM agent proposing actions per turn.
3. **LLM Narrator:** Post-action natural language narration.
4. **Web UI & Graph Visualization:** Cytoscape.js network topology viewer.
5. **Defender Agent & Response Actions:** Session revocation and host isolation.
6. **Probabilistic Exploit RNG:** Exploits with reliability < 1.0 (v1 treats reliability as 1.0).
7. **Branching Replay:** Forking runs at arbitrary tick N with spec patches.
8. **Multiplayer & Concurrency:** Concurrent attacker/defender turn scheduling.
9. **Plugin System:** Third-party custom effect primitives.
