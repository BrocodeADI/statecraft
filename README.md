# STATECRAFT — Cyber Environment Compiler + Deterministic Action Engine

> *"Describe a network in English. Get a deterministic cyber world you can attack, defend, and replay."*

Statecraft is an authoritative cyber environment simulation engine. An operator defines an organization's network, hosts, services, accounts, vulnerabilities, and security controls in an immutable, validated `EnvironmentSpec`. An actor interacts with this environment strictly through a constrained action grammar. The deterministic simulation engine acts as the authoritative referee—validating state transitions, enforcing fog-of-war constraints, generating telemetry, and recording an append-only event log.

---

## Architecture & Guarantees

1. **The Engine is Authoritative:** Agents (human, scripted, or LLM) only propose actions and receive filtered observations. They cannot directly mutate simulation state.
2. **Deterministic Simulation:** For any `(EnvironmentSpec, seed, action_sequence)` tuple, the resulting final state and event log are bit-for-bit identical.
3. **Fog of War:** Agents observe only what has been actively discovered, enumerated, or acquired.
4. **Append-Only Event Log & Replay:** Every state change produces an immutable event stream. Any run can be perfectly reconstructed via replay.

---

## 8 Core Actions Implemented

- `scan(target_network)`: Discovers reachable hosts through firewall rules.
- `enumerate(target_host)`: Discovers running services and banners on discovered hosts.
- `authenticate(target_service, credential_id)`: Validates credentials and establishes authenticated host sessions.
- `exploit(target_service, vuln_id)`: Evaluates preconditions and applies vulnerability effect primitives.
- `escalate_privilege(target_host)`: Elevates session privileges via vulnerabilities or administrative credentials.
- `pivot(target_network, via_host)`: Projects network reachability through compromised pivot hosts.
- `access_data(target_asset_or_file)`: Accesses sensitive data assets or files; achieves scenario objectives.
- `persist(target_host)`: Establishes persistent footholds on compromised hosts.

---

## 12 Effect Primitives (Closed Vocabulary)

1. `grant_session`
2. `elevate_privilege`
3. `revoke_session`
4. `obtain_credential`
5. `discover_asset`
6. `discover_service`
7. `pivot_network`
8. `read_file`
9. `read_data_asset`
10. `create_persistence`
11. `disable_control`
12. `achieve_objective`

---

## Quickstart

### 1. Installation

```bash
pip install -e .
```

### 2. Validate Scenario

```bash
statecraft validate scenarios/university-network.yaml
```

### 3. Inspect Scenario

```bash
statecraft show scenarios/university-network.yaml
```

### 4. Execute Simulation Run

```bash
statecraft run --scenario scenarios/university-network.yaml --out runs/university.scr
```

### 5. Replay Run

```bash
statecraft replay runs/university.scr
```

### 6. Run Test Suite

```bash
pytest -v
```
