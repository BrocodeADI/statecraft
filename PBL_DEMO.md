# Statecraft PBL Demonstration Guide & Presentation Script

This document serves as the official briefing, presentation guide, and Professor Q&A defense document for the Statecraft project demonstration.

---

## A. What Statecraft Is

**Statecraft** is an authoritative, deterministic cyber simulation engine. It models computer networks, firewall policies, identities, host vulnerabilities, security controls (WAF, IDS, EDR), and data assets as discrete stateful systems. 

Unlike heavy, fragile, and non-deterministic virtual machine testbeds, Statecraft separates **intelligence** from **simulation physics**:
- Agents (whether scripted attackers, automated red-teams, or AI models) propose actions.
- The deterministic Statecraft engine validates physical preconditions, computes state transitions via a closed vocabulary of 12 atomic effect primitives, emits causality-linked telemetry, and guarantees bit-for-bit replayability.

---

## B. What the Simulated University Network Represents

The reference scenario (`scenarios/university-network.yaml`) is a **Simulated University Network** — a synthetic, controlled reference model designed to benchmark and demonstrate Statecraft's capabilities.

> **IMPORTANT CLARIFICATION:**
> The scenario is a purely synthetic software specification (`env-univ-001`). It does **not** represent, interact with, or scan any real-world university infrastructure, student records, or live physical devices. All IP addresses (e.g. `10.0.1.10`, `10.0.10.20`), credentials (`cred.db01.app_user`), and data assets (`asset.student_pii`) exist exclusively within the simulation's memory and state store.

---

## C. The Exact One-Command Demo

To deliver a flawless presentation without typing individual commands during the evaluation, execute:

```bash
statecraft demo
```

### Presentation Flags:
- `statecraft demo` — Live presentation mode with readable pacing (~6–8 seconds of smooth step-by-step terminal execution).
- `statecraft demo --fast` — Instant execution without pauses (ideal for automated evaluation and quick verification).
- `statecraft demo --ai` — Appends the optional AI Action Proposer demonstration, verifying the engine authority boundary.
- `statecraft demo --fast --ai` — Instant execution including the AI Action Proposer section.

---

## D. What Each Demo Phase Demonstrates

When `statecraft demo` executes, it takes the evaluator through a coherent, 5-phase story:

### 1. ENVIRONMENT SPECIFICATION
- **What it shows:** Declarative modeling of network zones (`net.external`, `net.dmz`, `net.internal`), hosts (`WEB01`, `DB01`, `DC01`, `FACULTY-PC-01`), services, firewall rules, and the target asset (`asset.student_pii`).
- **Takeaway:** Demonstrates strong declarative typing and full network topology specification.

### 2. ENVIRONMENT VALIDATION
- **What it shows:** Static 6-stage fail-fast verification pipeline:
  1. *Schema Check:* Syntax and typing constraints.
  2. *Integrity Check:* Referential links between hosts, services, and security controls.
  3. *Graph Check:* CIDR consistency, routing definitions, duplicate IP prevention.
  4. *Reachability Check:* Confirms an entrypoint path exists from external boundaries.
  5. *Capability Check:* Actor grammar constraints and vulnerability effect validity.
  6. *Cycle Check:* Ensures no circular domain trust loops.
- **Takeaway:** Static guarantee that the environment is mathematically sound before a single tick runs.

### 3. ATTACK SIMULATION & TELEMETRY
- **What it shows:** Sequential execution of a 7-tick attack path:
  - `TICK 1 (SCAN):` DMZ scanned -> `WEB01 [10.0.1.10]` discovered.
  - `TICK 2 (ENUMERATE):` `WEB01` port scan -> Nginx and StudentPortal services discovered.
  - `TICK 3 (EXPLOIT):` SQL injection executed -> Database credentials obtained (`cred.db01.app_user`), Student PII discovered, and WAF detection event triggered (`ctrl.waf.web01`).
  - `TICK 4 (PIVOT):` Internal network reachability established via compromised web server.
  - `TICK 5 (SCAN):` Internal network scanned -> Database (`DB01`), Domain Controller (`DC01`), and Faculty workstation discovered.
  - `TICK 6 (AUTHENTICATE):` Authenticated PostgreSQL session established using stolen credentials.
  - `TICK 7 (ACCESS_DATA):` Student PII database accessed -> Scenario objective (`obj.exfiltrate_pii`) achieved.
- **Takeaway:** Demonstrates the distinction between:
  - **ACTION:** What the attacker attempts.
  - **STATE CHANGE:** Discrete mutations applied to the authoritative state store.
  - **TELEMETRY:** Derivative security detection events emitted by security controls as a consequence of the simulated event.

### 4. EXECUTION PERSISTENCE
- **What it shows:** All actions, state snapshots, and causality-linked telemetry events are persisted to a portable `.scr` archive (`runs/university.scr`).
- **Takeaway:** Full simulation run is captured in an immutable artifact package containing spec, manifest, and causal events.

### 5. DETERMINISTIC REPLAY
- **What it shows:** The replayer imports the `.scr` package, initializes a clean simulation from the embedded specification, re-executes all recorded actions, and verifies bit-for-bit final state equality:
  - Ticks: 7 == 7
  - Objectives: `obj.exfiltrate_pii` matched
  - Active sessions: 1 active matched
  - Events: 15 events reproduced in identical causal order
- **Takeaway:** Complete proof of deterministic reproducibility without precomputed or faked outputs.

---

## E. Where AI Fits

Statecraft incorporates an optional **AI Action Proposer** interface (`statecraft ai` or `statecraft demo --ai`):

```text
User Natural Language
         |
         v
AI Action Proposer (NLP / Model)
         |
         v
ProposedAction (Unprivileged)
         |
         v
Statecraft Engine (Authoritative Execution)
         |
         +--> Accepted: Validates topology/creds -> Applies Effect Primitives -> Emits Telemetry
         |
         +--> Rejected: Invalid target/creds/syntax -> Returns FailureReason -> State Unchanged
         |
         v
ActionResult (Authoritative Ground Truth)
         |
         v
Human-Readable Response
```

### Demonstration Prompts:
1. **Valid Proposal:**
   - Prompt: `"Find an entry point into the network."`
   - AI Proposal: `scan(net.dmz)`
   - Engine Decision: **Accepted** -> `WEB01 [10.0.1.10]` discovered.
2. **Rejected Proposal (Prerequisite Enforcement):**
   - Prompt: `"Access student PII"`
   - AI Proposal: `access_data(asset.student_pii)`
   - Engine Decision: **Rejected — No active session on target host**
   - State Effect: **Unchanged** (Engine strictly prevented illegal data access).

---

## F. Why the Engine Remains Authoritative

In typical AI red-teaming benchmarks, the LLM often acts as both the player and the referee, leading to hallucinations (e.g. claiming root access or accessing internal subnets without valid routes or credentials).

In Statecraft:
- The AI has **zero authority**.
- The AI cannot modify state variables, forge credentials, bypass firewall rules, or mark objectives achieved.
- All actions are strictly validated against topology invariants and executed through a closed vocabulary of 12 atomic effect primitives.
- If an action violates simulation physics, the engine rejects it and state is preserved.

---

## G. Professor Q&A (Defense Preparation)

### 1. "Is this a real university network?"
> **Answer:** No. It is a synthetic reference model (`scenarios/university-network.yaml`). All hosts, IP ranges, services, and credentials exist solely as software models inside Statecraft's memory. It does not touch or scan real-world networks or live machines.

### 2. "Why simulate instead of using real virtual machines?"
> **Answer:** VM-based cyber ranges (e.g. Proxmox, VMware, Docker) are resource-heavy, slow to orchestrate, and prone to non-deterministic execution (timing jitter, race conditions, OS updates). Statecraft executes discrete, state-machine transitions in milliseconds with guaranteed mathematical determinism, making automated testing and AI evaluation reproducible.

### 3. "Where is the AI?"
> **Answer:** The AI acts as an external **Action Proposer**. It sits outside the engine and translates operator intent or tactical goals into structured `ProposedAction` objects. The AI is intentionally decoupled from simulation physics to prevent LLM hallucinations from corrupting ground truth.

### 4. "Can the AI change the state directly?"
> **Answer:** Absolutely not. The engine enforces an unprivileged boundary. The AI can only submit a `ProposedAction`. The authoritative `ActionExecutor` validates firewall rules, active sessions, and credentials before computing a `StateDelta`. If validation fails, the action is rejected and the state remains unchanged.

### 5. "How do you know replay is deterministic?"
> **Answer:** The `.scr` archive records the exact sequence of actions and initial environment seed. During replay, a fresh engine state is initialized from scratch and the recorded actions are re-executed step by step. We then perform a field-by-field equality check on final tick count, active sessions, achieved objectives, and event sequence. In our test suite and demo, replay achieves 100% bit-for-bit equality.

### 6. "What happens if an invalid action is proposed?"
> **Answer:** The engine checks prerequisites (e.g. reachability, active sessions, credentials). If any check fails, the engine returns an `ActionResult(success=False, failure_reason=...)` with an empty `StateDelta`. The tick does not advance, no state mutation occurs, and the failure reason is logged.

### 7. "What is actually novel about this architecture?"
> **Answer:** The key architectural contribution is the **strict separation of intelligence from physics**:
> 1. A closed vocabulary of 12 atomic effect primitives that prevents arbitrary state corruption.
> 2. A dual-plane observation model providing ground truth for defenders and a fog-of-war projection for attackers.
> 3. Zero-hallucination deterministic replay for automated security evaluation.

### 8. "What is simulated versus real?"
> **Answer:**
> - **Simulated:** Network routing, firewall packet filtering, TCP/service reachability, vulnerability exploitation, credential validation, privilege levels, and WAF/IDS detection alerts.
> - **Real:** The Python execution engine, static validation pipeline, state machine snapshots, SQLite persistence, `.scr` archive packaging, and deterministic replay engine.
