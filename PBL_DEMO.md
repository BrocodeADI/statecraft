# Statecraft PBL Demonstration Script (3–5 Minutes)

This script provides an exact, step-by-step walkthrough for demonstrating the Statecraft Day-1 MVP during a PBL / MTE presentation.

---

## 1. Problem / Motivation (30 Seconds)
**Presenter Speaking Points:**
> "Cyber ranges and security simulations suffer from three fundamental problems:
> 1. They are heavy, fragile, and slow VM-based environments that are hard to orchestrate.
> 2. They lack deterministic reproducibility—running the same scenario twice often yields divergent outcomes.
> 3. Emerging LLM security evaluations hallucinate transitions or bypass real-world physical and network constraints because the model acts as both agent and referee.
>
> Statecraft solves this by separating **intelligence** from **physics**. Statecraft is an authoritative, deterministic cyber simulation engine. The engine owns ground truth, enforces strict network topology and credential invariants, and guarantees bit-for-bit replayability."

---

## 2. Statecraft Architecture Overview (30 Seconds)
**Presenter Speaking Points:**
> "Statecraft is built on a layered pipeline:
> - **EnvironmentSpec:** A declarative YAML format modeling topologies, firewalls, credentials, and data assets.
> - **Validation Pipeline:** A 6-stage fail-fast static analyzer verifying network integrity before execution begins.
> - **Authoritative State Engine:** An immutable snapshot store (`StateStore`) where actions can only mutate state through a closed vocabulary of 12 validated effect primitives.
> - **Telemetry & Fog of War:** A dual-plane model where full ground truth is logged to an append-only event log, while attackers receive a strictly filtered observation plane."

---

## 3. Load & Inspect Scenario (30 Seconds)
**Action:** Show the scenario configuration and inspect its structure.
```bash
statecraft show scenarios/university-network.yaml
```

**Presenter Speaking Points:**
> "Here we load our reference target: `scenarios/university-network.yaml`—Midland University Network.
> - Notice the segmentation: an external Internet boundary, a DMZ network hosting `WEB01` running an HTTP and application service, and an internal network with the database `DB01` holding student PII.
> - The firewall rules allow external traffic into the web server, but restrict internal database access strictly to `WEB01`."

---

## 4. Validate Scenario (30 Seconds)
**Action:** Run the static validation pipeline.
```bash
statecraft validate scenarios/university-network.yaml
```

**Presenter Speaking Points:**
> "Before a single tick executes, Statecraft runs a 6-stage validation pipeline:
> 1. Schema check
> 2. Referential integrity check
> 3. Network graph & CIDR overlap check
> 4. Reachability check
> 5. Capability check
> 6. Trust cycle detection
>
> If any rule references a non-existent host or an invalid subnet, the simulator refuses to start. All checks passed in milliseconds."

---

## 5. Run Attack Simulation (60 Seconds)
**Action:** Execute the automated attack simulation and export the run artifact.
```bash
statecraft run --scenario scenarios/university-network.yaml --out runs/university.scr
```

**Presenter Speaking Points:**
> "Now we run the attack. The engine executes a 7-tick vertical slice:
> - **Tick 1:** The attacker scans `net.dmz`, discovering `WEB01` at `10.0.1.10`.
> - **Tick 2:** The attacker enumerates `WEB01`, finding the exposed StudentPortal application service on port 8080.
> - **Tick 3:** The attacker exploits CVE `vuln.sqli-studentportal`. Notice that the engine immediately executes two atomic primitives: harvesting the database credential (`cred.db01.app_user`) and discovering `asset.student_pii`."

---

## 6. Show Telemetry & Detection (30 Seconds)
**Presenter Speaking Points (pointing to Tick 3 output):**
> "Notice the telemetry output on Tick 3:
> `[!] DETECTION: ctrl.waf.web01 triggered: WAF rule matched: SQL injection in StudentPortal`
> Statecraft's security control engine evaluates action verbs, targets, and vulnerability classes on every tick. The Web Application Firewall detected the attack in real-time, logging a derivative security event without interrupting engine authority."

---

## 7. Show Achieved Objective (30 Seconds)
**Presenter Speaking Points (pointing to Ticks 4–7 output):**
> "In Ticks 4 through 7:
> - **Tick 4:** The attacker pivots into `net.internal` through the compromised web server.
> - **Tick 5:** Scans the internal network, revealing `DB01`.
> - **Tick 6:** Authenticates to the Postgres service using the stolen credential.
> - **Tick 7:** Calls `access_data` on `asset.student_pii`.
>
> Because the attacker now holds an active session whose user matches the asset's access control list, the objective `obj.exfiltrate_pii` is marked **ACHIEVED**."

---

## 8. Replay the Run (30 Seconds)
**Action:** Replay the generated `.scr` archive.
```bash
statecraft replay runs/university.scr
```

**Presenter Speaking Points:**
> "Statecraft bundles the entire run into a standalone archive `runs/university.scr` containing the scenario spec, execution metadata, and the complete event log.
> When we run `statecraft replay`, the engine does NOT simply echo pre-recorded terminal text. It initializes a clean state from the embedded spec, transactionally applies the exact recorded actions, and reconstructs the run from first principles."

---

## 9. Deterministic State Reproduction (30 Seconds)
**Presenter Speaking Points (pointing to replay output):**
> "Look at the verification line:
> `[*] State match verified: Replay output is bit-for-bit identical to recorded run.`
> The final state of the replayed engine matches the original run completely:
> - Identical tick count (7 ticks)
> - Identical achieved objectives (`obj.exfiltrate_pii`)
> - Identical active sessions and privilege levels
> - Exactly 15 emitted events in identical causal order."

---

## 10. Why the Engine is Authoritative (30 Seconds)
**Presenter Speaking Points:**
> "Why does this matter?
> In Statecraft, the agent (whether a script, a human, or an LLM) has **zero authority**.
> - An agent cannot declare 'I have root access.'
> - An agent cannot directly mutate state variables.
> An agent can only submit a `ProposedAction`. The authoritative engine validates prerequisites, checks firewall rules, enforces topology, and applies discrete effect primitives. If an action violates physics, it fails and state is unaffected."

---

## 11. Current Limitations & Future Scope (30 Seconds)
**Presenter Speaking Points:**
> "To maintain rigorous engineering focus for Day-1, several features are intentionally deferred:
> - Automated LLM scenario compilation and autonomous multi-agent loops.
> - Defender automated responses (e.g. dynamic host isolation).
> - Web-based topology visualization.
>
> The core simulation engine, validation pipeline, effect system, and deterministic replay engine are 100% verified, tested, and operational today."

---

## 12. Unified Demonstration Command (`statecraft demo`)

For live evaluators, the entire demonstration sequence above is orchestrated via a single command:

```bash
statecraft demo
```

This single command automatically executes:
1. Environment loading and topology inspection
2. 6-stage static validation
3. Authoritative simulation of the 7-step reference attack
4. Run export to `runs/university.scr`
5. Bit-for-bit replay verification against original state
6. Architecture guarantee and summary stats

---

## 13. AI-Assisted Mode (`statecraft ai`)

Statecraft provides an optional natural language action proposer interface that demonstrates how AI agents interact with the authoritative engine:

```text
User Natural Language
         |
         v
AI Action Proposer (RuleBasedNLP / Model)
         |
         v
ProposedAction (Unprivileged)
         |
         v
Statecraft Engine (Authoritative Execution)
         |
         v
ActionResult (Ground Truth)
         |
         v
Human-Readable Response
```

### Demonstration Commands

1. **Valid Action Proposal:**
   ```bash
   statecraft ai --prompt "Find an entry point into the university network."
   ```
   *Result:* AI translates prompt into `ProposedAction(verb=scan, target=net.dmz)`. The engine validates network topology and executes the scan, discovering `WEB01 [10.0.1.10]`.

2. **Rejected Action Proposal (Engine Authority Enforcement):**
   ```bash
   statecraft ai --prompt "Access student PII"
   ```
   *Result:* AI proposes `ProposedAction(verb=access_data, target=asset.student_pii)`. The engine checks prerequisites, identifies that no active session exists on `host.db01`, and **strictly rejects** the action with `No active session on target host`. authoritatively preventing state mutation.

3. **Interactive Mode:**
   ```bash
   statecraft ai
   ```
   *Result:* Launches an interactive session allowing continuous command exploration.

### Safety Guarantee
The AI is strictly an **Action Proposer**, NOT the simulation referee:
- The AI cannot directly edit `EnvironmentState` or create sessions.
- The AI cannot mark objectives achieved or bypass firewalls.
- The AI cannot execute arbitrary code or shell commands.
- If the AI proposes an invalid action, the engine rejects it and the state remains unchanged.

