# Hunter

Hunter is a research harness for evaluating **autonomous threat-hunting
agents**: given nothing but a network's topology and a neutral task ("Determine
whether this network is compromised, and if so how. Begin."), can an LLM-driven
investigator ask the right questions, find the decisive evidence, reach the
correct verdict, and *not* invent things it can't actually support?

Each experiment pits a **Hunter** (the agent under test) against an
**Environment** — a network topology plus a hidden ground truth describing
what's really going on (an incident, decoys, competing narratives, or nothing
at all) — and scores the resulting investigation against a rubric.

## How a hunt works

Hunter runs in two modes: **collector mode** (env_000–005, legacy) and
**dispatcher mode** (env_006+, current research path).

### Dispatcher mode

1. **The Hunter** (`engine/hunter.py`) is given a network topology and a task
   framing. It investigates by repeatedly calling `request_evidence(description)`
   — phrasing requests in its own investigative terms — and ends by calling
   `submit_report(...)` with findings, confidence/severity, and open questions.
   The Hunter never sees a menu of collection capabilities, protocol names,
   vendor names, or data-source names. This is a hard invariant: leaking that
   information would corrupt the reasoning the project exists to test.

2. **The Dispatcher** (`engine/dispatcher.py`) sits between the Hunter and the
   network. It receives the Hunter's free-form request and uses a cheap routing
   model (Haiku, temperature 0) to select which collection tool(s) to invoke.
   All protocol knowledge lives here, hidden from the Hunter. Each response is
   tagged with a `trust_tier`:
   - `off_device_tap` — independent vantage; highest trust
   - `ssh_cli` / `snmp` — device self-reporting; medium trust
   - `scan_observed` — passive/active probe of externally-visible behavior
   - `host_edr` / `host_agent` — local agent; lower trust

   The Dispatcher runs in **replay** mode (reads from pre-captured recordings)
   or **live** mode (queries real infrastructure via SSH).

3. **The TopologyModel** (`engine/topology_model.py`) is a trust-tiered live
   map of the network, populated from multiple sources before the hunt begins:
   - Stage 1 scan: credential-free ARP sweep + ping + TCP port probe
     (`engine/collectors/scan.py`) → `SCAN_OBSERVED` evidence
   - Credentialed crawl: BFS from a seed device via LLDP/CDP neighbor tables
     (`engine/collectors/discovery.py`) → `DEVICE_REPORTED` evidence
   The Dispatcher exposes the model to the Hunter via a `topology_query` tool
   that returns the current snapshot (nodes, routes, ARP, neighbors) plus any
   cross-source discrepancies already detected. Devices seen in LLDP/CDP but
   not interrogable are marked `NOT_INTERROGABLE` — known coverage gaps, never
   treated as clean.

4. **Parsers** (`engine/parsers/`) normalize raw protocol output (routing
   tables, ARP caches, neighbor tables) into structured JSON the Hunter can
   reason over directly. A Haiku model handles normalization; adding a new
   protocol requires only a new parser file and a registry entry.

5. **Verification** (`engine/verifier.py` + `engine/report_gate.py`) checks
   the Hunter's reasoning against the evidence it actually collected, twice:
   - **`record_conclusion`** — when the Hunter records a working conclusion
     mid-investigation, a fresh-context verifier generates the strongest
     plausible competing explanation and judges whether the evidence
     *discriminates* between them, returning `SUPPORTED` /
     `NON_DIAGNOSTIC` / `CONTRADICTED`, a `reachable` flag (is the
     discriminating evidence even collectible here?), and a
     `binding_directive` the Hunter must act on.
   - **The terminal report gate** — at `submit_report`, every finding (not
     just ones the Hunter explicitly recorded a conclusion on) is
     independently re-reviewed the same way. Findings that don't hold up are
     force-resolved to an open `coverage_gap` — never rewritten into a false
     "clean"/"no compromise" — and claims that assert more than the evidence
     *type* supports (e.g. inferring exfiltrated *data content* from
     flow/volume evidence alone) are mechanically bounded via `scope_flags`,
     with the unsupported remainder moved to `open_questions`.

   `submit_report` is rejected — and the Hunter must revise — until every
   conclusion/finding is `SUPPORTED` or has been honestly hedged as an
   unreachable coverage gap, bounded by a gate-rejection limit so the loop
   always terminates.

### Collector mode (legacy, env_000–005)

The Hunter calls `collect_evidence(device_id, request)` directly; an
`EvidenceCollector` answers. Two implementations:
- **`GenerativeEvidenceCollector`** — an LLM "Matcher" improvises plausible
  evidence on the fly, weaving in ground-truth details where a real system
  would surface them.
- **`FixtureEvidenceCollector`** — a closed, deterministic, retrieval-only
  evidence set. An LLM router only *classifies* which canned record(s) a
  request asks about; the actual text is fixed in advance. No model ever
  authors evidence content.

**Scoring** (`engine/scoring.py`) replays `report.json`, `transcript.json`,
and `collection_log.json` against the environment's `rubric.json`. For each
rubric item it derives one of:
- `not_encountered` — never surfaced.
- `resolved_with_evidence` — surfaced, decisive evidence requested and cited,
  correct label.
- `unconfirmed_guess` — correct label reached without ever citing the decisive
  evidence (right answer, surface cues only).
- `handled_implicitly_unstated` — not named directly, but a stated general
  criterion correctly resolves it.
- `unresolved` — surfaced but mislabeled or unaddressed.

## Environments

Each `environments/<name>/` directory contains:

- `topology.json` — the network the Hunter sees: devices, segments, roles.
  Written to be strictly neutral — no hints about where an incident is or
  whether one exists at all.
- `ground_truth.md` — the real story (incident timeline, decisive-evidence
  tags, decoys/competing narratives, benign baselines). Never shown to the
  Hunter.
- `rubric.json` — scoreable items with `encounter_tags` / `decisive_evidence_tags`
  and the correct label for each.
- `answer_key.json` (dispatcher experiments) — expected verdict, failure-mode
  labels per verdict direction, plumbing checks, and research questions probed.

### Experiment catalog

| Environment | Mode | What it's testing |
|---|---|---|
| `env_000_dummy` | collector | Minimal smoke test of the Hunter loop end-to-end. |
| `env_001_noisy` | collector | A real incident buried in routine network noise. |
| `env_002_competing_narratives` | collector | Incident plus a second unrelated suspicious-looking activity stream — does the Hunter conflate them? |
| `env_003_wrong_story` | collector | Same network, louder "competing" EDR alert and decoys designed to lead toward a plausible-but-wrong conclusion. First environment with `coverage.json`/passive-detection comparison. |
| `env_004_cloud_identity_lotl` | collector | Hybrid-identity living-off-the-land intrusion (Storm-0558/Midnight Blizzard-style OAuth abuse), the *quietest* signal in the environment, competing against a zero-success password spray and an authorized pentest. Includes a `_control` variant with the incident removed. |
| `env_005_favorable_*` / `env_005_hostile_*` | collector | 2×2 (favorable vs. hostile instrumentation × compromised vs. clean) around a single edge-router intrusion. Tests whether the Hunter's conclusion changes based on evidence quality, and whether clean cells stay clean. Uses `FixtureEvidenceCollector`. |
| `env_005_hostile_compromised_notap` | collector | Ablation: identical incident but the one out-of-band tap that makes it resolvable doesn't exist. Self-check that the Hunter holds the suspicion as a coverage gap rather than producing a false all-clear or phantom escalation. |
| `env_006_replay_demo` | dispatcher | Dispatcher-mode smoke test. Recordings from a simple edge-router network; verifies the Hunter → Dispatcher → Parser pipeline end-to-end. |
| `env_exp1_a_clean` | dispatcher | **Experiment 1A** — clean three-device LAN with no anomalies. Expected verdict: `NO_FINDING`. Tests false-positive rate over the full scan → crawl → hunt pipeline. |
| `env_exp1_b_discrepancy` | dispatcher | **Experiment 1B** — same topology plus a static /32 host route to a known Tor exit node (185.220.101.50) present in `DEVICE_REPORTED` but absent from `SCAN_OBSERVED`. Expected verdict: `CAN'T_CLEAR` — the discrepancy is suspicious but indistinguishable from an admin error without an independent tap. Tests that the Hunter surfaces the anomaly at low confidence without over-claiming. |

`CHANGES.md` has the detailed, chronological design rationale for each
environment and every fix made in response to a run's results.

## Network discovery pipeline

The dispatcher-mode experiments use a two-stage discovery pipeline to populate
the TopologyModel before the hunt begins.

**Stage 1 — credential-free scan** (`run_scan.py`):
Auto-detects the local subnet and runs an ARP sweep + concurrent ping + TCP
port scan on management ports, classifying hosts as infrastructure or endpoint
by OUI and open-port signature. No credentials required; uses Python stdlib +
macOS built-ins only.

**Stage 2 — credentialed crawl** (`run_discovery.py`):
BFS from a seed device, interrogating each hop via SSH (`show ip route`,
`show ip arp`, `show lldp neighbors`, `show cdp neighbors`) and expanding via
neighbor tables. Runs in replay mode (reads pre-captured recordings) or live
mode (Netmiko SSH). Writes recordings from live runs so they can be replayed
later. Devices seen in neighbor tables but not interrogable are marked
`NOT_INTERROGABLE`.

## Running things

Setup:

```bash
poetry install
echo "ANTHROPIC_API_KEY=sk-..." > .env
```

**Dispatcher mode (current):**

```bash
# Single hunt in replay mode
python run_dispatch.py <scenario>
python run_dispatch.py env_006_replay_demo --no-verifier

# Experiment 1: 5 seeds × 2 scenarios (CLEAN vs DISCREPANCY)
python run_experiment1.py [--scenarios a,b] [--seeds N]

# Stage 1: credential-free LAN scan
python run_scan.py

# Stage 2: credentialed crawl from seed device (replay or live)
python run_discovery.py <scenario> [--seed <device_id>]
```

**Collector mode (env_000–005):**

```bash
# Run a single hunt and score it
python run_hunt.py <environment_name>
python score_hunt.py <environment_name> <run_dir_name>

# Three-arm experiment (passive detection vs. Hunter+Monitor vs. control)
python run_experiment.py [--force-regenerate-telemetry]

# env_005 favorable/hostile 2x2 (fixture-based)
python run_experiment_005.py [--seeds N] [--cells GROUP] [--no-verifier]

# Generate a telemetry chunk for the passive-detection arm
python generate_telemetry.py <environment_name> <feed|control>
```

**Tests:**

```bash
.venv/bin/python tests/test_report_gate.py
```

All runs write their artifacts (transcript, collection log, report, and when
the verifier is enabled, `verifier_log.json`) to
`runs/<environment_name>_<timestamp>/` or `runs/experiment1/<scenario>/seed_NN/`.

## Repo layout

```
engine/
  hunter.py          Hunter agent loop (request_evidence / submit_report)
  dispatcher.py      Intent → collection routing; hides all protocol knowledge
                      from the Hunter
  evidence.py        EvidenceCollector protocol, shared types
  topology_model.py  Trust-tiered live map: SCAN_OBSERVED + DEVICE_REPORTED;
                      snapshot(), discrepancies(), not_interrogable_nodes()
  verifier.py        Competing-hypothesis verifier (record_conclusion review)
  report_gate.py     Terminal report gate: per-finding re-review + scope_flags
                      at submit_report, with bounded forced resolution
  collectors/
    generative.py    LLM "Matcher" evidence collector (collector mode)
    fixtures.py      Deterministic fixture evidence collector (env_005)
    discovery.py     Credentialed BFS crawl: TopologyCrawl (replay + live)
    scan.py          Stage 1 credential-free scanner (ARP/ping/TCP port probe)
  parsers/
    __init__.py      Parser registry
    routing.py       Cisco IOS routing table normalizer
  detection.py       Passive single-pass detector (no collect_evidence)
  telemetry.py       Telemetry chunk generation for the detection arm
  rules.py           Cheap regex IoC rule-matcher (fairness-gate check)
  scoring.py         Rubric grading + confabulation graders
  coverage.py        FEED/ON-DEMAND tag bookkeeping
  environment.py     Loads topology.json + ground_truth.md
  runner.py          Shared run-artifact writing
  render.py          Investigation-log rendering
  prompts/           All system prompts (Hunter, Dispatcher, Matcher, verifier,
                      graders, router)
environments/        One directory per environment (topology, ground truth,
                      rubric, answer key, ...)
recordings/          Pre-captured device responses for replay mode, organized
                      as recordings/<scenario>/ssh_cli/<device>/<command>.txt
                      and recordings/<scenario>/scan/result.json
runs/                Timestamped output of every hunt/experiment/scoring run
tests/               Plain-assert test scripts (no pytest)
run_hunt.py          Collector-mode entry point (env_000–005)
run_dispatch.py      Dispatcher-mode entry point (single hunt)
run_scan.py          Stage 1: credential-free LAN scan
run_discovery.py     Stage 2: credentialed BFS crawl
run_experiment.py    Three-arm experiment (env_003/004)
run_experiment_005.py  env_005 2×2 experiment
run_experiment1.py   Experiment 1: dispatcher-mode hunt over scanned topology
score_hunt.py        Post-hoc rubric scoring
generate_telemetry.py  Telemetry chunk generation
CHANGES.md           Chronological log of environment design fixes and why
```

## License

MIT — see [LICENSE](LICENSE).
