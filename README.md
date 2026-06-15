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

1. **The Hunter** (`engine/hunter.py`) is given a network topology and a task
   framing. It investigates by repeatedly calling `collect_evidence(device_id,
   request)` — phrasing requests the way a skilled analyst would — and ends by
   calling `submit_report(...)` with findings, confidence/severity, and open
   questions.
2. **An Evidence Collector** (`engine/evidence.py`'s `EvidenceCollector`
   protocol) answers each `collect_evidence` call. Two implementations exist:
   - **`GenerativeEvidenceCollector`** (`engine/collectors/generative.py`) — an
     LLM "Matcher" seeded with the topology and the Hunter-hidden ground truth.
     It improvises plausible evidence on the fly, weaving in ground-truth
     details where a real system would surface them.
   - **`FixtureEvidenceCollector`** (`engine/collectors/fixtures.py`) — a
     closed, deterministic, retrieval-only evidence set. An LLM router
     (forced tool call, temperature 0) only *classifies* which canned record(s)
     a request is asking about; the actual record text is fixed in advance in
     `environments/env_005_fixtures.json` and each cell's `sources.json`. No
     model ever authors evidence content, which removes a whole class of
     Matcher-side confabulation/leak failure modes.
3. **Verification** (`engine/verifier.py` + `engine/report_gate.py`) checks the
   Hunter's reasoning against the evidence it actually collected, twice:
   - **`record_conclusion`** — when the Hunter records a working conclusion
     mid-investigation, a fresh-context verifier model generates the strongest
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
4. **Scoring** (`engine/scoring.py`) replays `report.json`, `transcript.json`,
   and `collection_log.json` against the environment's `rubric.json`. For each
   rubric item it derives one of:
   - `not_encountered` — never surfaced.
   - `resolved_with_evidence` — surfaced, decisive evidence requested and
     cited, correct label.
   - `unconfirmed_guess` — correct label reached without ever requesting/citing
     the decisive evidence (right answer, surface cues only).
   - `handled_implicitly_unstated` — not named directly, but a stated general
     criterion correctly resolves it.
   - `unresolved` — surfaced but mislabeled or unaddressed.

   Separate graders check for **confabulation**: `grade_confabulation` (did a
   clean environment get accused of a compromise that doesn't exist?) and
   `grade_exfil_confabulation` (did the report assert specific *exfiltrated
   data content* beyond what the available evidence — volume/timing/
   destination — could support?).

## Environments

Each `environments/<name>/` directory contains:

- `topology.json` — the network the Hunter sees: devices, segments, roles.
  Written to be strictly neutral — no hints about where an incident is or
  whether one exists at all.
- `ground_truth.md` — the real story (incident timeline, decisive-evidence
  tags, decoys/competing narratives, benign baselines). Never shown to the
  Hunter directly; only surfaced through evidence collector responses.
- `rubric.json` — scoreable items (core incident, decoys, competing
  narratives, evidence gaps) with `encounter_tags` / `decisive_evidence_tags`
  and the correct label for each.
- `coverage.json` (env_003/004) — maps ground-truth tags to FEED (always
  visible in a telemetry chunk) vs. ON-DEMAND (only via `collect_evidence`),
  for the passive-detection experiments.
- `sources.json` (env_005 cells) — per-cell table of which evidence sources
  exist, what they cover, and what records they return; paired with the
  shared `env_005_fixtures.json` record library + routing map.

### Experiment catalog

| Environment | What it's testing |
|---|---|
| `env_000_dummy` | Minimal smoke test of the Hunter loop end-to-end. |
| `env_001_noisy` | A real incident buried in routine network noise. |
| `env_002_competing_narratives` | Incident plus a second, unrelated suspicious-looking activity stream — does the Hunter conflate them? |
| `env_003_wrong_story` | Same network, with a louder "competing" EDR alert and decoys designed to lead toward a plausible-but-wrong conclusion. Also the first environment with `coverage.json`/`rubric.json` for passive-detection comparison. |
| `env_004_cloud_identity_lotl` | A hybrid-identity (on-prem AD + Entra ID/M365) living-off-the-land intrusion (Storm-0558/Midnight Blizzard-style OAuth abuse) that is deliberately the *quietest* signal in the environment, competing against a zero-success password spray and an authorized pentest. Includes a `_control` variant with the incident removed entirely. |
| `env_005_favorable_*` / `env_005_hostile_*` | A 2x2 (favorable vs. hostile instrumentation x compromised vs. clean) around a single Northbridge Communications network/edge-router intrusion. Tests whether the Hunter's conclusion changes when the *same* incident is correlatable via clean off-device telemetry (favorable) vs. only via a doctored/self-reporting device plus one out-of-band tap (hostile) — and whether clean cells stay clean. Uses the deterministic `FixtureEvidenceCollector`. |
| `env_005_hostile_compromised_notap` | Ablation of `env_005_hostile_compromised`: identical incident and topology, but the one out-of-band tap that makes the intrusion resolvable doesn't exist — the decisive evidence is unreachable by construction. Self-check for whether the Hunter (and the verifier/report gate) correctly hold the unresolved suspicion as an open coverage gap rather than producing a false all-clear or a phantom escalation. |

`CHANGES.md` has the detailed, chronological design rationale for each
environment and every fix made in response to a run's results.

## Running things

Setup:

```bash
poetry install
echo "ANTHROPIC_API_KEY=sk-..." > .env
```

Run a single hunt (generative Matcher) and score it:

```bash
python run_hunt.py <environment_name>
python score_hunt.py <environment_name> <run_dir_name>
```

Run the three-arm experiment (passive detection vs. Hunter+Monitor vs.
control) across env_003/env_004:

```bash
python run_experiment.py [--force-regenerate-telemetry]
```

Run the env_005 favorable/hostile 2x2 (fixture-based Monitor):

```bash
python run_experiment_005.py [--seeds N] [--cells GROUP] [--no-verifier]
# --seeds N    number of seeds per cell (default 1, pilot)
# --cells      "all" (default), "favorable", "hostile", "compromised",
#               "clean", or "notap" (env_005_hostile_compromised_notap)
# --no-verifier  disable the competing-hypothesis verifier/report gate
```

Generate a telemetry chunk for the passive-detection arm:

```bash
python generate_telemetry.py <environment_name> <feed|control>
```

All runs write their artifacts (transcript, collection log, investigation log,
report, scoring, coverage matrix, and — when the verifier is enabled —
`verifier_log.json`) to `runs/<environment_name>_<timestamp>/`, and experiment
scripts write a `REPORT.md` summarizing the run.

Run the test suite (plain `assert`-based scripts, no pytest):

```bash
.venv/bin/python tests/test_report_gate.py
```

## Repo layout

```
engine/
  hunter.py          Hunter agent loop (collect_evidence / submit_report)
  evidence.py        EvidenceCollector protocol, shared types
  verifier.py        Competing-hypothesis verifier (record_conclusion review)
  report_gate.py     Terminal report gate: per-finding re-review + scope_flags
                      at submit_report, with bounded forced resolution
  collectors/
    generative.py    LLM "Matcher" evidence collector
    fixtures.py      Deterministic fixture evidence collector (env_005)
  detection.py       Passive single-pass detector (no collect_evidence)
  telemetry.py       Telemetry chunk generation for the detection arm
  rules.py           Cheap regex IoC rule-matcher (fairness-gate check)
  scoring.py         Rubric grading + confabulation graders
  coverage.py        FEED/ON-DEMAND tag bookkeeping
  environment.py     Loads topology.json + ground_truth.md
  runner.py          Shared run-artifact writing
  render.py          Investigation-log rendering
  prompts/           All system prompts (Hunter, Matcher, detector, verifier,
                      graders, router)
environments/        One directory per environment (topology, ground truth, rubric, ...)
runs/                Timestamped output of every hunt/experiment/scoring run
tests/               Plain-assert test scripts (no pytest); run via
                      `.venv/bin/python tests/test_*.py`
run_hunt.py, run_experiment*.py, score_hunt.py, generate_telemetry.py
  Composition roots / CLI entry points
CHANGES.md           Chronological log of environment design fixes and why
```

## License

MIT — see [LICENSE](LICENSE).
