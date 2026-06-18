# Hunter — Architecture and Invariants

Autonomous network threat-hunting agent. An LLM reasons from a network's
structure to where an intruder would have to be, then collects evidence to
confirm or rule it out — instead of pattern-matching signatures.

The central research focus is **calibration**: the agent must know when it
holds decisive proof, and must say "I can't tell" when it doesn't.

---

## Four components

### 1. Hunter (`engine/hunter.py`)

The reasoning agent. Receives only a network topology and an open task.
Ends the investigation by calling `submit_report`.

**CRITICAL INVARIANT**: the Hunter must NOT see a menu of collection
capabilities. In dispatcher mode it has exactly one collection tool:
`request_evidence(description)`, defined in `engine/evidence.py`. The
description field must be "What you want to observe or verify, in your own
investigative terms" — no protocol names, no vendor names, no data-source
names. Leaking the capability menu into the Hunter's prompt or this tool's
description corrupts the reasoning this project exists to test.

In legacy collector mode (`collect_evidence`), the Hunter also names a
`device_id`. This mode is kept for the existing research environments
(env_000–env_005).

System prompts:
- `engine/prompts/hunter_system.md` — collector mode (env_000–005)
- `engine/prompts/hunter_dispatcher_system.md` — dispatcher mode

### 2. Dispatcher (`engine/dispatcher.py`)

Translates the Hunter's free-form request to concrete protocol queries.
All collection capabilities, protocols, and data sources live here, hidden
from the Hunter.

Modes:
- **replay** — reads from `recordings/<scenario>/`; no network I/O
- **live** — (not yet implemented) queries real infrastructure

Tags every response with `trust_tier`:
- `off_device_tap` — independent vantage; highest trust
- `ssh_cli` / `snmp` — device self-reporting; medium trust
- `host_edr` / `host_agent` — local agent; lower trust

The LLM routing step (Haiku, temperature 0) selects which recording(s) from
`index.json` match the Hunter's request. This step only classifies intent;
it never authors evidence content.

### 3. Parsers (`engine/parsers/`)

One parser per protocol family. Takes raw vendor/protocol output and returns
a normalized format the Hunter can reason over directly.

Current parsers:
- `routing` — Cisco IOS `show ip route` and similar routing table output

Add a new parser by registering it in `engine/parsers/__init__.py`.

### 4. Verifier (`engine/verifier.py` + `engine/report_gate.py`)

Calibration gate. Two passes:

1. `record_conclusion` (mid-investigation) — generates the strongest
   competing explanation and returns SUPPORTED / NON_DIAGNOSTIC / CONTRADICTED
   + a `binding_directive` the Hunter must act on.

2. Terminal report gate (`submit_report`) — re-reviews every finding in the
   draft report, applies `scope_flags` to over-scoped claims, and
   force-resolves unsupported findings to `coverage_gap` after the rejection
   budget is exhausted. Never rewrites a finding to "clean" — only to an
   honest hedge.

---

## Directory layout

```
engine/
  hunter.py              Hunter agent loop
  dispatcher.py          Intent → collection routing
  evidence.py            Tool definitions + EvidenceCollector protocol
  verifier.py            Mid-investigation calibration gate
  report_gate.py         Terminal report gate
  parsers/
    __init__.py          Parser registry
    routing.py           Routing table normalizer
  collectors/
    generative.py        LLM Matcher (env_000–005, research)
    fixtures.py          Deterministic fixture collector (env_005)
    replay.py            (future: standalone replay collector)
  prompts/
    hunter_system.md              Hunter prompt, collector mode
    hunter_dispatcher_system.md   Hunter prompt, dispatcher mode
    verifier_system.md            Verifier prompt
    ...
recordings/
  <scenario>/
    index.json           Manifest: id, description, protocol, parser, trust_tier, file
    *.txt / *.json       Raw captured responses
environments/
  <name>/
    topology.json        Network map (Hunter-visible)
    ground_truth.md      Real story (never shown to Hunter)
    rubric.json          Scoring items
runs/                    Timestamped output of every run (gitignored)
run_hunt.py              Collector-mode entry point (env_000–005)
run_dispatch.py          Dispatcher-mode entry point
run_experiment_005.py    env_005 2x2 experiment runner
```

---

## Recording format (`recordings/<scenario>/index.json`)

```json
[
  {
    "id":          "edge_rtr01_routing",
    "description": "Routing table on edge-rtr01",
    "protocol":    "ssh_cli",
    "parser":      "routing",
    "target":      "edge-rtr01",
    "query":       "show ip route",
    "trust_tier":  "ssh_cli",
    "file":        "edge_rtr01_show_ip_route.txt"
  }
]
```

`parser` maps to a key in `engine/parsers/__init__.py`'s registry.
Set to `null` to return the raw text without normalization.

---

## Adding a new protocol

1. Add a raw recording file under `recordings/<scenario>/`
2. Add an entry to `recordings/<scenario>/index.json` with `"parser": "myproto"`
3. Write `engine/parsers/myproto.py` with a `parse(raw, client, model) -> str` function
4. Register it in `engine/parsers/__init__.py`

---

## Running

```bash
# Dispatcher mode (replay), single scenario
python run_dispatch.py env_006_replay_demo

# Dispatcher mode, no verifier
python run_dispatch.py env_006_replay_demo --no-verifier

# Legacy collector mode (env_000–005)
python run_hunt.py env_001_noisy
```

---

## Explicit non-goals

- Do NOT give the Hunter any collection tool besides `request_evidence`, and
  do NOT leak capability hints (protocol names, source names, vendor names)
  into its prompt or that tool's description.
- Do NOT build an automated grader. Humans grade by reading transcripts.
- Do NOT over-engineer. This is a concept-stage experiment.
