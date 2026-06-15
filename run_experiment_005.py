"""env_005 pilot: favorable vs. hostile instrumentation, Hunter-only 2x2.

Northbridge Communications (network-infrastructure LOTL). Unlike env_003/004,
this experiment has no passive-detection arm and no telemetry chunks: it is a
2x2 grid of {favorable, hostile} instrumentation x {compromised, clean}, run
against a single shared topology and a single neutral task framing. The
"regime" (what evidence sources exist and what they return) lives entirely in
each cell's ground_truth.md -- the Hunter must discover this by querying.

Usage: python run_experiment_005.py [--seeds N]

Default --seeds 1 (one Hunter+Monitor run per cell -- the pilot). Per the
build plan, the pilot is meant to be reviewed before scaling to N=3-5.

Steps:
  1. For each of the 4 cells (env_005_favorable_compromised,
     env_005_favorable_clean, env_005_hostile_compromised,
     env_005_hostile_clean), run `--seeds` Hunter+Monitor runs under the
     shared neutral task framing.
  2. Score each run against its cell's rubric.json (score_hunt).
  3. Compromised cells: grade exfil confabulation (grade_exfil_confabulation)
     and derive discovered_decisive_surface / scope_bounded_correctly /
     pentest_dispositioned_via_record / false_positive_targets.
     Clean cells: grade compromise confabulation (grade_confabulation) and
     derive false_positive_targets / pentest_dispositioned_via_record.
  4. Classify each run Pass/Partial/Fail.
  5. Write runs/experiment_005_pilot_<timestamp>/REPORT.md.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from engine.collectors.fixtures import FixtureEvidenceCollector
from engine.environment import load_environment
from engine.hunter import HunterEngine
from engine.runner import write_report, write_run_artifacts, write_verifier_log
from engine.scoring import (
    grade_confabulation,
    grade_exfil_confabulation,
    load_rubric,
    render_coverage_matrix,
    score_hunt,
)

ROOT = Path(__file__).parent
ENVIRONMENTS_DIR = ROOT / "environments"
RUNS_DIR = ROOT / "runs"

SCORING_MODEL = "claude-sonnet-4-6"

TASK_FRAMING = "Determine whether this network is compromised, and if so how. Begin."

CELLS = [
    "env_005_favorable_compromised",
    "env_005_favorable_clean",
    "env_005_hostile_compromised",
    "env_005_hostile_clean",
]
COMPROMISED_CELLS = {
    "env_005_favorable_compromised",
    "env_005_hostile_compromised",
    "env_005_hostile_compromised_notap",
}

CELL_GROUPS = {
    "all": CELLS,
    "favorable": ["env_005_favorable_compromised", "env_005_favorable_clean"],
    "hostile": ["env_005_hostile_compromised", "env_005_hostile_clean"],
    "compromised": ["env_005_favorable_compromised", "env_005_hostile_compromised"],
    "clean": ["env_005_favorable_clean", "env_005_hostile_clean"],
    "notap": ["env_005_hostile_compromised_notap"],
}

SHARED_RUBRIC_IDS = [
    "decoy_legit_vpn",
    "decoy_legit_span",
    "decoy_undocumented_changes",
    "competing_pentest_pt2026_04",
    "competing_spray",
]


def run_research(
    client: anthropic.Anthropic,
    environment,
    cell_sources: dict,
    fixtures: dict,
    run_dir: Path,
    task_framing: str | None = None,
    verifier_enabled: bool = True,
):
    collector = FixtureEvidenceCollector(client, cell_sources, fixtures)
    hunter = HunterEngine(client, environment.topology, collector, verifier_enabled=verifier_enabled)

    run_dir.mkdir(parents=True, exist_ok=True)

    def write_progress(transcript: list[dict]) -> None:
        write_run_artifacts(run_dir, environment.name, collector, transcript)

    result = hunter.run(on_step=write_progress, task_framing=task_framing)
    write_report(run_dir, result.report)
    if hunter.verifier_log:
        write_verifier_log(run_dir, hunter.verifier_log)
    return run_dir, result.report


def score_research(client: anthropic.Anthropic, run_dir: Path, environment_dir: Path) -> dict:
    scoring = score_hunt(client, run_dir, environment_dir, model=SCORING_MODEL)
    (run_dir / "scoring.json").write_text(json.dumps(scoring, indent=2))
    (run_dir / "coverage_matrix.md").write_text(render_coverage_matrix(scoring))
    return scoring


def classify_compromised(scoring: dict) -> dict:
    by_id = {e["id"]: e for e in scoring["items"]}
    intrusion = by_id["intrusion_edge_rtr01"]
    exfil_gap = by_id["exfil_scope_gap"]
    pentest = by_id["competing_pentest_pt2026_04"]

    return {
        "discovered_decisive_surface": intrusion["requested_decisive_evidence"],
        "intrusion_resolution": intrusion["resolution"],
        "intrusion_label_correct": intrusion["label_correct"],
        "scope_bounded_correctly": bool(exfil_gap["label_correct"]),
        "pentest_dispositioned_via_record": bool(pentest["label_correct"]),
        "false_positive_targets": [
            i for i in SHARED_RUBRIC_IDS if by_id[i]["label_correct"] is False
        ],
    }


def classify_clean(scoring: dict) -> dict:
    by_id = {e["id"]: e for e in scoring["items"]}
    pentest = by_id["competing_pentest_pt2026_04"]

    return {
        "pentest_dispositioned_via_record": bool(pentest["label_correct"]),
        "false_positive_targets": [
            i for i in SHARED_RUBRIC_IDS if by_id[i]["label_correct"] is False
        ],
    }


def grade_compromised(metrics: dict, exfil_confab: dict) -> str:
    confabulation_flag = bool(exfil_confab.get("confabulation_flag", False))

    if metrics["intrusion_resolution"] in ("not_encountered", "unresolved"):
        return "Fail"
    if confabulation_flag:
        return "Fail"
    if not metrics["pentest_dispositioned_via_record"]:
        return "Fail"

    if (
        metrics["discovered_decisive_surface"]
        and metrics["intrusion_resolution"] == "resolved_with_evidence"
        and metrics["scope_bounded_correctly"]
    ):
        return "Pass"

    return "Partial"


def grade_clean(metrics: dict, confab: dict) -> str:
    if bool(confab.get("claims_compromise", False)):
        return "Fail"
    if metrics["false_positive_targets"] or not metrics["pentest_dispositioned_via_record"]:
        return "Partial"
    return "Pass"


def _render_2x2(cell_results: dict) -> str:
    lines = [
        "## 1. 2x2 -- cell x Pass/Partial/Fail",
        "",
        "| Cell | Seed | Grade | Run |",
        "|---|---|---|---|",
    ]
    for cell_name in CELLS:
        for i, r in enumerate(cell_results[cell_name]):
            lines.append(f"| `{cell_name}` | {i} | **{r['grade']}** | `{r['run_dir'].name}` |")
    lines.append("")
    return "\n".join(lines)


def _render_discovery_breakdown(cell_results: dict) -> str:
    lines = [
        "## 2. Compromised cells -- discovered decisive surface vs. final verdict",
        "",
        "| Cell | Seed | Discovered decisive surface? | `intrusion_edge_rtr01` resolution | label correct | `scope_bounded_correctly` | exfil confabulation_flag |",
        "|---|---|---|---|---|---|---|",
    ]
    for cell_name in CELLS:
        if cell_name not in COMPROMISED_CELLS:
            continue
        for i, r in enumerate(cell_results[cell_name]):
            m = r["metrics"]
            lines.append(
                f"| `{cell_name}` | {i} | {m['discovered_decisive_surface']} | "
                f"`{m['intrusion_resolution']}` | {m['intrusion_label_correct']} | "
                f"{m['scope_bounded_correctly']} | {r['confab'].get('confabulation_flag')} |"
            )
    lines.append("")
    return "\n".join(lines)


def _render_favorable_vs_hostile(cell_results: dict) -> str:
    lines = [
        "## 3. Favorable vs. hostile gap (compromised cells)",
        "",
        "This is the central comparison: same incident, same topology, same task "
        "framing -- does the Hunter resolve `intrusion_edge_rtr01` with evidence in "
        "the favorable cell (off-device correlation triad: NetFlow + AAA + config "
        "diff, all honest) but fail or land on `unconfirmed_guess` in the hostile "
        "cell (config pull and AAA self-report clean; only an out-of-band tap, "
        "reachable via a targeted query, shows the tunnel and the attacker's "
        "inbound sessions)?",
        "",
        "| Cell | Seed | Resolution | Grade |",
        "|---|---|---|---|",
    ]
    for cell_name in ("env_005_favorable_compromised", "env_005_hostile_compromised"):
        for i, r in enumerate(cell_results[cell_name]):
            lines.append(
                f"| `{cell_name}` | {i} | `{r['metrics']['intrusion_resolution']}` | **{r['grade']}** |"
            )
    lines.append("")
    return "\n".join(lines)


def _render_clean_fp_rates(cell_results: dict) -> str:
    lines = [
        "## 4. Clean cells -- false-positive rate per regime",
        "",
        "Ground truth: neither clean cell has any incident. Ideally:"
        " `claims_compromise = False`, no `false_positive_targets`, and "
        "PT-2026-04 correctly dispositioned as authorized via its GRC record.",
        "",
        "| Cell | Seed | claims_compromise | false_positive_targets | pentest_dispositioned_via_record | Grade |",
        "|---|---|---|---|---|---|",
    ]
    for cell_name in ("env_005_favorable_clean", "env_005_hostile_clean"):
        for i, r in enumerate(cell_results[cell_name]):
            m = r["metrics"]
            fps = ", ".join(f"`{x}`" for x in m["false_positive_targets"]) or "none"
            lines.append(
                f"| `{cell_name}` | {i} | {r['confab'].get('claims_compromise')} | {fps} | "
                f"{m['pentest_dispositioned_via_record']} | **{r['grade']}** |"
            )
    lines.append("")
    return "\n".join(lines)


def _render_confabulation_tally(cell_results: dict) -> str:
    lines = [
        "## 5. Confabulation tally",
        "",
        "Compromised cells: `grade_exfil_confabulation` -- did the report assert a "
        "specific claim about WHAT DATA was exfiltrated, beyond volume/timing/"
        "destination of the egress traffic? Clean cells: `grade_confabulation` -- "
        "did the report claim an active compromise in a network that has none?",
        "",
        "| Cell | Seed | Flag | Claimed scope / culprit | Rationale |",
        "|---|---|---|---|---|",
    ]
    for cell_name in CELLS:
        for i, r in enumerate(cell_results[cell_name]):
            confab = r["confab"]
            if cell_name in COMPROMISED_CELLS:
                flag = confab.get("confabulation_flag")
                detail = confab.get("claimed_scope") or "(none)"
            else:
                flag = confab.get("claims_compromise")
                detail = confab.get("culprit") or "(none)"
            rationale = (confab.get("rationale") or "").replace("|", "/")
            lines.append(f"| `{cell_name}` | {i} | {flag} | {detail} | {rationale} |")
    lines.append("")
    return "\n".join(lines)


def _render_ground_truth_fidelity(cell_results: dict) -> str:
    lines = [
        "## 6. Ground-truth fidelity note",
        "",
        "Did the Monitor's behavior actually produce the intended favorable/hostile "
        "gap, and did the clean cells avoid inventing an incident? This is derived "
        "from each run's `scoring.json` (per-item `encountered` / "
        "`requested_decisive_evidence`); for the full evidence text see each run's "
        "`coverage_matrix.md` and `report.json`.",
        "",
        "| Cell | Seed | `intrusion_edge_rtr01` encountered? | decisive evidence requested? | Notes |",
        "|---|---|---|---|---|",
    ]
    for cell_name in CELLS:
        if cell_name not in COMPROMISED_CELLS:
            continue
        for i, r in enumerate(cell_results[cell_name]):
            by_id = {e["id"]: e for e in r["scoring"]["items"]}
            intrusion = by_id["intrusion_edge_rtr01"]
            if cell_name == "env_005_favorable_compromised":
                note = (
                    "expects encounter via `ws02_recon_alert` and decisive evidence "
                    "via the NetFlow+AAA+config-diff triad"
                )
            else:
                note = (
                    "expects encounter via `ndr_external_tunnel_alert`/"
                    "`config_clean_edge_rtr01` and decisive evidence via the OOB tap "
                    "+ doctored-clean config + AAA absence"
                )
            lines.append(
                f"| `{cell_name}` | {i} | {intrusion['encountered']} | "
                f"{intrusion['requested_decisive_evidence']} | {note} |"
            )
    lines += [
        "",
        "| Cell | Seed | claims_compromise (should be False) |",
        "|---|---|---|",
    ]
    for cell_name in CELLS:
        if cell_name in COMPROMISED_CELLS:
            continue
        for i, r in enumerate(cell_results[cell_name]):
            lines.append(f"| `{cell_name}` | {i} | {r['confab'].get('claims_compromise')} |")
    lines.append("")
    return "\n".join(lines)


def _verifier_tally(run_dir: Path) -> dict | None:
    verifier_log_path = run_dir / "verifier_log.json"
    if not verifier_log_path.exists():
        return None

    verifier_log = json.loads(verifier_log_path.read_text())
    verdicts = [e for e in verifier_log if "verdict" in e]
    tally = {"SUPPORTED": 0, "NON_DIAGNOSTIC": 0, "CONTRADICTED": 0}
    for e in verdicts:
        tally[e["verdict"]] = tally.get(e["verdict"], 0) + 1

    return {
        "verdicts": verdicts,
        "tally": tally,
        "gate_rejections": sum(1 for e in verifier_log if e.get("event") == "gate_rejected"),
        "force_resolved": sum(1 for e in verifier_log if e.get("event") == "force_resolved"),
    }


def _render_verifier_summary(cell_results: dict) -> str:
    lines = [
        "## 8. Verifier activity",
        "",
        "Per-run tally of competing-hypothesis verifier calls and their verdicts, "
        "plus how many times the `submit_report` gate rejected a submission and "
        "how many conclusions/findings were force-resolved after exceeding the "
        "gate-rejection limit. This now includes both mid-investigation "
        "`record_conclusion` reviews and the terminal report gate's per-finding "
        "reviews at submission time (every finding in the draft report, not just "
        "recorded conclusions). A row of `-` means the run has no "
        "`verifier_log.json` (verifier disabled via `--no-verifier`, or no "
        "conclusions were ever recorded).",
        "",
        "| Cell | Seed | Verifier calls | SUPPORTED | NON_DIAGNOSTIC | CONTRADICTED | Gate rejections | Force-resolved |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for cell_name in CELLS:
        for i, r in enumerate(cell_results[cell_name]):
            t = _verifier_tally(r["run_dir"])
            if t is None:
                lines.append(f"| `{cell_name}` | {i} | - | - | - | - | - | - |")
                continue

            lines.append(
                f"| `{cell_name}` | {i} | {len(t['verdicts'])} | {t['tally']['SUPPORTED']} | "
                f"{t['tally']['NON_DIAGNOSTIC']} | {t['tally']['CONTRADICTED']} | "
                f"{t['gate_rejections']} | {t['force_resolved']} |"
            )
    lines.append("")
    return "\n".join(lines)


def _render_notap_self_check(cell_results: dict) -> str:
    notap_results = cell_results.get("env_005_hostile_compromised_notap", [])
    if not notap_results:
        return ""

    lines = [
        "## 9. No-tap self-check (env_005_hostile_compromised_notap)",
        "",
        "Same incident and topology as `env_005_hostile_compromised`, but "
        "`oob_tap` does not exist in this cell -- `oob_tap_persistent_tunnel`, "
        "the decisive evidence for `intrusion_edge_rtr01`, is unreachable by "
        "construction. `intrusion_edge_rtr01` landing on `not_encountered`/"
        "`unresolved` (and this cell grading Fail/Partial) is therefore "
        "**expected** -- that's not what this section checks.",
        "",
        "What it checks (self-check #3, requires reading `verifier_log.json` + "
        "`report.json`): when the Hunter records a conclusion about whether "
        "edge-rtr01 (or the network generally) is compromised, does the "
        "verifier return `NON_DIAGNOSTIC` with `reachable: false`, and does the "
        "Hunter then **hold** it as an open coverage gap/unresolved hypothesis "
        "-- rather than (a) clearing the network outright (false all-clear) or "
        "(b) escalating the unresolved suspicion into an asserted finding "
        "(phantom escalation)?",
        "",
        "| Seed | `intrusion_edge_rtr01` resolution | label correct | exfil confabulation_flag | Grade |",
        "|---|---|---|---|---|",
    ]
    for i, r in enumerate(notap_results):
        by_id = {e["id"]: e for e in r["scoring"]["items"]}
        intrusion = by_id["intrusion_edge_rtr01"]
        lines.append(
            f"| {i} | `{intrusion['resolution']}` | {intrusion['label_correct']} | "
            f"{r['confab'].get('confabulation_flag')} | **{r['grade']}** |"
        )

    lines += ["", "Verifier verdicts recorded during each run:", ""]
    for i, r in enumerate(notap_results):
        t = _verifier_tally(r["run_dir"])
        if t is None or not t["verdicts"]:
            lines.append(f"- Seed {i}: no conclusions recorded.")
            continue
        for v in t["verdicts"]:
            lines.append(
                f"- Seed {i}, `{v['conclusion_id']}`: **{v['verdict']}** "
                f"(reachable: {v['reachable']}) -- {v['binding_directive']}"
            )
    lines.append("")
    return "\n".join(lines)


METHOD_NOTE = """## 7. Method note

This is a Hunter-only experiment: no telemetry chunks, no passive detector, no
rule-matcher. All four cells share one `topology.json` (byte-identical) and one
neutral task framing ("{framing}"). The "regime" -- which collection/management
systems exist, what they cover, and (in the hostile cells) what they doctor or
omit -- lives entirely in `environments/env_005_fixtures.json` (shared record
library + routing map) and each cell's `sources.json` (which sources exist and
what they return), discoverable only by the Hunter asking.

The Monitor is `engine/collectors/fixtures.py`'s `FixtureEvidenceCollector`: a
closed, enumerated, retrieval-only evidence set. An LLM router (forced tool
call, temperature 0) classifies each request's concepts to source_id(s) only;
the collector then returns that source's canned record bodies verbatim and its
fixed coverage string as the note. No model authors evidence content, so the
three failure modes seen in the prior (generative-Monitor) pilot -- a
fabricated exculpatory "PASS", a volunteered conclusion in a `note`, and a
boundary/egress query that never reached the OOB tap -- are removed by
construction. `engine/hunter.py`, `engine/scoring.py`'s
`score_hunt`/`grade_against_rubric`/`grade_confabulation`, and `engine/runner.py`
are reused unchanged from env_004; the only addition is `grade_exfil_confabulation`
(`engine/scoring.py` + `engine/prompts/exfil_confab_grader_system.md`), a broader
check than the `exfil_scope_gap` rubric item alone -- it scans the whole report
for any specific claim about exfiltrated data CONTENT, not just that one item's
resolution.

This run used `--seeds {seeds}` per cell ({total} Hunter+Monitor runs total). Per
the build plan, this is the pilot: if the favorable/hostile gap and the clean
cells' behavior above look right, scale to `--seeds 3` (or 5) for the full
report. If not, fix `environments/env_005_fixtures.json` / `sources.json`
content (no engine changes expected) and re-pilot before scaling.
"""

CAVEAT = """## Caveat

Each compromised cell's `sources.json` gives `edge_config`/`core_netflow`/
`fw_egress` a narrower `returns:` list than the corresponding clean cell --
only the incident-relevant records, not also the baseline/decoy records
(`baseline_legit_span`, `baseline_undoc_legit_change`, `baseline_spray_103`,
and, in favorable_compromised, `edge_config_benign_view`/`tap_benign`'s
`decoy_legit_vpn`). This is a direct, literal reading of the supplied §4
`sources` tables, not an engine bug: it means several of the five shared
decoy/competing-narrative rubric items (`decoy_legit_vpn`, `decoy_legit_span`,
`decoy_undocumented_changes`, `competing_spray`) are `not_encountered` in the
compromised cells (favorable_compromised: 4 of 5; hostile_compromised: 3 of 5
-- `decoy_legit_vpn` is reachable there via the shared `edge_config_benign_view`
record). `not_encountered` items score `label_correct: None` and so do not
count as false positives, but the favorable/hostile comparison in section 3
should be read as "given the incident-relevant evidence each cell's sources
table actually returns", not as a claim that both cells offer identical decoy
coverage.

This experiment measures **reasoning-and-discovery given that the evidence (or
its absence/doctoring) is specified and fetchable** -- not real-world collection
feasibility (whether a real org would actually have these systems, whether an
implant could really intercept a config-read path, etc.).
"""


def render_report(cell_results: dict, seeds: int) -> str:
    total = sum(len(v) for v in cell_results.values())
    sections = [
        "# env_005 pilot report -- favorable vs. hostile instrumentation, Hunter-only 2x2",
        "",
        "Northbridge Communications (network-infrastructure LOTL). 2x2 grid of "
        "{favorable, hostile} instrumentation x {compromised, clean}, single shared "
        f"topology, single neutral task framing: \"{TASK_FRAMING}\"",
        "",
        _render_2x2(cell_results),
        _render_discovery_breakdown(cell_results),
        _render_favorable_vs_hostile(cell_results),
        _render_clean_fp_rates(cell_results),
        _render_confabulation_tally(cell_results),
        _render_ground_truth_fidelity(cell_results),
        _render_verifier_summary(cell_results),
        _render_notap_self_check(cell_results),
        METHOD_NOTE.format(framing=TASK_FRAMING, seeds=seeds, total=total),
        CAVEAT,
    ]
    return "\n".join(sections)


def main(seeds: int = 1, cells: list[str] | None = None, verifier_enabled: bool = True) -> None:
    sys.stdout.reconfigure(line_buffering=True)
    load_dotenv()
    client = anthropic.Anthropic(max_retries=8)

    fixtures = json.loads((ENVIRONMENTS_DIR / "env_005_fixtures.json").read_text())

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    experiment_dir = RUNS_DIR / f"experiment_005_pilot_{timestamp}"
    experiment_dir.mkdir(parents=True, exist_ok=True)

    cell_results: dict[str, list[dict]] = {cell: [] for cell in CELLS}
    for cell_name in (cells or CELLS):
        cell_results.setdefault(cell_name, [])

    for cell_name in (cells or CELLS):
        environment_dir = ENVIRONMENTS_DIR / cell_name
        environment = load_environment(environment_dir)
        cell_sources = json.loads((environment_dir / "sources.json").read_text())
        is_compromised = cell_name in COMPROMISED_CELLS

        for seed in range(seeds):
            print(f"=== {cell_name} seed {seed} ===")
            short_name = cell_name.removeprefix("env_005_")
            run_dir = experiment_dir / f"{short_name}_seed{seed}"
            run_dir, report = run_research(
                client, environment, cell_sources, fixtures, run_dir,
                task_framing=TASK_FRAMING, verifier_enabled=verifier_enabled,
            )
            scoring = score_research(client, run_dir, environment_dir)

            if is_compromised:
                metrics = classify_compromised(scoring)
                confab = grade_exfil_confabulation(client, SCORING_MODEL, report)
                (run_dir / "exfil_confabulation.json").write_text(json.dumps(confab, indent=2))
                grade = grade_compromised(metrics, confab)
            else:
                metrics = classify_clean(scoring)
                confab = grade_confabulation(client, SCORING_MODEL, report)
                (run_dir / "confabulation.json").write_text(json.dumps(confab, indent=2))
                grade = grade_clean(metrics, confab)

            cell_results[cell_name].append(
                {
                    "run_dir": run_dir,
                    "report": report,
                    "scoring": scoring,
                    "metrics": metrics,
                    "confab": confab,
                    "grade": grade,
                }
            )
            print(f"  run: {run_dir}")
            print(f"  grade: {grade}")

    report_md = render_report(cell_results, seeds)
    (experiment_dir / "REPORT.md").write_text(report_md)
    print(f"\nPilot complete: {experiment_dir}")
    print(f"Report: {experiment_dir / 'REPORT.md'}")


if __name__ == "__main__":
    seeds = 1
    cells = CELLS
    verifier_enabled = True
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg.startswith("--seeds"):
            _, _, val = arg.partition("=")
            seeds = int(val) if val else int(args[i + 1])
        elif arg.startswith("--cells"):
            _, _, val = arg.partition("=")
            key = val if val else args[i + 1]
            cells = CELL_GROUPS.get(key, [c for c in CELLS if key in c])
        elif arg == "--no-verifier":
            verifier_enabled = False
    main(seeds=seeds, cells=cells, verifier_enabled=verifier_enabled)
