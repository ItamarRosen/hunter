"""Three-arm experiment orchestration: Detection (passive LLM) vs Research
(Hunter+Monitor) vs Control, across env_003_wrong_story and
env_004_cloud_identity_lotl.

Usage: python run_experiment.py [--force-regenerate-telemetry]

Steps (in order):
  1. Generate/reuse + validate three telemetry chunks: env_003 FEED,
     env_004 FEED, and an env_004 CONTROL chunk (FEED minus core_incident).
  2. Fairness gate: run the passive detector on the env_003 chunk. If it
     doesn't resolve all core_incident items, write a report explaining the
     failure and STOP -- engine/prompts/detector_system.md needs
     strengthening before env_004 is touched.
  3. Passive detection on the env_004 FEED chunk and the env_004 CONTROL
     chunk.
  4. Research (Hunter+Monitor) on env_003 -- reuses an existing scored run,
     zero new cost.
  5. Research on env_004 -- new Hunter+Monitor run.
  6. Research on the control environment, twice, under two task framings.
  7. Write runs/experiment_<timestamp>/REPORT.md covering the six requested
     outputs, a method note, and the pre-defined-evidence caveat. Then stop.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from engine import rules
from engine.collectors.generative import GenerativeEvidenceCollector
from engine.coverage import load_coverage
from engine.detection import DetectionEngine
from engine.environment import load_environment
from engine.hunter import HunterEngine
from engine.runner import write_report, write_run_artifacts
from engine.scoring import (
    grade_confabulation,
    load_rubric,
    render_coverage_matrix,
    score_detection,
    score_hunt,
)
from engine.telemetry import TelemetryGenerator, validate_chunk

ROOT = Path(__file__).parent
ENVIRONMENTS_DIR = ROOT / "environments"
RUNS_DIR = ROOT / "runs"
TELEMETRY_DIR = RUNS_DIR / "telemetry"

SCORING_MODEL = "claude-sonnet-4-6"

ENV003_NAME = "env_003_wrong_story"
ENV004_NAME = "env_004_cloud_identity_lotl"
CONTROL_NAME = "env_004_cloud_identity_lotl_control"

# Existing scored env_003 Research run -- reused at zero extra cost.
ENV003_RESEARCH_RUN = "env_003_wrong_story_20260614T145538Z"

CONTROL_FRAMING_B = "Determine whether this network is compromised, and if so how. Begin."


def get_or_generate_chunk(
    client: anthropic.Anthropic,
    environment,
    coverage: dict,
    mode: str,
    force: bool = False,
) -> tuple[Path, str, dict]:
    """Reuse the most recent validated chunk for (environment, mode) under
    runs/telemetry/, or generate + validate a new one."""
    existing = sorted(TELEMETRY_DIR.glob(f"{environment.name}_{mode}_*"))
    if existing and not force:
        run_dir = existing[-1]
        manifest = json.loads((run_dir / "manifest.json").read_text())
        if manifest["validation"]["passed"]:
            return run_dir, (run_dir / "chunk.md").read_text(), manifest

    generator = TelemetryGenerator(client, environment, coverage)
    chunk = generator.generate(mode)
    validation = validate_chunk(chunk, coverage)
    if not validation["passed"]:
        raise RuntimeError(
            f"{environment.name} {mode} chunk failed leak validation: {validation['hits']}"
        )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = TELEMETRY_DIR / f"{environment.name}_{mode}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "environment": chunk.environment,
        "mode": chunk.mode,
        "included_tags": chunk.included_tags,
        "excluded_tags": chunk.excluded_tags,
        "validation": validation,
    }
    (run_dir / "chunk.md").write_text(chunk.text)
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return run_dir, chunk.text, manifest


def run_detection(
    client: anthropic.Anthropic,
    environment,
    chunk_text: str,
    rubric: dict,
    coverage: dict,
    included_tags: list[str],
) -> dict:
    rule_hits = rules.match(environment.name, chunk_text)
    assessment = DetectionEngine(client, environment.topology).analyze(chunk_text)
    scoring = score_detection(
        client, SCORING_MODEL, rubric, assessment, coverage, environment.ground_truth, included_tags
    )
    confabulation = grade_confabulation(client, SCORING_MODEL, assessment)
    return {
        "rule_hits": [{"rule": h.rule, "match": h.match} for h in rule_hits],
        "assessment": assessment,
        "scoring": scoring,
        "confabulation": confabulation,
    }


def run_research(client: anthropic.Anthropic, environment, run_name: str, task_framing: str | None = None):
    collector = GenerativeEvidenceCollector(client, environment)
    hunter = HunterEngine(client, environment.topology, collector)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RUNS_DIR / f"{run_name}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    def write_progress(transcript: list[dict]) -> None:
        write_run_artifacts(run_dir, environment.name, collector, transcript)

    result = hunter.run(on_step=write_progress, task_framing=task_framing)
    write_report(run_dir, result.report)
    return run_dir, result.report


def score_research(client: anthropic.Anthropic, run_dir: Path, environment_dir: Path) -> dict:
    scoring = score_hunt(client, run_dir, environment_dir, model=SCORING_MODEL)
    (run_dir / "scoring.json").write_text(json.dumps(scoring, indent=2))
    (run_dir / "coverage_matrix.md").write_text(render_coverage_matrix(scoring))
    return scoring


def fairness_gate_passed(scoring: dict, rubric: dict) -> bool:
    core_ids = {item["id"] for item in rubric["items"] if item["category"] == "core_incident"}
    for entry in scoring["items"]:
        if entry["id"] in core_ids and entry["resolution"] not in (
            "resolved_with_evidence",
            "unconfirmed_guess",
        ):
            return False
    return True


def _items_by_category(scoring: dict, rubric: dict, category: str) -> list[dict]:
    ids = {item["id"] for item in rubric["items"] if item["category"] == category}
    return [e for e in scoring["items"] if e["id"] in ids]


def _resolution_summary(items: list[dict]) -> str:
    counts: dict[str, int] = {}
    for e in items:
        counts[e["resolution"]] = counts.get(e["resolution"], 0) + 1
    order = [
        "resolved_with_evidence",
        "unconfirmed_guess",
        "handled_implicitly_unstated",
        "unresolved",
        "not_encountered",
    ]
    parts = [f"{counts[r]} {r}" for r in order if counts.get(r)]
    return ", ".join(parts) if parts else "(none)"


def _decisive_evidence_used(items: list[dict]) -> list[str]:
    return [e["id"] for e in items if e["requested_decisive_evidence"] and e["cited_it"]]


def render_gate_failure_report(env003_manifest, env004_manifest, control_manifest, gate, env003_rubric) -> str:
    core_items = _items_by_category(gate["scoring"], env003_rubric, "core_incident")
    lines = [
        "# Experiment report -- STOPPED at the env_003 fairness gate",
        "",
        "The passive detector did not resolve all `core_incident` items on the",
        "env_003 chunk. Per the experiment design, `engine/prompts/detector_system.md`",
        "needs strengthening and the gate must pass before env_004 is touched.",
        "env_004 was not run.",
        "",
        "## Telemetry validation",
        "",
        "| Chunk | included | excluded | leak-probe passed |",
        "|---|---|---|---|",
        f"| env_003 feed | {len(env003_manifest['included_tags'])} | {len(env003_manifest['excluded_tags'])} | {env003_manifest['validation']['passed']} |",
        f"| env_004 feed | {len(env004_manifest['included_tags'])} | {len(env004_manifest['excluded_tags'])} | {env004_manifest['validation']['passed']} |",
        f"| env_004 control | {len(control_manifest['included_tags'])} | {len(control_manifest['excluded_tags'])} | {control_manifest['validation']['passed']} |",
        "",
        "## Fairness gate -- core_incident item resolutions",
        "",
        "| id | encountered | decisive evidence requested | cited | label correct | resolution |",
        "|---|---|---|---|---|---|",
    ]
    for e in core_items:
        lines.append(
            f"| `{e['id']}` | {e['encountered']} | {e['requested_decisive_evidence']} | "
            f"{e['cited_it']} | {e['label_correct']} | {e['resolution']} |"
        )
    lines += [
        "",
        "## Detector's submit_assessment output",
        "",
        "```json",
        json.dumps(gate["assessment"], indent=2),
        "```",
        "",
        "## Rule-matcher hits",
        "",
        "```json",
        json.dumps(gate["rule_hits"], indent=2),
        "```",
    ]
    return "\n".join(lines)


def _render_2x2(data: dict) -> str:
    env003_rubric = data["env003_rubric"]
    env004_rubric = data["env004_rubric"]

    detection_003 = _items_by_category(data["gate"]["scoring"], env003_rubric, "core_incident")
    research_003 = _items_by_category(data["env003_research_scoring"], env003_rubric, "core_incident")
    detection_004 = _items_by_category(data["env004_detection"]["scoring"], env004_rubric, "core_incident")
    research_004 = _items_by_category(data["env004_research_scoring"], env004_rubric, "core_incident")

    def cell(items: list[dict]) -> str:
        used = _decisive_evidence_used(items)
        used_str = ", ".join(f"`{i}`" for i in used) if used else "none"
        return f"{_resolution_summary(items)}<br>decisive evidence used: {used_str}"

    return "\n".join(
        [
            "## 1. 2x2 -- Detection vs Research, env_003 vs env_004",
            "",
            "Core-incident item resolutions (8 items for env_003, 3 for env_004) and which "
            "items' decisive evidence was actually requested *and* cited in the final report.",
            "",
            "| | env_003 (artifact-rich) | env_004 (identity/SaaS LOTL) |",
            "|---|---|---|",
            f"| **Detection** (passive LLM) | {cell(detection_003)} | {cell(detection_004)} |",
            f"| **Research** (Hunter+Monitor) | {cell(research_003)} | {cell(research_004)} |",
            "",
            "Per-item detail: `fairness_gate_coverage_matrix.md` and "
            "`detection_env004_coverage_matrix.md` (this directory); "
            f"`runs/{data['env003_research_run'].name}/coverage_matrix.md` and "
            f"`runs/{data['env004_research_dir'].name}/coverage_matrix.md`.",
            "",
        ]
    )


def _render_lead_vs_compromise(data: dict) -> str:
    scoring = data["env004_detection"]["scoring"]
    confab = data["env004_detection"]["confabulation"]
    by_id = {e["id"]: e for e in scoring["items"]}

    signin = by_id["compromised_account_signin"]
    persistence = by_id["oauth_app_persistence"]
    exfil = by_id["sp_data_access_exfil"]

    return "\n".join(
        [
            "## 2. env_004 detection -- surfaced the lead vs. concluded the compromise",
            "",
            "**(a) Surfaced the lead** -- did the detector's report mention the "
            "2026-05-28 ext-auditor-rwilcox sign-in (`compromised_account_signin`) at all?",
            "",
            f"- encountered: {signin['encountered']}",
            f"- cited in report: {signin['cited_it']}",
            f"- final label: {signin['final_label']!r}",
            f"- resolution: `{signin['resolution']}`",
            "",
            "**(b) Concluded the compromise** -- does the report assert, as a finding "
            "(not an open question), that this network IS compromised, naming a culprit?",
            "",
            f"- claims_compromise: {confab.get('claims_compromise')}",
            f"- culprit named: {confab.get('culprit') or '(none)'}",
            f"- rationale: {confab.get('rationale')}",
            "",
            "Cross-check on the other two core_incident items (whose decisive evidence -- "
            "`oauth_consent_grant`, `sp_data_access` -- is ON-DEMAND and therefore never "
            "present in the FEED chunk):",
            "",
            "| id | encountered | resolution | final label |",
            "|---|---|---|---|",
            f"| `oauth_app_persistence` | {persistence['encountered']} | `{persistence['resolution']}` | {persistence['final_label']!r} |",
            f"| `sp_data_access_exfil` | {exfil['encountered']} | `{exfil['resolution']}` | {exfil['final_label']!r} |",
            "",
            "`sp_data_access_exfil`'s encounter_tag (`sp_data_access`) is itself ON-DEMAND, "
            "so it is structurally `not_encountered` from a FEED-only chunk -- this is the "
            "intended signature of passive detection without collection, not a detector failure.",
            "",
        ]
    )


def _render_fp_rates(data: dict) -> str:
    env004_rubric = data["env004_rubric"]

    def fp_table(scoring: dict) -> tuple[str, list[str]]:
        items = _items_by_category(scoring, env004_rubric, "decoy") + _items_by_category(
            scoring, env004_rubric, "competing_narrative"
        )
        rows = []
        fp = 0
        for e in items:
            is_fp = e["label_correct"] is False
            fp += int(is_fp)
            rows.append(
                f"| `{e['id']}` | {e['category']} | {e['encountered']} | "
                f"{e['label_correct']} | {'**FP**' if is_fp else ''} |"
            )
        return f"{fp}/{len(items)}", rows

    env004_rate, env004_rows = fp_table(data["env004_detection"]["scoring"])
    control_rate, control_rows = fp_table(data["control_detection"]["scoring"])
    control_confab = data["control_detection"]["confabulation"]

    return "\n".join(
        [
            "## 3. Detection false-positive rate on benign twins / decoys / competing narratives",
            "",
            f"**env_004 FEED chunk** (includes the real incident): {env004_rate} decoy/competing items mislabeled.",
            "",
            "| id | category | encountered | label correct | |",
            "|---|---|---|---|---|",
            *env004_rows,
            "",
            f"**env_004 CONTROL chunk** (core_incident FEED cells removed -- only decoys + "
            f"competing narratives remain): {control_rate} mislabeled.",
            "",
            "| id | category | encountered | label correct | |",
            "|---|---|---|---|---|",
            *control_rows,
            "",
            "Chunk-level confabulation check on the CONTROL chunk (which by construction "
            "contains no core_incident evidence): does the detector still claim an active compromise?",
            "",
            f"- claims_compromise: {control_confab.get('claims_compromise')}",
            f"- culprit named: {control_confab.get('culprit') or '(none)'}",
            f"- rationale: {control_confab.get('rationale')}",
            "",
        ]
    )


def _render_env004_research(data: dict) -> str:
    scoring = data["env004_research_scoring"]
    by_id = {e["id"]: e for e in scoring["items"]}
    core_ids = [
        "compromised_account_signin",
        "oauth_app_persistence",
        "sp_data_access_exfil",
        "evidence_gap_mailitemsaccessed",
    ]

    lines = [
        "## 4. Research (Hunter+Monitor) on env_004 -- core incident result",
        "",
        "| id | encountered | decisive evidence requested | cited | label correct | resolution |",
        "|---|---|---|---|---|---|",
    ]
    for cid in core_ids:
        e = by_id[cid]
        lines.append(
            f"| `{e['id']}` | {e['encountered']} | {e['requested_decisive_evidence']} | "
            f"{e['cited_it']} | {e['label_correct']} | `{e['resolution']}` |"
        )

    persistence = by_id["oauth_app_persistence"]
    exfil = by_id["sp_data_access_exfil"]
    full_chain = (
        persistence["resolution"] == "resolved_with_evidence"
        and exfil["resolution"] == "resolved_with_evidence"
    )
    lines += [
        "",
        "**Full evidence-path requirement met** (`oauth_app_persistence` AND "
        "`sp_data_access_exfil` both `resolved_with_evidence` -- i.e. the Hunter requested "
        "and cited the ON-DEMAND `oauth_consent_grant` / `sp_data_access` evidence, not just "
        f"the FEED sign-in lead): **{full_chain}**",
        "",
        f"Run: `runs/{data['env004_research_dir'].name}/`",
        "",
    ]
    return "\n".join(lines)


def _render_confabulation(data: dict) -> str:
    def fp_summary(scoring: dict) -> str:
        items = scoring["items"]
        fp = sum(1 for e in items if e["label_correct"] is False)
        return f"{fp}/{len(items)} mislabeled"

    a_confab = data["control_a_confab"]
    b_confab = data["control_b_confab"]

    return "\n".join(
        [
            "## 5. Control confabulation across both framings",
            "",
            "Ground truth: this environment has NO incident -- both framings should "
            "ideally conclude no compromise.",
            "",
            "| Framing | claims_compromise | culprit | decoy/competing FP rate |",
            "|---|---|---|---|",
            f"| A (default: \"Begin.\") | {a_confab.get('claims_compromise')} | "
            f"{a_confab.get('culprit') or '(none)'} | {fp_summary(data['control_a_scoring'])} |",
            "| B (neutral: \"Determine whether this network is compromised, and if so "
            f"how\") | {b_confab.get('claims_compromise')} | {b_confab.get('culprit') or '(none)'} | "
            f"{fp_summary(data['control_b_scoring'])} |",
            "",
            f"**Framing A rationale**: {a_confab.get('rationale')}",
            "",
            f"**Framing B rationale**: {b_confab.get('rationale')}",
            "",
            f"Runs: `runs/{data['control_a_dir'].name}/`, `runs/{data['control_b_dir'].name}/`",
            "",
        ]
    )


def _render_method_note(data: dict) -> str:
    def chunk_row(manifest: dict, label: str) -> str:
        v = manifest["validation"]
        hits = v["hits"] if v["hits"] else "none"
        return f"| {label} | {len(manifest['included_tags'])} | {len(manifest['excluded_tags'])} | {v['passed']} | {hits} |"

    gate_core = _items_by_category(data["gate"]["scoring"], data["env003_rubric"], "core_incident")

    lines = [
        "## 6. Method note",
        "",
        "### Telemetry chunks: FEED-only, leak-validated",
        "",
        "| Chunk | included tags | excluded tags | leak-probe passed | hits |",
        "|---|---|---|---|---|",
        chunk_row(data["env003_manifest"], "env_003 feed"),
        chunk_row(data["env004_manifest"], "env_004 feed"),
        chunk_row(data["control_manifest"], "env_004 control"),
        "",
        "`included_tags` are exclusively FEED-tier per `coverage.json`; ON-DEMAND and GAP "
        "excerpts are structurally never placed in a generation prompt, so they cannot leak. "
        "`validate_chunk`'s leak-probe search is a secondary sanity check and passed (no "
        "hits) on all three chunks.",
        "",
        "### Chunk/Monitor consistency",
        "",
        "Both the telemetry generator (`engine/telemetry.py`) and the detection scorer's "
        "stand-in evidence (`score_detection` via `engine.coverage.extract_excerpts`) -- as "
        "well as the Monitor's `GenerativeEvidenceCollector` when the Hunter asks about the "
        "same tag -- all render from the *same* `ground_truth.md` table-row excerpts for a "
        "given tag, under the same `coverage.json` tier assignments, using the same model "
        "(claude-sonnet-4-6) for free-text generation. The guarantee is structural (same "
        "source-of-truth excerpt + same model + same tier membership), not a byte-for-byte "
        "diff of generated prose.",
        "",
        "### env_003 fairness gate",
        "",
        "PASSED -- all `core_incident` items resolved as `resolved_with_evidence` or "
        "`unconfirmed_guess`:",
        "",
        "| id | resolution | label correct |",
        "|---|---|---|",
    ]
    for e in gate_core:
        lines.append(f"| `{e['id']}` | `{e['resolution']}` | {e['label_correct']} |")
    lines += [
        "",
        f"Rule-matcher hits on env_003 chunk: {data['gate']['rule_hits'] or 'none'}",
        "",
    ]
    return "\n".join(lines)


CAVEAT = """## Caveat

All three arms read pre-defined evidence: the telemetry chunks are rendered from
`ground_truth.md` excerpts, and the Hunter's `collect_evidence` calls are answered by a
Monitor that improvises from the same ground truth. This experiment measures
**reasoning-vs-collection given that the evidence exists and is fetchable** -- not
real-world detection/collection feasibility (alert-pipeline coverage, log retention, API
rate limits, etc.).
"""


def render_report(data: dict) -> str:
    sections = [
        "# Three-arm experiment report",
        "",
        "Detection (passive single-pass LLM, claude-opus-4-8, no collect_evidence) vs. "
        "Research (Hunter+Monitor, same model family) vs. Control (env_004 with the core "
        "incident removed), across env_003_wrong_story (artifact-rich) and "
        "env_004_cloud_identity_lotl (identity/SaaS LOTL).",
        "",
        _render_2x2(data),
        _render_lead_vs_compromise(data),
        _render_fp_rates(data),
        _render_env004_research(data),
        _render_confabulation(data),
        _render_method_note(data),
        CAVEAT,
    ]
    return "\n".join(sections)


def main(force_regenerate_telemetry: bool = False) -> None:
    sys.stdout.reconfigure(line_buffering=True)
    load_dotenv()
    client = anthropic.Anthropic()

    env003 = load_environment(ENVIRONMENTS_DIR / ENV003_NAME)
    env003_coverage = load_coverage(ENVIRONMENTS_DIR / ENV003_NAME)
    env003_rubric = load_rubric(ENVIRONMENTS_DIR / ENV003_NAME)

    env004 = load_environment(ENVIRONMENTS_DIR / ENV004_NAME)
    env004_coverage = load_coverage(ENVIRONMENTS_DIR / ENV004_NAME)
    env004_rubric = load_rubric(ENVIRONMENTS_DIR / ENV004_NAME)

    control_env = load_environment(ENVIRONMENTS_DIR / CONTROL_NAME)
    control_rubric = load_rubric(ENVIRONMENTS_DIR / CONTROL_NAME)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    experiment_dir = RUNS_DIR / f"experiment_{timestamp}"
    experiment_dir.mkdir(parents=True, exist_ok=True)

    # --- 1. Telemetry ---
    print("=== Step 1: telemetry generation/validation ===")
    TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)
    env003_chunk_dir, env003_chunk_text, env003_manifest = get_or_generate_chunk(
        client, env003, env003_coverage, "feed", force_regenerate_telemetry
    )
    env004_chunk_dir, env004_chunk_text, env004_manifest = get_or_generate_chunk(
        client, env004, env004_coverage, "feed", force_regenerate_telemetry
    )
    control_chunk_dir, control_chunk_text, control_manifest = get_or_generate_chunk(
        client, env004, env004_coverage, "control", force_regenerate_telemetry
    )
    print(f"  env_003 feed:    {env003_chunk_dir}")
    print(f"  env_004 feed:    {env004_chunk_dir}")
    print(f"  env_004 control: {control_chunk_dir}")

    # --- 2. Fairness gate ---
    print("\n=== Step 2: env_003 fairness gate ===")
    gate = run_detection(
        client, env003, env003_chunk_text, env003_rubric, env003_coverage, env003_manifest["included_tags"]
    )
    gate["passed"] = fairness_gate_passed(gate["scoring"], env003_rubric)
    (experiment_dir / "fairness_gate.json").write_text(json.dumps(gate, indent=2))
    (experiment_dir / "fairness_gate_coverage_matrix.md").write_text(render_coverage_matrix(gate["scoring"]))
    print(f"  Fairness gate: {'PASSED' if gate['passed'] else 'FAILED'}")

    if not gate["passed"]:
        report = render_gate_failure_report(env003_manifest, env004_manifest, control_manifest, gate, env003_rubric)
        (experiment_dir / "REPORT.md").write_text(report)
        print(f"\nFairness gate FAILED -- see {experiment_dir / 'REPORT.md'}")
        print("Strengthen engine/prompts/detector_system.md and re-run before proceeding to env_004.")
        return

    # --- 3. Detection: env_004 + control chunk ---
    print("\n=== Step 3: detection on env_004 + control chunk ===")
    env004_detection = run_detection(
        client, env004, env004_chunk_text, env004_rubric, env004_coverage, env004_manifest["included_tags"]
    )
    control_detection = run_detection(
        client, env004, control_chunk_text, env004_rubric, env004_coverage, control_manifest["included_tags"]
    )
    (experiment_dir / "detection_env004.json").write_text(json.dumps(env004_detection, indent=2))
    (experiment_dir / "detection_control_chunk.json").write_text(json.dumps(control_detection, indent=2))
    (experiment_dir / "detection_env004_coverage_matrix.md").write_text(render_coverage_matrix(env004_detection["scoring"]))
    (experiment_dir / "detection_control_chunk_coverage_matrix.md").write_text(render_coverage_matrix(control_detection["scoring"]))

    # --- 4. Research: env_003 (reuse) ---
    print("\n=== Step 4: research env_003 (reusing existing scored run) ===")
    env003_research_run = RUNS_DIR / ENV003_RESEARCH_RUN
    env003_research_scoring = json.loads((env003_research_run / "scoring.json").read_text())
    print(f"  reused: {env003_research_run}")

    # --- 5. Research: env_004 (new run) ---
    print("\n=== Step 5: research env_004 (new Hunter+Monitor run) ===")
    env004_research_dir, env004_research_report = run_research(client, env004, ENV004_NAME)
    env004_research_scoring = score_research(client, env004_research_dir, ENVIRONMENTS_DIR / ENV004_NAME)
    print(f"  run: {env004_research_dir}")

    # --- 6. Research: control x2 ---
    print("\n=== Step 6: research control (x2 framings) ===")
    control_a_dir, control_a_report = run_research(client, control_env, f"{CONTROL_NAME}_framingA")
    control_a_scoring = score_research(client, control_a_dir, ENVIRONMENTS_DIR / CONTROL_NAME)
    control_a_confab = grade_confabulation(client, SCORING_MODEL, control_a_report)
    (control_a_dir / "confabulation.json").write_text(json.dumps(control_a_confab, indent=2))
    print(f"  framing A (default) run: {control_a_dir}")

    control_b_dir, control_b_report = run_research(
        client, control_env, f"{CONTROL_NAME}_framingB", task_framing=CONTROL_FRAMING_B
    )
    control_b_scoring = score_research(client, control_b_dir, ENVIRONMENTS_DIR / CONTROL_NAME)
    control_b_confab = grade_confabulation(client, SCORING_MODEL, control_b_report)
    (control_b_dir / "confabulation.json").write_text(json.dumps(control_b_confab, indent=2))
    print(f"  framing B (neutral) run: {control_b_dir}")

    # --- 7. Report ---
    print("\n=== Step 7: writing report ===")
    report_md = render_report(
        {
            "env003_manifest": env003_manifest,
            "env004_manifest": env004_manifest,
            "control_manifest": control_manifest,
            "gate": gate,
            "env003_rubric": env003_rubric,
            "env004_rubric": env004_rubric,
            "control_rubric": control_rubric,
            "env004_detection": env004_detection,
            "control_detection": control_detection,
            "env003_research_scoring": env003_research_scoring,
            "env003_research_run": env003_research_run,
            "env004_research_dir": env004_research_dir,
            "env004_research_report": env004_research_report,
            "env004_research_scoring": env004_research_scoring,
            "control_a_dir": control_a_dir,
            "control_a_report": control_a_report,
            "control_a_scoring": control_a_scoring,
            "control_a_confab": control_a_confab,
            "control_b_dir": control_b_dir,
            "control_b_report": control_b_report,
            "control_b_scoring": control_b_scoring,
            "control_b_confab": control_b_confab,
        }
    )
    (experiment_dir / "REPORT.md").write_text(report_md)
    print(f"\nExperiment complete: {experiment_dir}")
    print(f"Report: {experiment_dir / 'REPORT.md'}")


if __name__ == "__main__":
    main(force_regenerate_telemetry="--force-regenerate-telemetry" in sys.argv)
