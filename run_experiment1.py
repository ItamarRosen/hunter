"""Experiment 1: First end-to-end hunt over scanned topology.

Two scenarios, 5 seeds each, cheap-tier Hunter (Haiku).
Writes full transcripts to runs/experiment1/<scenario>/seed_<N>/.
Prints a per-seed verdict table and flags plumbing vs judgment problems.

Usage:
  python run_experiment1.py [--scenarios a,b] [--seeds N]
  python run_experiment1.py --scenarios a      # scenario A only
  python run_experiment1.py --seeds 1          # quick smoke test
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from engine.collectors.discovery import TopologyCrawl
from engine.dispatcher import Dispatcher
from engine.hunter import HunterEngine
from engine.topology_model import TopologyEvidence, TopologyModel

ROOT             = Path(__file__).parent
ENVIRONMENTS_DIR = ROOT / "environments"
RECORDINGS_DIR   = ROOT / "recordings"
RUNS_DIR         = ROOT / "runs" / "experiment1"

# Cheap tier: integration check, not a quality run.
HUNTER_MODEL   = "claude-haiku-4-5-20251001"
VERIFIER_MODEL = "claude-haiku-4-5-20251001"
PARSER_MODEL   = "claude-haiku-4-5-20251001"

TASK_FRAMING = (
    "Network topology data has been collected via active scanning and device interrogation. "
    "Determine whether this network shows signs of compromise or unauthorized configuration. "
    "Begin."
)

SCENARIOS: dict[str, dict] = {
    "env_exp1_a_clean": {
        "label": "A — CLEAN",
        "expected": "NO_FINDING",
    },
    "env_exp1_b_discrepancy": {
        "label": "B — DISCREPANCY",
        "expected": "CAN'T_CLEAR",
    },
}


# ------------------------------------------------------------------
# TopologyModel bootstrap
# ------------------------------------------------------------------

def build_topo_model(
    client: anthropic.Anthropic,
    scenario_name: str,
    topology: dict,
) -> TopologyModel:
    """Pre-populate TopologyModel from scenario recordings (scan + crawl)."""
    model = TopologyModel(static_topology=topology)

    # Stage 1: load scan evidence.
    scan_path = RECORDINGS_DIR / scenario_name / "scan" / "result.json"
    if scan_path.exists():
        nodes = json.loads(scan_path.read_text())
        model.update(TopologyEvidence(
            device_id=f"scan:{scenario_name}",
            command="ping_sweep+arp+port_scan",
            source_type="SCAN_OBSERVED",
            trust_tier="scan_observed",
            evidence_ref=f"Stage 1 scan of {scenario_name}",
            parsed={"nodes": nodes},
        ))

    # Stage 3: crawl from seed device to add DEVICE_REPORTED evidence.
    seed = topology.get("seed_device", "rtr01")
    crawl = TopologyCrawl(
        client=client,
        model_name=PARSER_MODEL,
        scenario=scenario_name,
        topology_model=model,
        mode="replay",
    )
    crawl.run(seed=seed, max_depth=2)

    return model


# ------------------------------------------------------------------
# Verdict extraction (structural only — human grades by reading transcripts)
# ------------------------------------------------------------------

def extract_verdict(report: dict | None) -> str:
    """Crude structural classification: NO_FINDING / LOW / MEDIUM / HIGH."""
    if report is None:
        return "NO_REPORT"
    findings = report.get("findings", [])
    if not findings:
        return "NO_FINDING"
    confs = [f.get("confidence", "low") for f in findings]
    if "high"   in confs: return "HIGH_CONFIDENCE"
    if "medium" in confs: return "MEDIUM_CONFIDENCE"
    return "LOW_CONFIDENCE"


def verdict_label(structural: str) -> str:
    return {
        "NO_FINDING":        "NO_FINDING",
        "LOW_CONFIDENCE":    "CAN'T_CLEAR",
        "MEDIUM_CONFIDENCE": "CONFIRM",
        "HIGH_CONFIDENCE":   "CONFIRM",
        "NO_REPORT":         "NO_REPORT",
    }.get(structural, structural)


def check_plumbing(transcript: list[dict], scenario_name: str) -> dict:
    """Scan transcript for plumbing signals: did the discrepancy reach the Hunter?"""
    text = json.dumps(transcript)
    topo_called     = "topology_query" in text
    disc_ip         = "185.220.101.50"
    disc_reached    = disc_ip in text
    is_discrepancy  = "discrepancy" in scenario_name

    note = ""
    if is_discrepancy and not disc_reached:
        note = "PLUMBING: discrepancy IP never appeared in transcript — evidence may not have reached Hunter"
    elif is_discrepancy and disc_reached and not topo_called:
        note = "NOTE: discrepancy reached Hunter via ssh_cli (not topology_query)"
    elif not topo_called:
        note = "NOTE: topology_query never called — Hunter used ssh_cli only"

    return {
        "topology_query_called": topo_called,
        "discrepancy_reached_hunter": disc_reached if is_discrepancy else "N/A",
        "note": note,
    }


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def run_scenario(
    client: anthropic.Anthropic,
    scenario_name: str,
    meta: dict,
    seeds: int,
) -> list[dict]:
    topology_path = ENVIRONMENTS_DIR / scenario_name / "topology.json"
    if not topology_path.exists():
        print(f"  [skip] no topology.json for {scenario_name}")
        return []

    topology = json.loads(topology_path.read_text())
    answer_key_path = ENVIRONMENTS_DIR / scenario_name / "answer_key.json"
    answer_key = json.loads(answer_key_path.read_text()) if answer_key_path.exists() else {}

    print(f"\nBuilding TopologyModel for {scenario_name}…")
    topo_model = build_topo_model(client, scenario_name, topology)
    disc_count = len(topo_model.discrepancies())
    not_int_count = len(topo_model.not_interrogable_nodes())
    print(f"  Model ready — {disc_count} discrepancy(s), {not_int_count} NOT_INTERROGABLE node(s)")

    results = []
    for seed_num in range(1, seeds + 1):
        print(f"\n  Seed {seed_num}/{seeds}…")

        dispatcher = Dispatcher(
            client,
            topology=topology,
            scenario=scenario_name,
            mode="replay",
            topology_model=topo_model,
        )
        hunter = HunterEngine(
            client,
            topology,
            dispatcher=dispatcher,
            model=HUNTER_MODEL,
            max_collections=10,
            verifier_enabled=True,
            verifier_model=VERIFIER_MODEL,
        )

        result = hunter.run(task_framing=TASK_FRAMING)

        structural = extract_verdict(result.report)
        plumbing   = check_plumbing(result.transcript, scenario_name)

        # Write transcript.
        run_dir = RUNS_DIR / scenario_name / f"seed_{seed_num:02d}"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "transcript.json").write_text(json.dumps(result.transcript, indent=2))
        if result.report:
            (run_dir / "report.json").write_text(json.dumps(result.report, indent=2))
        if hunter.verifier_log:
            (run_dir / "verifier_log.json").write_text(json.dumps(hunter.verifier_log, indent=2))

        row = {
            "seed":      seed_num,
            "verdict":   verdict_label(structural),
            "expected":  meta["expected"],
            "match":     verdict_label(structural) == meta["expected"],
            "plumbing":  plumbing,
            "summary":   result.report.get("summary", "") if result.report else "",
            "findings":  result.report.get("findings", []) if result.report else [],
            "run_dir":   str(run_dir),
        }
        results.append(row)

        match_flag = "✓" if row["match"] else "✗"
        print(f"    {match_flag}  verdict={row['verdict']}  expected={row['expected']}")
        if plumbing["note"]:
            print(f"    ⚠  {plumbing['note']}")

    return results


def print_table(all_results: dict[str, list[dict]]) -> None:
    print(f"\n\n{'='*72}")
    print("  Experiment 1 — Verdict Table")
    print(f"{'='*72}")
    print(f"  {'Scenario':<30}  {'Seed':>4}  {'Verdict':<20}  {'Expected':<20}  {'Match'}")
    print(f"  {'-'*30}  {'-'*4}  {'-'*20}  {'-'*20}  {'-'*5}")

    for scenario_name, rows in all_results.items():
        meta = SCENARIOS[scenario_name]
        for row in rows:
            match = "PASS" if row["match"] else "FAIL"
            print(
                f"  {meta['label']:<30}  {row['seed']:>4}  "
                f"{row['verdict']:<20}  {row['expected']:<20}  {match}"
            )
        # Per-scenario pass rate
        passed = sum(1 for r in rows if r["match"])
        print(f"  {'':30}  {'':4}  {'':20}  {'pass rate:':20}  {passed}/{len(rows)}")
        print()

    print("\nTranscripts: runs/experiment1/<scenario>/seed_NN/")
    print("Grade by reading transcript.json and report.json.")
    print("\nPlumbing flags (check these first for any FAIL):")
    for scenario_name, rows in all_results.items():
        for row in rows:
            if row["plumbing"]["note"]:
                print(f"  Seed {row['seed']} [{SCENARIOS[scenario_name]['label']}]: {row['plumbing']['note']}")


def main() -> None:
    load_dotenv()
    client = anthropic.Anthropic()

    args = sys.argv[1:]
    scenario_filter = None
    seeds = 5

    for i, arg in enumerate(args):
        if arg == "--scenarios" and i + 1 < len(args):
            scenario_filter = set(args[i + 1].lower().split(","))
        if arg == "--seeds" and i + 1 < len(args):
            seeds = int(args[i + 1])

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    print(f"Experiment 1  —  {timestamp}")
    print(f"Hunter model: {HUNTER_MODEL}   seeds: {seeds}")

    all_results: dict[str, list[dict]] = {}
    for scenario_name, meta in SCENARIOS.items():
        if scenario_filter and not any(meta["label"].lower().startswith(f) for f in scenario_filter):
            continue
        print(f"\n{'='*60}")
        print(f"  {meta['label']}")
        print(f"{'='*60}")
        all_results[scenario_name] = run_scenario(client, scenario_name, meta, seeds)

    print_table(all_results)


if __name__ == "__main__":
    main()
