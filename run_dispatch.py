"""Entry point for a dispatcher-mode hunt.

Wires the Hunter and Dispatcher together for a scenario, runs the full
Hunter → Dispatcher → Parser → evidence → Hunter → verdict loop, and
writes the transcript + report to runs/.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from engine.dispatcher import Dispatcher
from engine.hunter import HunterEngine

ROOT = Path(__file__).parent
ENVIRONMENTS_DIR = ROOT / "environments"
RUNS_DIR = ROOT / "runs"

HUNTER_MODEL = "claude-opus-4-8"
VERIFIER_MODEL = "claude-sonnet-4-6"
TASK_FRAMING = "Determine whether this network is compromised, and if so how. Begin."


def main(scenario_name: str, mode: str = "replay", verifier: bool = True) -> None:
    sys.stdout.reconfigure(line_buffering=True)
    load_dotenv()
    client = anthropic.Anthropic()

    topology_path = ENVIRONMENTS_DIR / scenario_name / "topology.json"
    if not topology_path.exists():
        sys.exit(f"No topology.json found at {topology_path}")
    topology = json.loads(topology_path.read_text())

    dispatcher = Dispatcher(client, topology=topology, scenario=scenario_name, mode=mode)
    hunter = HunterEngine(
        client,
        topology,
        dispatcher=dispatcher,
        model=HUNTER_MODEL,
        verifier_enabled=verifier,
        verifier_model=VERIFIER_MODEL,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RUNS_DIR / f"{scenario_name}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    result = hunter.run(task_framing=TASK_FRAMING)

    (run_dir / "transcript.json").write_text(json.dumps(result.transcript, indent=2))
    if result.report:
        (run_dir / "report.json").write_text(json.dumps(result.report, indent=2))
    if hunter.verifier_log:
        (run_dir / "verifier_log.json").write_text(json.dumps(hunter.verifier_log, indent=2))

    print(f"\nRun complete: {run_dir}")


if __name__ == "__main__":
    args = sys.argv[1:]
    scenario = args[0] if args else "env_006_replay_demo"
    no_verifier = "--no-verifier" in args
    main(scenario, verifier=not no_verifier)
