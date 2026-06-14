"""Composition root: wires an Environment, a GenerativeEvidenceCollector, and
the HunterEngine together, runs a hunt, and writes the results to runs/.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from engine.collectors.generative import GenerativeEvidenceCollector
from engine.environment import load_environment
from engine.hunter import HunterEngine
from engine.runner import write_report, write_run_artifacts

ROOT = Path(__file__).parent
ENVIRONMENTS_DIR = ROOT / "environments"
RUNS_DIR = ROOT / "runs"


def main(environment_name: str) -> None:
    sys.stdout.reconfigure(line_buffering=True)
    load_dotenv()
    client = anthropic.Anthropic()

    environment = load_environment(ENVIRONMENTS_DIR / environment_name)
    collector = GenerativeEvidenceCollector(client, environment)
    hunter = HunterEngine(client, environment.topology, collector)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RUNS_DIR / f"{environment_name}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    def write_progress(transcript: list[dict]) -> None:
        write_run_artifacts(run_dir, environment_name, collector, transcript)

    result = hunter.run(on_step=write_progress)

    write_report(run_dir, result.report)

    print(f"Run complete: {run_dir}")
    print(json.dumps(result.report, indent=2))


if __name__ == "__main__":
    environment_name = sys.argv[1] if len(sys.argv) > 1 else "env_000_dummy"
    main(environment_name)
