"""Composition root: wires an Environment, a GenerativeEvidenceCollector, and
the HunterEngine together, runs a hunt, and writes the results to runs/.
"""

import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from engine.collectors.generative import GenerativeEvidenceCollector
from engine.environment import load_environment
from engine.hunter import HunterEngine
from engine.render import render_investigation_log

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
        collection_log = [asdict(entry) for entry in collector.log]
        (run_dir / "transcript.json").write_text(json.dumps(transcript, indent=2))
        (run_dir / "collection_log.json").write_text(json.dumps(collection_log, indent=2))
        (run_dir / "investigation_log.md").write_text(
            render_investigation_log(transcript, collection_log, environment_name)
        )

    result = hunter.run(on_step=write_progress)

    (run_dir / "report.json").write_text(json.dumps(result.report, indent=2))

    print(f"Run complete: {run_dir}")
    print(json.dumps(result.report, indent=2))


if __name__ == "__main__":
    environment_name = sys.argv[1] if len(sys.argv) > 1 else "env_000_dummy"
    main(environment_name)
