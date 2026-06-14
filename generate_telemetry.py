"""CLI entry point: generate a telemetry chunk for an environment.

Usage: python generate_telemetry.py <environment_name> <feed|control>
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from engine.coverage import load_coverage
from engine.environment import load_environment
from engine.telemetry import TelemetryGenerator, validate_chunk

ROOT = Path(__file__).parent
ENVIRONMENTS_DIR = ROOT / "environments"
RUNS_DIR = ROOT / "runs" / "telemetry"


def main(environment_name: str, mode: str) -> None:
    sys.stdout.reconfigure(line_buffering=True)
    load_dotenv()
    client = anthropic.Anthropic()

    environment = load_environment(ENVIRONMENTS_DIR / environment_name)
    coverage = load_coverage(ENVIRONMENTS_DIR / environment_name)

    generator = TelemetryGenerator(client, environment, coverage)
    chunk = generator.generate(mode)
    validation = validate_chunk(chunk, coverage)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RUNS_DIR / f"{environment_name}_{mode}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "chunk.md").write_text(chunk.text)
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "environment": chunk.environment,
                "mode": chunk.mode,
                "included_tags": chunk.included_tags,
                "excluded_tags": chunk.excluded_tags,
                "validation": validation,
            },
            indent=2,
        )
    )

    print(f"Chunk written: {run_dir}")
    print(json.dumps(validation, indent=2))


if __name__ == "__main__":
    environment_name = sys.argv[1] if len(sys.argv) > 1 else "env_004_cloud_identity_lotl"
    mode = sys.argv[2] if len(sys.argv) > 2 else "feed"
    main(environment_name, mode)
