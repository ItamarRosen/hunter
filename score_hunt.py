"""Score a completed hunt run: writes scoring.json and coverage_matrix.md
into the run directory.

Usage: python score_hunt.py <environment_name> <run_dir_name>
e.g.:  python score_hunt.py env_003_wrong_story env_003_wrong_story_20260614T133031Z
"""

import json
import sys
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from engine.scoring import render_coverage_matrix, score_hunt

ROOT = Path(__file__).parent
ENVIRONMENTS_DIR = ROOT / "environments"
RUNS_DIR = ROOT / "runs"


def main(environment_name: str, run_dir_name: str) -> None:
    load_dotenv()
    client = anthropic.Anthropic()

    environment_dir = ENVIRONMENTS_DIR / environment_name
    run_dir = RUNS_DIR / run_dir_name

    scoring = score_hunt(client, run_dir, environment_dir)

    (run_dir / "scoring.json").write_text(json.dumps(scoring, indent=2))
    (run_dir / "coverage_matrix.md").write_text(render_coverage_matrix(scoring))

    print(f"Scored: {run_dir}")
    print(render_coverage_matrix(scoring))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python score_hunt.py <environment_name> <run_dir_name>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
