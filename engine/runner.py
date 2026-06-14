"""Shared artifact-writing for a Hunter run.

Factored out of run_hunt.py so run_experiment.py can write the same
transcript/collection-log/investigation-log/report files for additional runs
(env_004, control x2) without duplicating the logic.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from engine.collectors.generative import GenerativeEvidenceCollector
from engine.render import render_investigation_log


def write_run_artifacts(
    run_dir: Path,
    environment_name: str,
    collector: GenerativeEvidenceCollector,
    transcript: list[dict],
) -> None:
    collection_log = [asdict(entry) for entry in collector.log]
    (run_dir / "transcript.json").write_text(json.dumps(transcript, indent=2))
    (run_dir / "collection_log.json").write_text(json.dumps(collection_log, indent=2))
    (run_dir / "investigation_log.md").write_text(
        render_investigation_log(transcript, collection_log, environment_name)
    )


def write_report(run_dir: Path, report: dict[str, Any] | None) -> None:
    (run_dir / "report.json").write_text(json.dumps(report, indent=2))
