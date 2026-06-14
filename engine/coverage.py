"""Coverage manifest loading and ground-truth excerpt extraction.

A `coverage.json` in an environment directory maps each `ground_truth.md`
reference tag to an evidence tier (FEED / ON_DEMAND / GAP) and category,
plus benign FEED-padding bullets and leak-probe strings used by the
telemetry generator (engine/telemetry.py) and detection scorer
(engine/scoring.py).
"""

from __future__ import annotations

import json
import re
from pathlib import Path


def load_coverage(environment_dir: Path) -> dict:
    return json.loads((environment_dir / "coverage.json").read_text())


def tags_with_tier(coverage: dict, tier: str) -> list[str]:
    return [tag for tag, info in coverage["tags"].items() if info["tier"] == tier]


def extract_excerpts(ground_truth: str, tags: list[str]) -> dict[str, str]:
    """Pull the markdown table row for each tag out of ground_truth.md.

    Every reference-tag row in these documents is a single-line markdown
    table row of the form "| `tag` | ...cells... |". Matching on the
    backtick-delimited tag avoids prefix collisions between tags like
    `competing_pentest_pt2026_03` and `competing_pentest_pt2026_03_auth`.

    Cells that are pure tier annotations (env_004's core-incident table has
    a "Tier" column whose cells start with `**FEED**`/`**ON-DEMAND**`) are
    dropped — they're instructions for the Matcher, not evidence content,
    and would leak this experiment's own tier vocabulary into the chunk.
    """
    tier_markers = ("**FEED**", "**ON-DEMAND**", "**GAP**")
    excerpts: dict[str, str] = {}
    for tag in tags:
        pattern = re.compile(
            r"^\|\s*`" + re.escape(tag) + r"`\s*\|(.*)\|\s*$", re.MULTILINE
        )
        match = pattern.search(ground_truth)
        if not match:
            continue
        cells = [c.strip() for c in match.group(1).split("|")]
        cells = [c for c in cells if c and not c.startswith(tier_markers)]
        excerpts[tag] = " — ".join(cells)
    return excerpts
