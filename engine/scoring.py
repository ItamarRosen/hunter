"""Post-hoc scoring for a completed hunt run.

Combines a mechanical coverage check (derived from collection_log.json's
ground_truth_refs tags) with an LLM-graded evidence-path check to produce,
per rubric item, one of four verdicts:

- "not_encountered"      — the Hunter never surfaced this item at all.
- "resolved_with_evidence" — surfaced, the decisive evidence was requested
                              and cited, and the final label is correct.
- "unconfirmed_guess"    — surfaced, the final label is correct, but the
                            decisive evidence was never requested and/or
                            never cited — the right answer was reached on
                            surface cues alone.
- "unresolved"           — surfaced, but the final label is missing or
                            incorrect.

Reads report.json, collection_log.json, and transcript.json from a run
directory, and rubric.json from the environment directory.
"""

from __future__ import annotations

import json
from pathlib import Path

import anthropic

GRADER_PROMPT_PATH = Path(__file__).parent / "prompts" / "grader_system.md"
DEFAULT_MODEL = "claude-sonnet-4-6"

GRADE_REPORT_TOOL = {
    "name": "grade_report",
    "description": "Record grading results for each rubric item.",
    "input_schema": {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Rubric item id, copied exactly.",
                        },
                        "cited_it": {"type": "boolean"},
                        "final_label": {"type": "string"},
                        "label_correct": {"type": "boolean"},
                        "rationale": {"type": "string"},
                    },
                    "required": [
                        "id",
                        "cited_it",
                        "final_label",
                        "label_correct",
                        "rationale",
                    ],
                },
            }
        },
        "required": ["items"],
    },
}


def load_rubric(environment_dir: Path) -> dict:
    return json.loads((environment_dir / "rubric.json").read_text())


def score_hunt(
    client: anthropic.Anthropic,
    run_dir: Path,
    environment_dir: Path,
    model: str = DEFAULT_MODEL,
) -> dict:
    collection_log = json.loads((run_dir / "collection_log.json").read_text())
    transcript = json.loads((run_dir / "transcript.json").read_text())
    report = json.loads((run_dir / "report.json").read_text())
    rubric = load_rubric(environment_dir)

    evidence = _pair_evidence_with_log(transcript, collection_log)

    coverage = []
    for item in rubric["items"]:
        encountered_entries = _matching_entries(evidence, item["encounter_tags"])
        decisive_entries = _matching_entries(evidence, item["decisive_evidence_tags"])
        coverage.append(
            {
                "item": item,
                "encountered": bool(encountered_entries),
                "requested_decisive_evidence": bool(decisive_entries),
                "encountered_entries": encountered_entries,
                "decisive_entries": decisive_entries,
            }
        )

    to_grade = [c for c in coverage if c["encountered"]]
    grading = _grade_report(client, model, to_grade, report) if to_grade else {}

    results = []
    for c in coverage:
        item = c["item"]
        if not c["encountered"]:
            results.append(
                {
                    "id": item["id"],
                    "category": item["category"],
                    "summary": item["summary"],
                    "encountered": False,
                    "requested_decisive_evidence": False,
                    "cited_it": None,
                    "final_label": None,
                    "label_correct": None,
                    "rationale": None,
                    "resolution": "not_encountered",
                }
            )
            continue

        g = grading.get(item["id"], {})
        cited = bool(g.get("cited_it", False))
        label_correct = bool(g.get("label_correct", False))
        requested = c["requested_decisive_evidence"]

        if requested and cited and label_correct:
            resolution = "resolved_with_evidence"
        elif label_correct:
            resolution = "unconfirmed_guess"
        else:
            resolution = "unresolved"

        results.append(
            {
                "id": item["id"],
                "category": item["category"],
                "summary": item["summary"],
                "encountered": True,
                "requested_decisive_evidence": requested,
                "cited_it": cited,
                "final_label": g.get("final_label"),
                "label_correct": label_correct,
                "rationale": g.get("rationale"),
                "resolution": resolution,
            }
        )

    return {"items": results}


def render_coverage_matrix(scoring: dict) -> str:
    lines = [
        "# Coverage matrix",
        "",
        "| Item | Category | Encountered? | Decisive evidence requested? | Cited? | Label correct? | Resolution | Final label |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for entry in scoring["items"]:

        def _fmt(value):
            if value is None:
                return "—"
            return "yes" if value else "no"

        lines.append(
            "| `{id}` | {category} | {encountered} | {requested} | {cited} | {label_correct} | {resolution} | {final_label} |".format(
                id=entry["id"],
                category=entry["category"],
                encountered=_fmt(entry["encountered"]),
                requested=_fmt(entry["requested_decisive_evidence"]),
                cited=_fmt(entry["cited_it"]),
                label_correct=_fmt(entry["label_correct"]),
                resolution=entry["resolution"],
                final_label=(entry["final_label"] or "—").replace("|", "/"),
            )
        )

    counts: dict[str, int] = {}
    for entry in scoring["items"]:
        counts[entry["resolution"]] = counts.get(entry["resolution"], 0) + 1

    lines += ["", "## Summary", ""]
    for resolution in (
        "resolved_with_evidence",
        "unconfirmed_guess",
        "unresolved",
        "not_encountered",
    ):
        lines.append(f"- **{resolution}**: {counts.get(resolution, 0)}")

    return "\n".join(lines)


def _pair_evidence_with_log(
    transcript: list[dict], collection_log: list[dict]
) -> list[dict]:
    """Merge collection_log entries with the data/note text from transcript
    tool results, in call order — collection_log and the transcript's
    tool_result blocks are populated in the same order."""
    entries = []
    idx = 0
    for message in transcript:
        if message["role"] != "user" or not isinstance(message["content"], list):
            continue
        for block in message["content"]:
            if block.get("type") != "tool_result":
                continue
            result = json.loads(block["content"])
            log_entry = collection_log[idx]
            idx += 1
            entries.append(
                {
                    "device_id": log_entry["device_id"],
                    "request": log_entry["request"],
                    "found": result.get("found"),
                    "note": result.get("note"),
                    "data": result.get("data"),
                    "embeds_ground_truth": log_entry["embeds_ground_truth"],
                    "ground_truth_refs": log_entry["ground_truth_refs"],
                }
            )
    return entries


def _matching_entries(evidence: list[dict], tags: list[str]) -> list[dict]:
    """Match on ground_truth_refs alone.

    embeds_ground_truth is set false for decoys and competing narratives by
    design (per ground_truth.md's tagging instructions for those sections) —
    it only marks the real-incident core IOCs. ground_truth_refs is the
    complete record of what was surfaced, regardless of that flag.
    """
    if not tags:
        return []
    return [e for e in evidence if any(t in e["ground_truth_refs"] for t in tags)]


def _grade_report(
    client: anthropic.Anthropic,
    model: str,
    to_grade: list[dict],
    report: dict,
) -> dict[str, dict]:
    system_prompt = GRADER_PROMPT_PATH.read_text()

    items_block = []
    for c in to_grade:
        item = c["item"]
        items_block.append(
            {
                "id": item["id"],
                "category": item["category"],
                "summary": item["summary"],
                "correct_label": item["correct_label"],
                "decisive_evidence_description": item["decisive_evidence_description"],
                "evidence_collected": [
                    {
                        "device_id": e["device_id"],
                        "request": e["request"],
                        "response": e["data"],
                        "note": e["note"],
                    }
                    for e in c["encountered_entries"]
                ],
                "decisive_evidence_collected": [
                    {
                        "device_id": e["device_id"],
                        "request": e["request"],
                        "response": e["data"],
                        "note": e["note"],
                    }
                    for e in c["decisive_entries"]
                ],
            }
        )

    user_content = (
        "## Rubric items to grade\n\n"
        + json.dumps(items_block, indent=2)
        + "\n\n## Final report submitted by the Hunter\n\n"
        + json.dumps(report, indent=2)
    )

    response = client.messages.create(
        model=model,
        max_tokens=8192,
        system=system_prompt,
        messages=[{"role": "user", "content": user_content}],
        tools=[GRADE_REPORT_TOOL],
        tool_choice={"type": "tool", "name": "grade_report"},
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "grade_report":
            return {entry["id"]: entry for entry in block.input.get("items", [])}

    return {}
