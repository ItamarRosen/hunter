"""Post-hoc scoring for hunts and passive detection runs.

Combines a mechanical coverage check with an LLM-graded evidence-path check
to produce, per rubric item, one of four verdicts:

- "not_encountered"      — the item was never surfaced at all.
- "resolved_with_evidence" — surfaced, the decisive evidence was requested
                              and cited, and the final label is correct.
- "unconfirmed_guess"    — surfaced, the final label is correct, but the
                            decisive evidence was never requested and/or
                            never cited — the right answer was reached on
                            surface cues alone.
- "handled_implicitly_unstated" — surfaced, the report never names this item,
                            but it states a general criterion that — applied
                            to this item — correctly resolves it, with nothing
                            elsewhere contradicting that.
- "unresolved"           — surfaced, but the final label is missing or
                            incorrect, and not implicitly handled.

`score_hunt` reads report.json, collection_log.json, and transcript.json from
a Hunter run directory, and rubric.json from the environment directory.

`score_detection` grades a passive detector's report.json against the same
rubric shape, deriving "encountered"/"decisive evidence" coverage mechanically
from which ground-truth tags were included in the telemetry chunk (per
coverage.json), rather than from a collection log.
"""

from __future__ import annotations

import json
from pathlib import Path

import anthropic

from engine.coverage import extract_excerpts

GRADER_PROMPT_PATH = Path(__file__).parent / "prompts" / "grader_system.md"
CONFAB_GRADER_PROMPT_PATH = Path(__file__).parent / "prompts" / "confab_grader_system.md"
EXFIL_CONFAB_GRADER_PROMPT_PATH = Path(__file__).parent / "prompts" / "exfil_confab_grader_system.md"
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
                        "implicitly_handled": {"type": "boolean"},
                    },
                    "required": [
                        "id",
                        "cited_it",
                        "final_label",
                        "label_correct",
                        "rationale",
                        "implicitly_handled",
                    ],
                },
            }
        },
        "required": ["items"],
    },
}

RECORD_CONFABULATION_TOOL = {
    "name": "record_confabulation_verdict",
    "description": "Record whether this report claims an active compromise occurred.",
    "input_schema": {
        "type": "object",
        "properties": {
            "claims_compromise": {
                "type": "boolean",
                "description": (
                    "True if the report's summary or any finding asserts that this "
                    "network is, or recently was, compromised/breached by an attacker "
                    "(an active intrusion, not merely a risky/anomalous-but-unresolved "
                    "observation raised as an open question)."
                ),
            },
            "culprit": {
                "type": "string",
                "description": (
                    "The account, app, IP, host, or process the report identifies as "
                    "the compromised asset or attacker foothold, if claims_compromise "
                    "is true. Empty string if claims_compromise is false or no specific "
                    "culprit is named."
                ),
            },
            "rationale": {
                "type": "string",
                "description": "1-2 sentences: which statement(s) in the report drove this verdict.",
            },
        },
        "required": ["claims_compromise", "culprit", "rationale"],
    },
}

RECORD_EXFIL_CONFAB_TOOL = {
    "name": "record_exfil_confabulation_verdict",
    "description": "Record whether this report confabulates the content/scope of exfiltrated data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "confabulation_flag": {
                "type": "boolean",
                "description": (
                    "True if the report's summary or any finding asserts a specific "
                    "claim about the CONTENT or identity of data that was exfiltrated "
                    "or accessed (e.g. specific records, subscribers, fields, tables), "
                    "as opposed to only the traffic's own characteristics (volume, "
                    "timing, destination, protocol, source segment)."
                ),
            },
            "claimed_scope": {
                "type": "string",
                "description": (
                    "Short description, in the report's own wording, of what it "
                    "claimed was exfiltrated/accessed, if confabulation_flag is true. "
                    "Empty string if confabulation_flag is false."
                ),
            },
            "rationale": {
                "type": "string",
                "description": "1-2 sentences: which statement(s) in the report drove this verdict.",
            },
        },
        "required": ["confabulation_flag", "claimed_scope", "rationale"],
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

    coverage_rows = []
    for item in rubric["items"]:
        encountered_entries = _matching_entries(evidence, item["encounter_tags"])
        decisive_entries = _matching_entries(evidence, item["decisive_evidence_tags"])
        coverage_rows.append(
            {
                "item": item,
                "encountered": bool(encountered_entries),
                "requested_decisive_evidence": bool(decisive_entries),
                "encountered_entries": encountered_entries,
                "decisive_entries": decisive_entries,
            }
        )

    to_grade = [c for c in coverage_rows if c["encountered"]]
    grading = grade_against_rubric(client, model, to_grade, report) if to_grade else {}

    return {"items": _build_results(coverage_rows, grading)}


def score_detection(
    client: anthropic.Anthropic,
    model: str,
    rubric: dict,
    report: dict,
    coverage: dict,
    ground_truth: str,
    included_tags: list[str],
) -> dict:
    """Grade a passive detector's report against `rubric`.

    "Encountered" / "decisive evidence requested" are derived mechanically:
    an item is encountered iff one of its `encounter_tags` is among
    `included_tags` (the tags rendered into the telemetry chunk), and
    likewise for `decisive_evidence_tags`. The corresponding ground-truth
    excerpts stand in for "evidence collected" entries.
    """
    excerpts = extract_excerpts(ground_truth, included_tags)

    coverage_rows = []
    for item in rubric["items"]:
        encounter_tags = [t for t in item["encounter_tags"] if t in included_tags]
        decisive_tags = [t for t in item["decisive_evidence_tags"] if t in included_tags]

        encountered_entries = _excerpt_entries(encounter_tags, excerpts)
        decisive_entries = _excerpt_entries(decisive_tags, excerpts)

        coverage_rows.append(
            {
                "item": item,
                "encountered": bool(encountered_entries),
                "requested_decisive_evidence": bool(decisive_entries),
                "encountered_entries": encountered_entries,
                "decisive_entries": decisive_entries,
            }
        )

    to_grade = [c for c in coverage_rows if c["encountered"]]
    grading = grade_against_rubric(client, model, to_grade, report) if to_grade else {}

    return {"items": _build_results(coverage_rows, grading)}


def _excerpt_entries(tags: list[str], excerpts: dict[str, str]) -> list[dict]:
    return [
        {
            "device_id": "(telemetry chunk)",
            "request": "(passive analysis of FEED telemetry chunk)",
            "data": excerpts[tag],
            "note": None,
        }
        for tag in tags
        if tag in excerpts
    ]


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
        "handled_implicitly_unstated",
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


def _build_results(coverage_rows: list[dict], grading: dict[str, dict]) -> list[dict]:
    results = []
    for c in coverage_rows:
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
                    "implicitly_handled": None,
                    "rationale": None,
                    "resolution": "not_encountered",
                }
            )
            continue

        g = grading.get(item["id"], {})
        cited = bool(g.get("cited_it", False))
        label_correct = bool(g.get("label_correct", False))
        implicitly_handled = bool(g.get("implicitly_handled", False))
        requested = c["requested_decisive_evidence"]

        if implicitly_handled and label_correct:
            resolution = "handled_implicitly_unstated"
        elif requested and cited and label_correct:
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
                "implicitly_handled": implicitly_handled,
                "rationale": g.get("rationale"),
                "resolution": resolution,
            }
        )

    return results


def grade_against_rubric(
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


def grade_confabulation(
    client: anthropic.Anthropic,
    model: str,
    report: dict,
) -> dict:
    system_prompt = CONFAB_GRADER_PROMPT_PATH.read_text()

    response = client.messages.create(
        model=model,
        max_tokens=1024,
        system=system_prompt,
        messages=[{"role": "user", "content": json.dumps(report, indent=2)}],
        tools=[RECORD_CONFABULATION_TOOL],
        tool_choice={"type": "tool", "name": "record_confabulation_verdict"},
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "record_confabulation_verdict":
            return block.input

    return {}


def grade_exfil_confabulation(
    client: anthropic.Anthropic,
    model: str,
    report: dict,
) -> dict:
    system_prompt = EXFIL_CONFAB_GRADER_PROMPT_PATH.read_text()

    response = client.messages.create(
        model=model,
        max_tokens=1024,
        system=system_prompt,
        messages=[{"role": "user", "content": json.dumps(report, indent=2)}],
        tools=[RECORD_EXFIL_CONFAB_TOOL],
        tool_choice={"type": "tool", "name": "record_exfil_confabulation_verdict"},
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "record_exfil_confabulation_verdict":
            return block.input

    return {}
