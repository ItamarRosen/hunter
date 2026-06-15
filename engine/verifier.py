"""Competing-hypothesis verifier.

A second, fresh-context invocation of the same model that reviews one of the
Hunter's working conclusions: it generates the strongest plausible competing
explanation, judges whether the evidence collected so far actually
*discriminates* between them, and returns a binding verdict
(SUPPORTED / NON_DIAGNOSTIC / CONTRADICTED) plus a directive the Hunter must
act on. It sees no ground truth and cannot call collect_evidence itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import anthropic

VERIFIER_PROMPT_PATH = Path(__file__).parent / "prompts" / "verifier_system.md"
DEFAULT_MODEL = "claude-opus-4-8"

RECORD_VERDICT_TOOL = {
    "name": "record_verdict",
    "description": "Record the verification verdict for this working conclusion.",
    "input_schema": {
        "type": "object",
        "properties": {
            "conclusion": {
                "type": "string",
                "description": "Short restatement of what the hunter concluded.",
            },
            "alternatives_considered": {
                "type": "array",
                "items": {"type": "string"},
                "description": "The strongest plausible alternative explanation(s) considered.",
            },
            "key_evidence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "evidence_ref": {
                            "type": "string",
                            "description": "Which numbered entry from the evidence record this refers to.",
                        },
                        "discriminates": {"type": "boolean"},
                        "why": {"type": "string"},
                    },
                    "required": ["evidence_ref", "discriminates", "why"],
                },
            },
            "verdict": {
                "type": "string",
                "enum": ["SUPPORTED", "NON_DIAGNOSTIC", "CONTRADICTED"],
            },
            "discriminating_evidence_to_seek": {
                "type": "string",
                "description": "Only meaningful if verdict is NON_DIAGNOSTIC. Empty string otherwise.",
            },
            "reachable": {
                "type": "string",
                "enum": ["true", "false", "unknown"],
                "description": (
                    "Is a source that could plausibly produce "
                    "discriminating_evidence_to_seek visible anywhere in this "
                    "investigation so far? Only meaningful if verdict is "
                    "NON_DIAGNOSTIC."
                ),
            },
            "binding_directive": {
                "type": "string",
                "description": "The instruction the hunter must act on.",
            },
            "scope_flags": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "claim": {
                            "type": "string",
                            "description": "Exact verbatim substring of `reasoning` that asserts more than the evidence type establishes.",
                        },
                        "supported_scope": {
                            "type": "string",
                            "description": "What the evidence type actually supports.",
                        },
                        "bounded_rewrite": {
                            "type": "string",
                            "description": "Rewrite of `claim` restricted to `supported_scope`.",
                        },
                        "moved_to_open_question": {
                            "type": "string",
                            "description": "The unobserved part of `claim`, phrased as an open question.",
                        },
                    },
                    "required": ["claim", "supported_scope", "bounded_rewrite", "moved_to_open_question"],
                },
                "description": (
                    "Claims in `reasoning` that assert more than the evidence "
                    "type can establish, regardless of whether the explanation "
                    "is correct. Empty array if none."
                ),
            },
        },
        "required": [
            "conclusion",
            "alternatives_considered",
            "key_evidence",
            "verdict",
            "discriminating_evidence_to_seek",
            "reachable",
            "binding_directive",
            "scope_flags",
        ],
    },
}


def build_evidence_record(messages: list[dict]) -> list[dict]:
    """Derive the full collect_evidence record from a live transcript.

    Maps each collect_evidence tool_use id to its (device_id, request), then
    pairs that with the matching tool_result's {found, data, note}. Skips
    tool_results that don't correspond to a collect_evidence call (e.g.
    record_conclusion verdicts, gate rejections).
    """
    requests_by_id: dict[str, dict] = {}
    for message in messages:
        if message["role"] != "assistant":
            continue
        for block in message["content"]:
            if block.get("type") == "tool_use" and block.get("name") == "collect_evidence":
                requests_by_id[block["id"]] = {
                    "device_id": block["input"]["device_id"],
                    "request": block["input"]["request"],
                }

    record: list[dict] = []
    for message in messages:
        if message["role"] != "user" or not isinstance(message["content"], list):
            continue
        for block in message["content"]:
            if block.get("type") != "tool_result":
                continue
            call = requests_by_id.get(block["tool_use_id"])
            if call is None:
                continue
            result = json.loads(block["content"])
            record.append({
                "device_id": call["device_id"],
                "request": call["request"],
                "found": result.get("found"),
                "data": result.get("data"),
                "note": result.get("note"),
            })

    return record


def run_verifier(
    client: anthropic.Anthropic,
    model: str,
    statement: str,
    reasoning: str,
    evidence_record: list[dict],
) -> dict:
    system_prompt = VERIFIER_PROMPT_PATH.read_text()

    user_content = (
        "## Working conclusion\n\n"
        f"Statement: {statement}\n\n"
        f"Reasoning: {reasoning}\n\n"
        "## Evidence collected so far\n\n"
        f"{_render_evidence_record(evidence_record)}"
    )

    response = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_content}],
        tools=[RECORD_VERDICT_TOOL],
        tool_choice={"type": "tool", "name": "record_verdict"},
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "record_verdict":
            verdict = dict(block.input)
            verdict["reachable"] = _parse_reachable(verdict.get("reachable"))
            return verdict

    return {
        "conclusion": statement,
        "alternatives_considered": [],
        "key_evidence": [],
        "verdict": "SUPPORTED",
        "discriminating_evidence_to_seek": "",
        "reachable": None,
        "binding_directive": "",
        "scope_flags": [],
    }


def _render_evidence_record(evidence_record: list[dict]) -> str:
    if not evidence_record:
        return "(no evidence collected yet)"

    parts = []
    for i, entry in enumerate(evidence_record, 1):
        parts.append(
            f"{i}. collect_evidence({entry['device_id']}): {entry['request']}\n"
            f"   -> found: {entry['found']}\n"
            f"   -> note: {entry['note']}\n"
            f"   -> data: {entry['data']}"
        )
    return "\n\n".join(parts)


def _parse_reachable(value: str | None) -> bool | None:
    if value == "true":
        return True
    if value == "false":
        return False
    return None
