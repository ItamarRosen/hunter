"""The Hunter agent loop.

An LLM reasons over a network's topology, requests evidence via an
EvidenceCollector, and ends the investigation with a structured report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import anthropic

from engine.evidence import COLLECT_EVIDENCE_TOOL, EvidenceCollector

HUNTER_PROMPT_PATH = Path(__file__).parent / "prompts" / "hunter_system.md"
DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_MAX_COLLECTIONS = 15

SUBMIT_REPORT_TOOL = {
    "name": "submit_report",
    "description": "Submit your final investigation report. This ends the investigation.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "One or two sentences: the bottom line of this investigation.",
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "affected_devices": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Device ids from the topology involved in this finding.",
                        },
                        "evidence": {
                            "type": "string",
                            "description": (
                                "Narrative summary of the evidence supporting this "
                                "finding, referencing what collect_evidence returned."
                            ),
                        },
                        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    },
                    "required": ["title", "affected_devices", "evidence", "confidence", "severity"],
                },
            },
            "open_questions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Things worth investigating further with more time or access.",
            },
        },
        "required": ["summary", "findings", "open_questions"],
    },
}


@dataclass
class HuntResult:
    report: dict[str, Any] | None
    transcript: list[dict] = field(default_factory=list)


class HunterEngine:
    def __init__(
        self,
        client: anthropic.Anthropic,
        topology: dict[str, Any],
        collector: EvidenceCollector,
        model: str = DEFAULT_MODEL,
        max_collections: int = DEFAULT_MAX_COLLECTIONS,
    ) -> None:
        self._client = client
        self._topology = topology
        self._collector = collector
        self._model = model
        self._max_collections = max_collections
        self._system_prompt = HUNTER_PROMPT_PATH.read_text()

    def run(self, on_step: Callable[[list[dict]], None] | None = None) -> HuntResult:
        messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    "Network topology:\n"
                    f"{json.dumps(self._topology, indent=2)}\n\n"
                    f"You have up to {self._max_collections} collect_evidence calls "
                    "for this investigation. Begin."
                ),
            }
        ]

        collections_used = 0
        max_rounds = self._max_collections * 2

        print(f"=== Hunt started — budget: {self._max_collections} collect_evidence calls ===\n")

        for round_num in range(max_rounds + 1):
            budget_exhausted = collections_used >= self._max_collections or round_num == max_rounds
            if budget_exhausted:
                tools = [SUBMIT_REPORT_TOOL]
                tool_choice = {"type": "tool", "name": "submit_report"}
            else:
                tools = [COLLECT_EVIDENCE_TOOL, SUBMIT_REPORT_TOOL]
                tool_choice = {"type": "auto"}

            response = self._client.messages.create(
                model=self._model,
                max_tokens=4096,
                system=self._system_prompt,
                messages=messages,
                tools=tools,
                tool_choice=tool_choice,
            )
            messages.append({"role": "assistant", "content": [_block_to_dict(b) for b in response.content]})
            if on_step:
                on_step(messages)

            for block in response.content:
                if block.type == "text" and block.text.strip():
                    print(block.text.strip() + "\n")

            tool_uses = [b for b in response.content if b.type == "tool_use"]

            report_block = next((b for b in tool_uses if b.name == "submit_report"), None)
            if report_block is not None:
                _print_report(report_block.input)
                if on_step:
                    on_step(messages)
                return HuntResult(report=report_block.input, transcript=messages)

            if not tool_uses:
                messages.append({
                    "role": "user",
                    "content": "Continue your investigation, or call submit_report to finish.",
                })
                if on_step:
                    on_step(messages)
                continue

            tool_results = []
            for block in tool_uses:
                collections_used += 1
                device_id = block.input["device_id"]
                request = block.input["request"]
                print(f"[{collections_used}/{self._max_collections}] collect_evidence({device_id}): {request}")

                evidence = self._collector.collect(device_id=device_id, request=request)

                status = "found" if evidence.found else "not found"
                note = f" — {evidence.note}" if evidence.note else ""
                preview = " ".join(evidence.data.split())
                if len(preview) > 200:
                    preview = preview[:200] + "..."
                print(f"    -> {status}{note}")
                print(f"    {preview}\n")

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps({
                        "found": evidence.found,
                        "data": evidence.data,
                        "note": evidence.note,
                    }),
                })
            messages.append({"role": "user", "content": tool_results})
            if on_step:
                on_step(messages)

        # Unreachable: the final round forces submit_report.
        return HuntResult(report=None, transcript=messages)


def _print_report(report: dict) -> None:
    print("=== Final report ===\n")
    print(report.get("summary", ""))

    findings = report.get("findings", [])
    if findings:
        print("\nFindings:")
        for i, finding in enumerate(findings, 1):
            devices = ", ".join(finding.get("affected_devices", []))
            print(
                f"  {i}. [{finding.get('severity')}/{finding.get('confidence')}] "
                f"{finding['title']} (devices: {devices})"
            )
            print(f"     {finding.get('evidence', '')}")
    else:
        print("\nNo findings.")

    open_questions = report.get("open_questions", [])
    if open_questions:
        print("\nOpen questions:")
        for q in open_questions:
            print(f"  - {q}")


def _block_to_dict(block: Any) -> dict:
    if block.type == "text":
        return {"type": "text", "text": block.text}
    if block.type == "tool_use":
        return {"type": "tool_use", "id": block.id, "name": block.name, "input": block.input}
    raise ValueError(f"Unexpected content block type: {block.type}")
