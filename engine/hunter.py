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

from engine import report_gate, verifier
from engine.evidence import COLLECT_EVIDENCE_TOOL, REQUEST_EVIDENCE_TOOL, EvidenceCollector

HUNTER_PROMPT_PATH = Path(__file__).parent / "prompts" / "hunter_system.md"
HUNTER_DISPATCHER_PROMPT_PATH = Path(__file__).parent / "prompts" / "hunter_dispatcher_system.md"
DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_MAX_COLLECTIONS = 15
MAX_GATE_REJECTIONS = 2

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
                            "description": "Narrative summary of the evidence supporting this finding.",
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

RECORD_CONCLUSION_TOOL = {
    "name": "record_conclusion",
    "description": (
        "Record a working conclusion the moment you crystallize it -- a "
        "finding you're ready to assert, or a hypothesis/asset you're ready "
        "to dismiss or clear -- so it can be checked against competing "
        "explanations before it goes in your final report. To revise or "
        "downgrade an existing conclusion (e.g. after new evidence, or in "
        "response to a verdict), call this again with the SAME "
        "conclusion_id and updated statement/reasoning."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "conclusion_id": {
                "type": "string",
                "description": "Short stable slug, e.g. 'edge_rtr01_compromise' or 'noc_mon01_span_benign'.",
            },
            "statement": {
                "type": "string",
                "description": "The conclusion itself, stated plainly.",
            },
            "reasoning": {
                "type": "string",
                "description": "Why you believe this, citing what you've collected.",
            },
        },
        "required": ["conclusion_id", "statement", "reasoning"],
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
        collector: EvidenceCollector | None = None,
        model: str = DEFAULT_MODEL,
        max_collections: int = DEFAULT_MAX_COLLECTIONS,
        verifier_enabled: bool = True,
        verifier_model: str | None = None,
        dispatcher: Any = None,
    ) -> None:
        self._client = client
        self._topology = topology
        self._collector = collector
        self._dispatcher = dispatcher
        self._model = model
        self._max_collections = max_collections
        self._collect_tool = REQUEST_EVIDENCE_TOOL if dispatcher is not None else COLLECT_EVIDENCE_TOOL
        prompt_path = HUNTER_DISPATCHER_PROMPT_PATH if dispatcher is not None else HUNTER_PROMPT_PATH
        self._system_prompt = prompt_path.read_text()
        self._verifier_enabled = verifier_enabled
        self._verifier_model = verifier_model or model

    def run(
        self,
        on_step: Callable[[list[dict]], None] | None = None,
        task_framing: str | None = None,
    ) -> HuntResult:
        closing = task_framing or "Begin."
        messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    "Network topology:\n"
                    f"{json.dumps(self._topology, indent=2)}\n\n"
                    f"You have up to {self._max_collections} {self._collect_tool["name"]} calls "
                    f"for this investigation. {closing}"
                ),
            }
        ]

        collections_used = 0
        max_rounds = self._max_collections * 2
        self._conclusions: dict[str, dict] = {}
        self.verifier_log: list[dict] = []
        self._gate_attempts = 0

        print(f"=== Hunt started — budget: {self._max_collections} {self._collect_tool["name"]} calls ===\n")

        for round_num in range(max_rounds + 1):
            budget_exhausted = collections_used >= self._max_collections or round_num == max_rounds
            if budget_exhausted:
                tools = [SUBMIT_REPORT_TOOL]
                tool_choice = {"type": "tool", "name": "submit_report"}
            elif self._verifier_enabled:
                tools = [self._collect_tool, SUBMIT_REPORT_TOOL, RECORD_CONCLUSION_TOOL]
                tool_choice = {"type": "auto"}
            else:
                tools = [self._collect_tool, SUBMIT_REPORT_TOOL]
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

            if not tool_uses:
                messages.append({
                    "role": "user",
                    "content": "Continue your investigation, or call submit_report to finish.",
                })
                if on_step:
                    on_step(messages)
                continue

            report_block = next((b for b in tool_uses if b.name == "submit_report"), None)
            other_blocks = [b for b in tool_uses if b.name != "submit_report"]

            tool_results = []
            for block in other_blocks:
                if block.name == self._collect_tool["name"]:
                    collections_used += 1
                    if self._dispatcher is not None:
                        description = block.input["description"]
                        print(f"[{collections_used}/{self._max_collections}] request_evidence: {description}")
                        evidence = self._dispatcher.dispatch(description)
                    else:
                        device_id = block.input["device_id"]
                        request   = block.input["request"]
                        print(f"[{collections_used}/{self._max_collections}] collect_evidence({device_id}): {request}")
                        evidence = self._collector.collect(device_id=device_id, request=request)

                    _print_evidence(evidence)
                    tool_results.append(_make_tool_result(block.id, {
                        "found": evidence.found,
                        "data":  evidence.data,
                        "note":  evidence.note,
                    }))
                elif block.name == "record_conclusion" and self._verifier_enabled:
                    conclusion_id = block.input["conclusion_id"]
                    statement = block.input["statement"]
                    reasoning = block.input["reasoning"]
                    print(f"[verifier] record_conclusion({conclusion_id}): {statement}")

                    evidence_record = verifier.build_evidence_record(messages)
                    verdict = verifier.run_verifier(
                        self._client, self._verifier_model, statement, reasoning, evidence_record,
                    )
                    print(f"    -> {verdict['verdict']} — {verdict.get('binding_directive', '')}\n")

                    self.verifier_log.append({
                        "conclusion_id": conclusion_id,
                        "round": round_num,
                        "collections_used_at_this_point": collections_used,
                        "statement": statement,
                        "reasoning": reasoning,
                        "alternatives_considered": verdict.get("alternatives_considered", []),
                        "key_evidence": verdict.get("key_evidence", []),
                        "verdict": verdict["verdict"],
                        "discriminating_evidence_to_seek": verdict.get("discriminating_evidence_to_seek", ""),
                        "reachable": verdict["reachable"],
                        "binding_directive": verdict.get("binding_directive", ""),
                    })

                    self._conclusions[conclusion_id] = {
                        "statement": statement,
                        "reasoning": reasoning,
                        "verdict": verdict["verdict"],
                        "reachable": verdict["reachable"],
                        "binding_directive": verdict.get("binding_directive", ""),
                        "status": "resolved" if verdict["verdict"] == "SUPPORTED" else "open",
                        "gate_rejections": 0,
                        "force_resolved": False,
                    }

                    tool_results.append(_make_tool_result(block.id, verdict))

                else:
                    # Catch-all: tool not available in this mode — must still
                    # return a tool_result or the API will see orphaned tool_use blocks.
                    tool_results.append(_make_tool_result(
                        block.id, {"error": f"Tool '{block.name}' is not available in this mode."}
                    ))

            if report_block is not None:
                unresolved_items = [
                    (cid, c) for cid, c in self._conclusions.items() if c["status"] == "open"
                ]
                if self._verifier_enabled and not budget_exhausted and unresolved_items:
                    unresolved_payload = []
                    for cid, c in unresolved_items:
                        c["gate_rejections"] += 1
                        if c["gate_rejections"] > MAX_GATE_REJECTIONS:
                            c["status"] = "resolved"
                            c["force_resolved"] = True
                            self.verifier_log.append({
                                "event": "force_resolved",
                                "conclusion_id": cid,
                                "round": round_num,
                            })
                        else:
                            unresolved_payload.append({
                                "conclusion_id": cid,
                                "statement": c["statement"],
                                "verdict": c["verdict"],
                                "binding_directive": c["binding_directive"],
                                "reachable": c["reachable"],
                            })

                    if unresolved_payload:
                        self.verifier_log.append({
                            "event": "gate_rejected",
                            "round": round_num,
                            "unresolved_conclusion_ids": [p["conclusion_id"] for p in unresolved_payload],
                        })
                        tool_results.append(_make_tool_result(report_block.id, {
                            "accepted": False,
                            "reason": (
                                "One or more working conclusions have not yet been "
                                "resolved by the verifier. Address each one per its "
                                "binding_directive, then call record_conclusion again "
                                "on the same conclusion_id before resubmitting."
                            ),
                            "unresolved_conclusions": unresolved_payload,
                        }))
                        messages.append({"role": "user", "content": tool_results})
                        if on_step:
                            on_step(messages)
                        continue

                final_report = report_block.input

                if self._verifier_enabled:
                    evidence_record = verifier.build_evidence_record(messages)
                    accepted, final_report, gate_log_entries, unresolved_payload = report_gate.review_report(
                        self._client, self._verifier_model, final_report,
                        evidence_record, self._gate_attempts, budget_exhausted,
                    )
                    for entry in gate_log_entries:
                        entry.setdefault("round", round_num)
                        entry.setdefault("collections_used_at_this_point", collections_used)
                        self.verifier_log.append(entry)

                    if not accepted:
                        self._gate_attempts += 1
                        tool_results.append(_make_tool_result(report_block.id, {
                            "accepted": False,
                            "reason": (
                                "One or more findings in your draft report have not "
                                "been confirmed by the verifier. Address each one per "
                                "its binding_directive — collect the named "
                                "discriminating evidence and revise the finding, or "
                                "downgrade it — then resubmit."
                            ),
                            "unresolved_conclusions": unresolved_payload,
                        }))
                        messages.append({"role": "user", "content": tool_results})
                        if on_step:
                            on_step(messages)
                        continue

                if tool_results:
                    messages.append({"role": "user", "content": tool_results})
                    if on_step:
                        on_step(messages)
                _print_report(final_report)
                if on_step:
                    on_step(messages)
                return HuntResult(report=final_report, transcript=messages)

            if tool_results:
                messages.append({"role": "user", "content": tool_results})
            if on_step:
                on_step(messages)

        # Unreachable: the final round forces submit_report.
        return HuntResult(report=None, transcript=messages)


def _make_tool_result(tool_use_id: str, content: dict) -> dict:
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": json.dumps(content)}


def _print_evidence(evidence: Any) -> None:
    status  = "found" if evidence.found else "not found"
    note    = f" — {evidence.note}" if evidence.note else ""
    preview = " ".join(evidence.data.split())
    if len(preview) > 200:
        preview = preview[:200] + "..."
    print(f"    -> {status}{note}")
    print(f"    {preview}\n")


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
