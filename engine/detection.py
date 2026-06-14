"""Passive detection engine.

A single-pass LLM analyst reads one telemetry chunk (no follow-up access,
no collect_evidence) and produces a structured assessment via one forced
submit_assessment tool call. Uses the same model as the Hunter
(engine.hunter.DEFAULT_MODEL) -- only adaptive-collection access differs,
isolating the reasoning-vs-collection variable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import anthropic

DETECTOR_PROMPT_PATH = Path(__file__).parent / "prompts" / "detector_system.md"
DEFAULT_MODEL = "claude-opus-4-8"

SUBMIT_ASSESSMENT_TOOL = {
    "name": "submit_assessment",
    "description": "Submit your triage assessment of the telemetry export. This ends the analysis.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "One or two sentences: the bottom line of this triage.",
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
                                "finding, citing specific entries from the export."
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
                "description": "Things noticed but not resolvable from this export alone, with what would resolve them.",
            },
        },
        "required": ["summary", "findings", "open_questions"],
    },
}


class DetectionEngine:
    def __init__(
        self,
        client: anthropic.Anthropic,
        topology: dict[str, Any],
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._client = client
        self._topology = topology
        self._model = model
        self._system_prompt = DETECTOR_PROMPT_PATH.read_text()

    def analyze(self, chunk_text: str) -> dict:
        messages = [
            {
                "role": "user",
                "content": (
                    "Network topology:\n"
                    f"{json.dumps(self._topology, indent=2)}\n\n"
                    "Telemetry export:\n"
                    f"{chunk_text}\n\n"
                    "Submit your assessment."
                ),
            }
        ]

        response = self._client.messages.create(
            model=self._model,
            max_tokens=8192,
            system=self._system_prompt,
            messages=messages,
            tools=[SUBMIT_ASSESSMENT_TOOL],
            tool_choice={"type": "tool", "name": "submit_assessment"},
        )

        assessment_block = next(b for b in response.content if b.type == "tool_use")
        return assessment_block.input
