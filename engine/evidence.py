"""Core evidence-collection types and the EvidenceCollector interface.

This is the seam between the Hunter's reasoning loop and whatever produces
evidence on the other side of it — a generative LLM "Matcher", a static
fixture, or anything else that can answer collect().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class EvidenceResponse:
    found: bool
    data: str
    note: str | None = None


@dataclass
class CollectionLogEntry:
    device_id: str
    request: str
    found: bool
    embeds_ground_truth: bool
    ground_truth_refs: list[str] = field(default_factory=list)


class EvidenceCollector(Protocol):
    def collect(self, device_id: str, request: str) -> EvidenceResponse: ...


COLLECT_EVIDENCE_TOOL = {
    "name": "collect_evidence",
    "description": (
        "Request evidence from a specific device on the network: logs, "
        "configuration, running state, file artifacts, or anything else "
        "you'd ask a colleague or a SIEM to pull. Be specific and phrase "
        "the request the way a skilled analyst would."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "device_id": {
                "type": "string",
                "description": "The id of the device to query, from the network topology.",
            },
            "request": {
                "type": "string",
                "description": "A specific, analyst-grade request for evidence from this device.",
            },
        },
        "required": ["device_id", "request"],
    },
}
