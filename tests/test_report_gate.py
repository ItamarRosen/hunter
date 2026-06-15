"""Forced-rejection test for the terminal report gate.

Exercises engine.report_gate.review_report against a stubbed verifier: a
finding that never resolves gets force-resolved to an open coverage gap
(never "clean"/"no compromise") after MAX_GATE_REJECTIONS rejections, while a
finding with an over-scoped claim gets its scope_flags applied (bounded
rewrite + open question) starting from the very first call.

Run with: .venv/bin/python tests/test_report_gate.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import report_gate

NOC_MON01_TITLE = "Possible compromise via NOC-MON01 SPAN"
EXFIL_TITLE = "Records-segment traffic exfiltrated"

EXFIL_CLAIM = "subscriber/billing data was exfiltrated"
EXFIL_BOUNDED = (
    "records-segment traffic was exfiltrated; the specific records it "
    "contained is unconfirmed"
)
EXFIL_OPEN_QUESTION = (
    "Determine which subscriber/billing records were in the exfiltrated traffic."
)


def _stub_run_verifier(client, model, statement, reasoning, evidence_record):
    if statement == NOC_MON01_TITLE:
        return {
            "conclusion": statement,
            "alternatives_considered": [
                "NOC-MON01's SPAN/mirror port is a legitimate monitoring tap.",
            ],
            "key_evidence": [],
            "verdict": "NON_DIAGNOSTIC",
            "discriminating_evidence_to_seek": (
                "An authorization/change record for the SPAN/mirror "
                "configuration on NOC-MON01."
            ),
            "reachable": False,
            "binding_directive": (
                "Hold as an open coverage gap -- cannot confirm or clear "
                "without an authorization record that is not reachable in "
                "this investigation."
            ),
            "scope_flags": [],
        }

    if statement == EXFIL_TITLE:
        if EXFIL_CLAIM in reasoning:
            scope_flags = [{
                "claim": EXFIL_CLAIM,
                "supported_scope": (
                    "Flow/volume evidence supports that traffic occurred and "
                    "its volume/direction, not payload content."
                ),
                "bounded_rewrite": EXFIL_BOUNDED,
                "moved_to_open_question": EXFIL_OPEN_QUESTION,
            }]
        else:
            scope_flags = []

        return {
            "conclusion": statement,
            "alternatives_considered": [],
            "key_evidence": [],
            "verdict": "SUPPORTED",
            "discriminating_evidence_to_seek": "",
            "reachable": None,
            "binding_directive": "",
            "scope_flags": scope_flags,
        }

    raise AssertionError(f"Unexpected statement: {statement!r}")


def _build_draft_report() -> dict:
    return {
        "summary": "Investigation in progress.",
        "findings": [
            {
                "title": NOC_MON01_TITLE,
                "affected_devices": ["noc-mon01"],
                "evidence": (
                    "NOC-MON01 has a SPAN/mirror session capturing "
                    "records-segment traffic; no authorization record was "
                    "found for this configuration."
                ),
                "confidence": "low",
                "severity": "medium",
            },
            {
                "title": EXFIL_TITLE,
                "affected_devices": ["edge-rtr01"],
                "evidence": (
                    "NetFlow shows ~55.9 GB egressed via a GRE tunnel on "
                    "edge-rtr01 to a known-malicious IP; "
                    f"{EXFIL_CLAIM}."
                ),
                "confidence": "high",
                "severity": "critical",
            },
        ],
        "open_questions": [],
    }


def main() -> None:
    draft_report = _build_draft_report()

    with patch("engine.report_gate.verifier.run_verifier", side_effect=_stub_run_verifier):
        accepted0, draft_report, log0, _ = report_gate.review_report(
            None, "stub", draft_report, [], attempts=0, budget_exhausted=False,
        )
        accepted1, draft_report, log1, _ = report_gate.review_report(
            None, "stub", draft_report, [], attempts=1, budget_exhausted=False,
        )
        accepted2, draft_report, log2, _ = report_gate.review_report(
            None, "stub", draft_report, [], attempts=2, budget_exhausted=False,
        )

    # attempts=0 and attempts=1: rejected, one gate_rejected event each.
    assert accepted0 is False, "attempts=0 should be rejected"
    assert accepted1 is False, "attempts=1 should be rejected"
    assert sum(1 for e in log0 if e.get("event") == "gate_rejected") == 1
    assert sum(1 for e in log1 if e.get("event") == "gate_rejected") == 1

    # attempts=2: accepted, NOC-MON01 force-resolved, no further rejection.
    assert accepted2 is True, "attempts=2 should be force-accepted"
    force_resolved = [
        e for e in log2
        if e.get("event") == "force_resolved" and e.get("conclusion_id") == NOC_MON01_TITLE
    ]
    assert len(force_resolved) == 1, "expected exactly one force_resolved entry for NOC-MON01"
    assert not any(e.get("event") == "gate_rejected" for e in log2)

    by_title = {f["title"]: f for f in draft_report["findings"]}

    # Hard safety rule: force-resolution never produces an all-clear.
    noc_mon01 = by_title[NOC_MON01_TITLE]
    assert noc_mon01["type"] == "coverage_gap"
    assert "clean" not in noc_mon01["evidence"].lower()
    assert "no compromise" not in noc_mon01["evidence"].lower()

    # Scope-flag rewrite applied (present from the very first call onward).
    exfil = by_title[EXFIL_TITLE]
    assert EXFIL_BOUNDED in exfil["evidence"]
    assert EXFIL_CLAIM not in exfil["evidence"]
    assert EXFIL_OPEN_QUESTION in draft_report["open_questions"]
    assert draft_report["open_questions"].count(EXFIL_OPEN_QUESTION) == 1

    print("All report_gate forced-rejection assertions passed.")


if __name__ == "__main__":
    main()
