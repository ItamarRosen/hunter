"""Terminal report gate.

A backstop on top of the mid-investigation `record_conclusion` verifier
reviews: before a `submit_report` is accepted, every finding in the draft
report -- compromise findings and clean/dismissal findings alike -- is run
through the same competing-hypothesis verifier, regardless of whether it was
already reviewed via `record_conclusion`. This catches over-statement that
slips through when the hunter never called `record_conclusion` at all.

Findings the verifier finds NON_DIAGNOSTIC or CONTRADICTED block submission
until a bounded number of resolve attempts is exceeded, at which point they
are force-resolved to an open coverage gap (never to "clean"/"no compromise").
Findings with non-empty `scope_flags` have their over-scoped clauses bounded
to what the evidence type actually supports, with the unobserved remainder
moved to `open_questions` -- this happens on every call, accepted or not.
"""

from __future__ import annotations

from typing import Any

from engine import verifier

MAX_GATE_REJECTIONS = 2  # same limit as hunter.py's conclusion gate


def review_report(
    client: Any,
    model: str,
    report: dict,
    evidence_record: list[dict],
    attempts: int,
    budget_exhausted: bool = False,
) -> tuple[bool, dict, list[dict], list[dict]]:
    """Review every finding in `report["findings"]` against the evidence record.

    Mutates `report` in place -- scope_flags rewrites and coverage_gap
    reclassification are applied regardless of whether the report is accepted
    -- and also returns it.

    Returns (accepted, report, log_entries, unresolved_payload):
    - log_entries: verifier_log-shaped entries (per-finding verdict dicts
      carrying a "verdict" key, plus {"event": "gate_rejected"|"force_resolved",
      ...} entries).
    - unresolved_payload: same shape as hunter.py's `unresolved_conclusions`
      list ({conclusion_id, statement, verdict, binding_directive, reachable}),
      ready to embed in the submit_report rejection tool_result. Empty when
      accepted.
    """
    log_entries: list[dict] = []
    unresolved_payload: list[dict] = []
    must_force = budget_exhausted or attempts >= MAX_GATE_REJECTIONS

    for finding in report.get("findings", []):
        verdict = verifier.run_verifier(
            client, model,
            statement=finding["title"],
            reasoning=finding.get("evidence", ""),
            evidence_record=evidence_record,
        )

        log_entries.append({
            "conclusion_id": finding["title"],
            "source": "report_gate",
            "statement": finding["title"],
            "reasoning": finding.get("evidence", ""),
            "alternatives_considered": verdict.get("alternatives_considered", []),
            "key_evidence": verdict.get("key_evidence", []),
            "verdict": verdict["verdict"],
            "discriminating_evidence_to_seek": verdict.get("discriminating_evidence_to_seek", ""),
            "reachable": verdict["reachable"],
            "binding_directive": verdict.get("binding_directive", ""),
            "scope_flags": verdict.get("scope_flags", []),
        })

        _apply_scope_flags(finding, report, verdict.get("scope_flags", []))

        if verdict["verdict"] == "SUPPORTED":
            finding.setdefault("type", "finding")
            continue

        if must_force:
            _force_resolve_finding(finding, verdict)
            log_entries.append({"event": "force_resolved", "conclusion_id": finding["title"]})
        else:
            unresolved_payload.append({
                "conclusion_id": finding["title"],
                "statement": finding["title"],
                "verdict": verdict["verdict"],
                "binding_directive": verdict.get("binding_directive", ""),
                "reachable": verdict["reachable"],
            })

    if unresolved_payload:
        log_entries.append({
            "event": "gate_rejected",
            "unresolved_conclusion_ids": [p["conclusion_id"] for p in unresolved_payload],
        })
        return False, report, log_entries, unresolved_payload

    return True, report, log_entries, []


def _apply_scope_flags(finding: dict, report: dict, scope_flags: list[dict]) -> None:
    for flag in scope_flags:
        claim = flag.get("claim", "")
        bounded = flag.get("bounded_rewrite", "")
        evidence = finding.get("evidence", "")
        if claim and claim in evidence:
            finding["evidence"] = evidence.replace(claim, bounded)
        elif bounded:
            finding["evidence"] = f"{evidence} [Scope note: {bounded}]"

        moved = flag.get("moved_to_open_question", "")
        if moved:
            report.setdefault("open_questions", []).append(moved)


def _force_resolve_finding(finding: dict, verdict: dict) -> None:
    finding["type"] = "coverage_gap"
    finding["confidence"] = "low"
    directive = verdict.get("binding_directive", "")
    finding["evidence"] = (
        f"{finding.get('evidence', '')} [Held as an open coverage gap -- "
        f"cannot confirm, cannot clear. Verifier: {verdict['verdict']}, "
        f"reachable={verdict['reachable']}. {directive}]"
    )
