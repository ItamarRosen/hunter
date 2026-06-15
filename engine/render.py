"""Renders a hunt's transcript + collection log as a readable markdown narrative.

Pure presentation over data already captured by HunterEngine and
GenerativeEvidenceCollector — interleaves the Hunter's reasoning, the
evidence it requested, what came back, and the final report.
"""

import json


def render_investigation_log(
    transcript: list[dict],
    collection_log: list[dict],
    environment_name: str,
) -> str:
    lines = [f"# Investigation log — {environment_name}", ""]

    # First pass: which tool_use ids are collect_evidence calls (these are
    # the only ones paired 1:1 with collection_log), and a lookup from any
    # tool_use id to its tool_result content (used to pair record_conclusion
    # verdicts and submit_report gate verdicts with the call that produced
    # them).
    collect_evidence_ids: set[str] = set()
    tool_results_by_id: dict[str, dict] = {}
    for message in transcript:
        if message["role"] == "assistant":
            for block in message["content"]:
                if block.get("type") == "tool_use" and block.get("name") == "collect_evidence":
                    collect_evidence_ids.add(block["id"])
        elif message["role"] == "user" and isinstance(message["content"], list):
            for block in message["content"]:
                if block.get("type") == "tool_result":
                    tool_results_by_id[block["tool_use_id"]] = json.loads(block["content"])

    step = 0
    collection_idx = 0

    for message in transcript:
        content = message["content"]

        if message["role"] == "user" and isinstance(content, str):
            if step == 0:
                lines += ["## Briefing", "", content, "", "---", ""]
            continue

        if message["role"] == "assistant":
            step += 1
            lines += [f"## Step {step}", ""]
            for block in content:
                if block["type"] == "text":
                    lines += [block["text"], ""]
                elif block["type"] == "tool_use" and block["name"] == "collect_evidence":
                    device_id = block["input"]["device_id"]
                    request = block["input"]["request"]
                    lines += [f"**→ collect_evidence(`{device_id}`)**", "", f"> {request}", ""]
                elif block["type"] == "tool_use" and block["name"] == "record_conclusion":
                    lines += _render_record_conclusion(block, tool_results_by_id.get(block["id"]))
                elif block["type"] == "tool_use" and block["name"] == "submit_report":
                    gate_result = tool_results_by_id.get(block["id"])
                    if gate_result is not None and gate_result.get("accepted") is False:
                        lines += _render_gate_rejection(gate_result)
                    else:
                        lines += ["## Final report", ""]
                        lines += _render_report(block["input"])
            continue

        if message["role"] == "user" and isinstance(content, list):
            for block in content:
                if block["type"] != "tool_result":
                    continue
                if block["tool_use_id"] not in collect_evidence_ids:
                    continue
                result = json.loads(block["content"])
                entry = collection_log[collection_idx]
                collection_idx += 1

                status = f"**← result** — found: `{result['found']}`"
                if result.get("note"):
                    status += f", note: _{result['note']}_"
                lines += [status]

                if entry.get("embeds_ground_truth"):
                    refs = ", ".join(entry.get("ground_truth_refs", []))
                    lines += ["", f"🎯 _embeds ground truth: {refs}_"]

                lines += ["", "```", result["data"], "```", ""]

            lines += ["---", ""]

    return "\n".join(lines)


def _render_record_conclusion(block: dict, verdict: dict | None) -> list[str]:
    conclusion_id = block["input"]["conclusion_id"]
    statement = block["input"]["statement"]
    reasoning = block["input"]["reasoning"]

    lines = [
        f"**→ record_conclusion(`{conclusion_id}`)**",
        "",
        f"> {statement}",
        "",
        f"_Reasoning: {reasoning}_",
        "",
    ]

    if verdict is not None:
        lines += [
            f"**← verdict: {verdict.get('verdict')}** (reachable: {verdict.get('reachable')})",
            "",
            f"_{verdict.get('binding_directive', '')}_",
            "",
        ]
        alternatives = verdict.get("alternatives_considered") or []
        if alternatives:
            lines += ["Alternatives considered:"]
            lines += [f"- {a}" for a in alternatives]
            lines += [""]

    return lines


def _render_gate_rejection(gate_result: dict) -> list[str]:
    lines = ["### Submission attempt rejected", "", gate_result.get("reason", ""), ""]
    for c in gate_result.get("unresolved_conclusions", []):
        lines.append(
            f"- `{c['conclusion_id']}` — {c['verdict']} "
            f"(reachable: {c['reachable']}): {c['binding_directive']}"
        )
    lines.append("")
    return lines


def _render_report(report: dict) -> list[str]:
    lines = [f"**Summary:** {report.get('summary', '')}", ""]

    findings = report.get("findings", [])
    if findings:
        lines += ["### Findings", ""]
        for i, finding in enumerate(findings, 1):
            lines += [
                f"**{i}. {finding['title']}**",
                "",
                f"- **Type:** {finding.get('type', 'finding')}",
                f"- **Affected devices:** {', '.join(finding.get('affected_devices', []))}",
                f"- **Confidence:** {finding.get('confidence')} — **Severity:** {finding.get('severity')}",
                f"- **Evidence:** {finding.get('evidence')}",
                "",
            ]
    else:
        lines += ["_No findings reported._", ""]

    lines += ["### Open questions", ""]
    open_questions = report.get("open_questions", [])
    if open_questions:
        lines += [f"- {q}" for q in open_questions]
    else:
        lines += ["_None._"]
    lines += [""]

    return lines
