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
                elif block["type"] == "tool_use" and block["name"] == "submit_report":
                    lines += ["## Final report", ""]
                    lines += _render_report(block["input"])
            continue

        if message["role"] == "user" and isinstance(content, list):
            for block in content:
                if block["type"] != "tool_result":
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


def _render_report(report: dict) -> list[str]:
    lines = [f"**Summary:** {report.get('summary', '')}", ""]

    findings = report.get("findings", [])
    if findings:
        lines += ["### Findings", ""]
        for i, finding in enumerate(findings, 1):
            lines += [
                f"**{i}. {finding['title']}**",
                "",
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
