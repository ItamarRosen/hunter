"""Cheap IoC/signature rule-matcher -- the no-LLM detection floor.

Hand-authored regex indicators of compromise per environment, checked
against a telemetry chunk with no model involved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

RULES: dict[str, list[tuple[str, str]]] = {
    "env_003_wrong_story": [
        ("c2_ip", r"185\.220\.101\.47"),
        ("backdoor_binary", r"winupdate32\.exe"),
        ("lsass_dump_technique", r"comsvcs\.dll"),
        ("malicious_scheduled_task", r"MicrosoftEdgeUpdateTaskMachine(?!Core)"),
        ("rogue_local_account", r"svc_backup\b"),
    ],
    "env_004_cloud_identity_lotl": [
        ("c2_ip", r"188\.43\.112\.77"),
        ("compromised_account", r"ext-auditor-rwilcox"),
        ("malicious_oauth_app", r"Mailbox Archiver Pro"),
        ("malicious_app_domain", r"archiver-pro\.mailbox-tools\.net"),
    ],
}


@dataclass
class RuleHit:
    rule: str
    match: str


def match(environment_name: str, chunk_text: str) -> list[RuleHit]:
    hits = []
    for rule_name, pattern in RULES.get(environment_name, []):
        for m in re.finditer(pattern, chunk_text):
            hits.append(RuleHit(rule=rule_name, match=m.group(0)))
    return hits
