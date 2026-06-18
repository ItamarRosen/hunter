"""Generic evidence parser: normalises raw protocol output to clean JSON.

One Haiku call per collection result. The protocol and command are passed as
context so Haiku knows what kind of data it's looking at, but the parsing
logic itself is generic — no per-protocol code.
"""

from __future__ import annotations

import json
import re

import anthropic

_SYSTEM = """\
You are a network evidence parser. You receive raw output from a network device or system.
Parse it into a clean, structured JSON object.

Rules:
- Discard CLI formatting noise: prompts, column headers, decoration lines, blank lines
- Use snake_case key names
- For routing tables: {"routes": [{"type": "S/C/O/B/L/...", "destination": "x.x.x.x/n", "next_hop": "...", "interface": "..."}], "notable": [...]}
- For interface counters: {"interfaces": [{"name": "...", "description": "...", "status": "up/down", "in_rate_bps": N, "out_rate_bps": N, "in_bytes_total": N, "out_bytes_total": N}]}
- For ARP tables: {"arp_entries": [{"ip": "x.x.x.x", "mac": "hhhh.hhhh.hhhh", "interface": "...", "age_min": N_or_null}]}
- For LLDP/CDP neighbor tables: {"neighbors": [{"device_id": "...", "local_interface": "...", "remote_interface": "...", "capabilities": ["R"]}]}
- Add a "notable" list to routing tables: flag static routes (S), host routes (/32), non-RFC1918 next-hops
- Return ONLY valid JSON. No markdown, no explanation."""


def parse(raw: str, protocol: str, command: str, client: anthropic.Anthropic, model: str) -> dict:
    resp = client.messages.create(
        model=model,
        max_tokens=2048,
        system=_SYSTEM,
        messages=[{"role": "user", "content": f"Protocol: {protocol}\nCommand/query: {command}\n\nRaw output:\n{raw}"}],
    )
    text = resp.content[0].text.strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return {"raw": text}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {"raw": text}
