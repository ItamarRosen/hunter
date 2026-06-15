"""Fixture evidence collector.

Implements EvidenceCollector with a closed, enumerated, retrieval-only
evidence set (env_005 monitor fixtures + contract). An LLM router does
classification only -- which source_id(s) a request's concepts touch -- and
this collector returns the matched source's record bodies verbatim from the
fixture library, plus its coverage string as the note. No model ever
authors evidence content; a request that routes to nothing, to a source
that doesn't exist in this cell, or to a source whose scope doesn't cover
the requested device, returns the canned "not found" response.
"""

import re
from pathlib import Path
from string import Template

import anthropic

from engine.evidence import CollectionLogEntry, EvidenceResponse

ROUTER_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "fixture_router_system.md"
DEFAULT_MODEL = "claude-sonnet-4-6"


class FixtureEvidenceCollector:
    def __init__(
        self,
        client: anthropic.Anthropic,
        cell_sources: dict,
        fixtures: dict,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._client = client
        self._model = model
        self._cell_sources = cell_sources["sources"]
        self._fixtures = fixtures
        self._system_prompt = _render_router_prompt(fixtures["routing"])
        self._route_tool = _build_route_tool(fixtures["routing"])
        self.log: list[CollectionLogEntry] = []

    def collect(self, device_id: str, request: str) -> EvidenceResponse:
        source_ids = self._route(device_id, request)
        source_ids = _resolve_egress_visibility(source_ids, self._cell_sources)

        records = self._fixtures["records"]
        record_tags = self._fixtures["record_tags"]
        source_scopes = self._fixtures["source_scopes"]
        device = device_id.strip().lower()

        data_parts: list[str] = []
        note_parts: list[str] = []
        empty_notes: list[str] = []
        refs: set[str] = set()
        core_flag = False
        in_scope_sources: list[dict] = []

        for source_id in source_ids:
            source = self._cell_sources.get(source_id)
            if source is None:
                continue

            scope = source_scopes.get(source_id, "*")
            if scope != "*" and device not in scope:
                empty_notes.append(
                    f"{source['coverage']} — does not cover {device_id} "
                    f"(covers: {', '.join(scope)})"
                )
                continue

            in_scope_sources.append(source)
            if source["exists"]:
                for record_id in source["returns"]:
                    data_parts.append(records[record_id])
                    tags = record_tags.get(record_id, {"tags": [], "core": False})
                    refs.update(tags["tags"])
                    core_flag = core_flag or tags["core"]
                note_parts.append(f"{source_id}: {source['coverage']}")
            else:
                empty_notes.append(source["coverage"])

        indicator_notes = _named_indicator_notes(
            request, data_parts, in_scope_sources, self._fixtures["tracked_indicators"]
        )

        if data_parts:
            found = True
            data = "\n\n".join(data_parts)
            note = "; ".join(note_parts + indicator_notes)
        else:
            found = False
            data = ""
            if empty_notes or indicator_notes:
                note = "; ".join(empty_notes + indicator_notes)
            else:
                note = self._fixtures["default_note"]

        self.log.append(
            CollectionLogEntry(
                device_id=device_id,
                request=request,
                found=found,
                embeds_ground_truth=core_flag,
                ground_truth_refs=sorted(refs),
            )
        )

        return EvidenceResponse(found=found, data=data, note=note)

    def _route(self, device_id: str, request: str) -> list[str]:
        user_turn = f"[Investigator query — device: {device_id}]\n{request}"
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            temperature=0,
            system=self._system_prompt,
            messages=[{"role": "user", "content": user_turn}],
            tools=[self._route_tool],
            tool_choice={"type": "tool", "name": "route_request"},
        )
        for block in response.content:
            if block.type == "tool_use":
                return list(dict.fromkeys(block.input.get("source_ids", [])))
        return []


def _resolve_egress_visibility(source_ids: list[str], cell_sources: dict) -> list[str]:
    if "egress_visibility" not in source_ids:
        return source_ids
    resolved = "edge_wan_netflow" if cell_sources["edge_wan_netflow"]["exists"] else "oob_tap"
    return list(dict.fromkeys(resolved if s == "egress_visibility" else s for s in source_ids))


def _named_indicator_notes(
    request: str,
    data_parts: list[str],
    in_scope_sources: list[dict],
    tracked_indicators: list[str],
) -> list[str]:
    """For any tracked indicator the request names but the collected data
    doesn't contain, note its absence per in-scope, existing source -- a
    query-time targeted lookup, never a volunteered denial."""
    data_text = "\n\n".join(data_parts)
    notes: list[str] = []
    for indicator in tracked_indicators:
        pattern = re.compile(r"\b" + re.escape(indicator) + r"\b", re.IGNORECASE)
        if not pattern.search(request) or pattern.search(data_text):
            continue
        for source in in_scope_sources:
            if source["exists"]:
                notes.append(f"no records involving {indicator} in {source['coverage']}")
    return notes


def _render_router_prompt(routing: dict) -> str:
    template = Template(ROUTER_PROMPT_PATH.read_text())
    plain_bullets = "\n".join(
        f"- **{source_id}**: {', '.join(phrases)}"
        for source_id, phrases in routing.items()
        if source_id not in ("egress_visibility", "edge_wan_netflow", "oob_tap")
    )
    egress_bullet = f"- **egress_visibility**: {', '.join(routing['egress_visibility'])}"
    return template.substitute(source_bullets=plain_bullets + "\n" + egress_bullet)


def _build_route_tool(routing: dict) -> dict:
    return {
        "name": "route_request",
        "description": (
            "Classify which monitor data source(s) this request is asking about. "
            "Return zero, one, or several source_ids."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "source_ids": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(routing.keys())},
                    "description": "The source_id(s) this request's concepts match, if any.",
                },
            },
            "required": ["source_ids"],
        },
    }
