"""Generative evidence collector.

Implements EvidenceCollector with an LLM-backed "Matcher": a stateful
conversation seeded with the network topology and a (Hunter-hidden) ground
truth, which generates a plausible response to each collect() call —
weaving in ground-truth evidence where a real investigation would surface
it, and realistic normal data otherwise.
"""

import json
import re
from pathlib import Path
from string import Template

import anthropic

from engine.environment import Environment
from engine.evidence import CollectionLogEntry, EvidenceResponse

MATCHER_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "matcher_system.md"
DEFAULT_MODEL = "claude-sonnet-4-6"


class GenerativeEvidenceCollector:
    def __init__(
        self,
        client: anthropic.Anthropic,
        environment: Environment,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._client = client
        self._model = model
        self._system_prompt = _render_matcher_prompt(environment)
        self._history: list[dict] = []
        self.log: list[CollectionLogEntry] = []

    def collect(self, device_id: str, request: str) -> EvidenceResponse:
        user_turn = f"[Investigator query — device: {device_id}]\n{request}"
        messages = self._history + [{"role": "user", "content": user_turn}]

        response = self._client.messages.create(
            model=self._model,
            max_tokens=4096,
            system=self._system_prompt,
            messages=messages,
        )
        raw = response.content[0].text
        result = _parse_matcher_response(raw)

        self._history.append({"role": "user", "content": user_turn})
        self._history.append({"role": "assistant", "content": raw})

        self.log.append(
            CollectionLogEntry(
                device_id=device_id,
                request=request,
                found=result["found"],
                embeds_ground_truth=result["embeds_ground_truth"],
                ground_truth_refs=result["ground_truth_refs"],
            )
        )

        return EvidenceResponse(
            found=result["found"],
            data=result["data"],
            note=result["note"],
        )


def _render_matcher_prompt(environment: Environment) -> str:
    template = Template(MATCHER_PROMPT_PATH.read_text())
    return template.substitute(
        topology=json.dumps(environment.topology, indent=2),
        ground_truth=environment.ground_truth,
    )


def _parse_matcher_response(raw: str) -> dict:
    """Extract the JSON object the Matcher was instructed to return.

    Falls back to treating the whole response as evidence data if the
    model didn't return valid JSON — a single malformed turn shouldn't
    crash the investigation.
    """
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        try:
            payload = json.loads(match.group(0))
            return {
                "found": bool(payload.get("found", True)),
                "data": payload.get("data", ""),
                "note": payload.get("note"),
                "embeds_ground_truth": bool(payload.get("embeds_ground_truth", False)),
                "ground_truth_refs": payload.get("ground_truth_refs", []),
            }
        except json.JSONDecodeError:
            pass

    return {
        "found": True,
        "data": raw,
        "note": None,
        "embeds_ground_truth": False,
        "ground_truth_refs": [],
    }
