"""Telemetry chunk generation.

Renders the FEED-tier slice of an environment's ground truth as one
unlabeled, mixed-format raw telemetry chunk, padded with deterministic
benign FEED noise via the same model the Monitor uses
(engine.collectors.generative.DEFAULT_MODEL) -- the input to the passive
detection arm (engine/detection.py).

Generation is per-device: one messages.create() call per topology device,
each scoped to that device's FEED items plus the full feed_baseline list
(the model picks whichever bullets are relevant to this device). This keeps
each call's output bounded so the items that matter are never crowded out
by baseline padding for other devices.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Any, Literal

import anthropic

from engine.coverage import extract_excerpts, tags_with_tier
from engine.environment import Environment

TELEMETRY_PROMPT_PATH = Path(__file__).parent / "prompts" / "telemetry_system.md"
DEFAULT_MODEL = "claude-sonnet-4-6"

DEVICE_MAX_TOKENS_BASE = 3072
DEVICE_MAX_TOKENS_PER_ITEM = 1024
DEVICE_MAX_TOKENS_CAP = 8192


@dataclass
class TelemetryChunk:
    environment: str
    mode: str  # "feed" | "control"
    included_tags: list[str]
    excluded_tags: list[str]
    text: str


class TelemetryGenerator:
    def __init__(
        self,
        client: anthropic.Anthropic,
        environment: Environment,
        coverage: dict,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._client = client
        self._environment = environment
        self._coverage = coverage
        self._model = model

    def generate(self, mode: Literal["feed", "control"]) -> TelemetryChunk:
        feed_tags = tags_with_tier(self._coverage, "FEED")
        if mode == "feed":
            included_tags = feed_tags
        elif mode == "control":
            included_tags = [
                tag
                for tag in feed_tags
                if self._coverage["tags"][tag]["category"] != "core_incident"
            ]
        else:
            raise ValueError(f"unknown mode: {mode!r}")

        excluded_tags = [tag for tag in feed_tags if tag not in included_tags]

        excerpts = extract_excerpts(self._environment.ground_truth, included_tags)

        items_by_device: dict[str, list[dict]] = defaultdict(list)
        for tag in included_tags:
            if tag not in excerpts:
                continue
            info = self._coverage["tags"][tag]
            items_by_device[info["device_id"]].append(
                {"tag": tag, "category": info["category"], "excerpt": excerpts[tag]}
            )

        sections = [
            self._generate_device_section(device, items_by_device.get(device["id"], []))
            for device in self._environment.topology["devices"]
        ]

        return TelemetryChunk(
            environment=self._environment.name,
            mode=mode,
            included_tags=included_tags,
            excluded_tags=excluded_tags,
            text="\n\n---\n\n".join(sections),
        )

    def _generate_device_section(self, device: dict[str, Any], device_items: list[dict]) -> str:
        system_prompt = _render_telemetry_prompt(
            self._environment, device, device_items, self._coverage["feed_baseline"]
        )
        max_tokens = min(
            DEVICE_MAX_TOKENS_CAP,
            DEVICE_MAX_TOKENS_BASE + DEVICE_MAX_TOKENS_PER_ITEM * len(device_items),
        )

        response = self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[
                {"role": "user", "content": "Generate this device's telemetry section now."}
            ],
        )
        return response.content[0].text


def _render_telemetry_prompt(
    environment: Environment,
    device: dict[str, Any],
    device_items: list[dict],
    feed_baseline: list[str],
) -> str:
    template = Template(TELEMETRY_PROMPT_PATH.read_text())
    return template.substitute(
        topology=json.dumps(environment.topology, indent=2),
        device=json.dumps(device, indent=2),
        feed_items=json.dumps(device_items, indent=2),
        feed_baseline="\n".join(f"- {bullet}" for bullet in feed_baseline),
    )


def validate_chunk(chunk: TelemetryChunk, coverage: dict) -> dict:
    """Mechanical leak check: search the chunk for ON_DEMAND/GAP leak probes.

    The primary guarantee is structural -- only FEED excerpts for tags in
    `chunk.included_tags` are ever placed in the generation prompts, so
    ON-DEMAND/GAP content is never available to leak. This is a secondary
    sanity check against accidental overlap with the FEED material.
    """
    text_lower = chunk.text.lower()
    hits = []
    for tag, info in coverage["tags"].items():
        if info["tier"] == "FEED":
            continue
        for probe in coverage.get("leak_probes", {}).get(tag, []):
            if probe.lower() in text_lower:
                hits.append({"tag": tag, "probe": probe})

    return {"passed": not hits, "hits": hits}
