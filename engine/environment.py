"""Loads an environment's topology and ground truth from disk."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Environment:
    name: str
    topology: dict[str, Any]
    ground_truth: str


def load_environment(path: Path) -> Environment:
    topology = json.loads((path / "topology.json").read_text())
    ground_truth = (path / "ground_truth.md").read_text()
    return Environment(name=path.name, topology=topology, ground_truth=ground_truth)
