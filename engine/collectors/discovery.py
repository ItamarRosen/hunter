"""Active topology discovery: interrogate one device (primitive) and crawl
outward from a seed via neighbor tables (discovery).

Two layers:
  interrogate_replay / interrogate_live  — single device, returns {cmd: raw}
  TopologyCrawl                          — seed-to-frontier BFS crawl

In REPLAY mode the crawl reads from recordings/; in LIVE mode it opens real
SSH sessions via Netmiko and also writes raw output back to recordings/ so
subsequent runs can replay deterministically.

The parser and TopologyModel see no difference between modes.
"""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path
from typing import Any

import anthropic

from engine import parsers
from engine.topology_model import TopologyEvidence, TopologyModel

RECORDINGS_DIR = Path(__file__).parent.parent.parent / "recordings"

DISCOVERY_COMMANDS: list[str] = [
    "show ip route",
    "show ip arp",
    "show lldp neighbors",
    "show cdp neighbors",
]


# ------------------------------------------------------------------
# Interrogation primitive: one device → {command: raw_text}
# ------------------------------------------------------------------

def interrogate_replay(device_id: str, recordings_dir: Path) -> dict[str, str]:
    """Read all discovery command outputs from recordings for one device.

    Returns {command: raw_text} for each command that has a recording.
    Commands with no recording are absent from the dict — the caller treats
    the device as not interrogable for those commands.
    """
    result: dict[str, str] = {}
    for command in DISCOVERY_COMMANDS:
        path = _recording_path(recordings_dir, device_id, command)
        if path.exists():
            result[command] = path.read_text()
    return result


def interrogate_live(
    host: str,
    creds: dict[str, Any],
    device_type: str | None = None,
) -> dict[str, str]:
    """SSH into one device via Netmiko, run discovery commands, return {command: raw}.

    If device_type is None, autodetects via Netmiko SSHDetect before connecting.
    Commands that fail on this OS are silently skipped (not every device has
    LLDP or every routing command).

    Raises RuntimeError if netmiko is not installed.
    """
    try:
        from netmiko import ConnectHandler, SSHDetect
    except ImportError:
        raise RuntimeError("pip install netmiko to use live interrogation.")

    conn_params: dict[str, Any] = {
        "host": host,
        "username": creds.get("user", ""),
        "password": creds.get("password"),
        "key_file": creds.get("key_file"),
        "port": int(creds.get("port", 22)),
    }

    if device_type is None:
        detector = SSHDetect(**{**conn_params, "device_type": "autodetect"})
        device_type = detector.autodetect() or "linux"
        detector.connection.disconnect()

    conn_params["device_type"] = device_type
    conn = ConnectHandler(**conn_params)

    result: dict[str, str] = {}
    try:
        for command in DISCOVERY_COMMANDS:
            try:
                result[command] = conn.send_command(command)
            except Exception:
                pass  # command not supported on this OS
    finally:
        conn.disconnect()

    return result


# ------------------------------------------------------------------
# Seed-based BFS crawl
# ------------------------------------------------------------------

class TopologyCrawl:
    """BFS crawl from a seed device outward via LLDP/CDP neighbor tables.

    Each hop:
      1. Interrogate the device (replay or live) → {command: raw}
      2. Parse each raw output → normalized topology evidence
      3. Feed into TopologyModel.update()
      4. Extract neighbor device IDs from parsed LLDP/CDP evidence
      5. Enqueue unseen neighbors for the next depth level

    Devices seen in neighbor tables but that cannot be interrogated (no
    recording in REPLAY, connection failure in LIVE) are marked
    NOT_INTERROGABLE in the TopologyModel — we know they exist, we just
    cannot pull their internal state.
    """

    def __init__(
        self,
        client: anthropic.Anthropic,
        model_name: str,
        scenario: str,
        topology_model: TopologyModel,
        mode: str = "replay",
    ) -> None:
        self._client = client
        self._model_name = model_name
        self._topology_model = topology_model
        self._mode = mode
        self._recordings_dir = RECORDINGS_DIR / scenario

    def run(
        self,
        seed: str,
        seed_host: str | None = None,
        seed_creds: dict[str, Any] | None = None,
        max_depth: int = 3,
    ) -> list[str]:
        """Run the BFS crawl from the seed device.

        In REPLAY mode, seed is a device_id (matched against recordings/).
        In LIVE mode, seed_host is the IP to connect to; seed is the logical name.

        Returns the list of device IDs in crawl order (interrogated only;
        NOT_INTERROGABLE nodes are noted inline but not included in the return list).
        """
        visited: set[str] = set()
        crawl_order: list[str] = []

        # Queue entries: (device_id, host_or_None, depth)
        queue: deque[tuple[str, str | None, int]] = deque()
        queue.append((seed, seed_host, 0))

        while queue:
            device_id, host, depth = queue.popleft()

            if device_id in visited or depth > max_depth:
                continue
            visited.add(device_id)

            raw_outputs = self._interrogate(device_id, host, seed_creds or {})

            if not raw_outputs:
                reason = "no_recording" if self._mode == "replay" else "connection_failed"
                self._topology_model.mark_not_interrogable(
                    device_id=device_id,
                    discovered_via=f"LLDP/CDP at depth {depth}",
                    reason=reason,
                )
                print(f"  [depth {depth}] {device_id} — DISCOVERED / NOT_INTERROGABLE ({reason})")
                continue

            print(f"  [depth {depth}] {device_id} — {len(raw_outputs)} command(s)")
            crawl_order.append(device_id)

            if self._mode == "live":
                for command, raw in raw_outputs.items():
                    _write_recording(self._recordings_dir, device_id, command, raw)

            evidence_list: list[TopologyEvidence] = []
            for command, raw in raw_outputs.items():
                parsed = parsers.parse(raw, "ssh_cli", command, self._client, self._model_name)
                ev = TopologyEvidence(
                    device_id=device_id,
                    command=command,
                    source_type="DEVICE_REPORTED",
                    trust_tier="ssh_cli",
                    evidence_ref=f"{device_id} / {command}",
                    parsed=parsed,
                )
                self._topology_model.update(ev)
                evidence_list.append(ev)

            for neighbor_id in _extract_neighbors(evidence_list):
                if neighbor_id not in visited:
                    queue.append((neighbor_id, None, depth + 1))

        return crawl_order

    def _interrogate(
        self,
        device_id: str,
        host: str | None,
        creds: dict,
    ) -> dict[str, str]:
        if self._mode == "replay":
            return interrogate_replay(device_id, self._recordings_dir)
        if self._mode == "live":
            try:
                raw = interrogate_live(host or device_id, creds)
                return raw
            except Exception as e:
                print(f"  [live] interrogation failed ({host or device_id}): {e}")
                return {}
        raise ValueError(f"Unknown mode: {self._mode!r}")


# ------------------------------------------------------------------
# Neighbor extraction from parsed LLDP/CDP evidence
# ------------------------------------------------------------------

def _extract_neighbors(evidence_list: list[TopologyEvidence]) -> list[str]:
    """Return adjacent device IDs from LLDP/CDP parsed output.

    Normalizes to lowercase short hostname (strips domain suffix) and
    deduplicates while preserving order of first appearance.
    """
    seen: set[str] = set()
    result: list[str] = []
    for ev in evidence_list:
        for neighbor in ev.parsed.get("neighbors", []):
            raw_name = neighbor.get("device_id") or neighbor.get("neighbor_id") or ""
            short = raw_name.lower().split(".")[0].strip()
            if short and short not in seen:
                seen.add(short)
                result.append(short)
    return result


# ------------------------------------------------------------------
# Recording path helpers (shared by replay reader and live writer)
# ------------------------------------------------------------------

def _recording_path(recordings_dir: Path, device_id: str, command: str) -> Path:
    filename = re.sub(r"[^\w]+", "_", command.strip().lower()).strip("_") + ".txt"
    return recordings_dir / "ssh_cli" / device_id / filename


def _write_recording(recordings_dir: Path, device_id: str, command: str, raw: str) -> None:
    path = _recording_path(recordings_dir, device_id, command)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw)
