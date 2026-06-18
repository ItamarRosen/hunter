"""Dispatcher: translates the Hunter's free-form evidence request into
concrete protocol queries, executes them, and returns parsed evidence.

The Hunter never sees this component. All collection capabilities live here.

Flow per request_evidence call:
  1. Haiku (tool calls) decides which protocol tool(s) to invoke and with
     what exact target/command, using the network topology as context.
  2. Each tool runs — replay reads a recording; live opens a real session.
  3. Raw output is normalised by the generic parser (Haiku) to clean JSON.
  4. Results are returned with provenance + trust tier attached.

Adding a new protocol:
  1. Add an entry to COLLECTION_TOOLS (shown to Haiku for routing).
  2. Add its trust tier to TRUST_TIERS.
  3. Implement _<protocol>_replay and/or _<protocol>_live as methods.
  4. Register them in __init__ under self._handlers.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

import anthropic

from engine import parsers
from engine.evidence import EvidenceResponse

RECORDINGS_DIR = Path(__file__).parent.parent / "recordings"
SIZE_LIMIT = 8_000  # chars; truncate and signal the Hunter if exceeded

# Maps tool name → trust tier label returned to the Hunter.
TRUST_TIERS: dict[str, str] = {
    "ssh_cli":       "ssh_cli",        # device self-reporting, medium trust
    "snmp_get":      "snmp",           # device self-reporting, medium trust
    "netflow_query": "netflow",        # off-device collector, higher trust
    "oob_tap":       "off_device_tap", # independent vantage, highest trust
    "host_edr":      "host_edr",       # local agent, lower trust
}

# Ordered from highest trust (index 0) to lowest trust (last index).
_TRUST_RANK = [
    "off_device_tap", "netflow", "ssh_cli", "snmp",
    "syslog", "vendor_api", "host_edr", "host_agent", "unknown",
]

COLLECTION_TOOLS = [
    {
        "name": "ssh_cli",
        "description": (
            "Run a CLI command on a network device via SSH. Use for routers, "
            "switches, firewalls, and any infrastructure that exposes a CLI."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target":  {"type": "string", "description": "Device ID from the topology."},
                "command": {"type": "string", "description": "Exact CLI command, e.g. 'show ip route'."},
            },
            "required": ["target", "command"],
        },
    },
    {
        "name": "snmp_get",
        "description": (
            "Query a device via SNMP. Use for interface counters, system info, "
            "and other MIB-accessible metrics."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Device ID from the topology."},
                "oid":    {"type": "string", "description": "SNMP OID or MIB object name."},
            },
            "required": ["target", "oid"],
        },
    },
    {
        "name": "netflow_query",
        "description": (
            "Query NetFlow/IPFIX records for traffic flow data. Use for "
            "communication patterns, volumes, and external destinations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target":     {"type": "string", "description": "NetFlow collector or exporter device ID."},
                "filter":     {"type": "string", "description": "Flow filter, e.g. 'src 10.0.1.0/24'."},
                "time_range": {"type": "string", "description": "Time range, e.g. 'last 24h'."},
            },
            "required": ["target", "filter"],
        },
    },
]

_DISPATCHER_SYSTEM = """\
You are an evidence dispatcher for a network security investigation.

Given an investigator's free-form request and the network topology, decide what
data to collect using the available tools. You may call multiple tools if the
request covers multiple devices or data types.

Use exact device IDs from the topology. Use exact CLI commands or query strings.
Do not interpret or analyse the request — just translate it into precise collection actions."""

# A handler takes the full inputs dict and returns (found, raw_text).
Handler = Callable[[dict], tuple[bool, str]]


class Dispatcher:
    """Routes Hunter requests to concrete protocol tools and returns parsed evidence.

    Credentials never touch any LLM — fetched from the CredentialStore at
    connection time and held in the session pool.
    """

    def __init__(
        self,
        client: anthropic.Anthropic,
        topology: dict[str, Any],
        scenario: str,
        model: str = "claude-haiku-4-5-20251001",
        mode: str = "replay",
        credential_store: CredentialStore | None = None,
    ) -> None:
        self._client = client
        self._topology = topology
        self._model = model
        self._mode = mode
        self._recordings_dir = RECORDINGS_DIR / scenario
        self._sessions: dict[tuple[str, str], Any] = {}
        self._creds = credential_store or _NullCredentialStore()

        if mode == "replay":
            self._handlers: dict[str, Handler] = {
                "ssh_cli": self._ssh_cli_replay,
            }
        elif mode == "live":
            self._handlers = {
                "ssh_cli": self._ssh_cli_live,
            }
        else:
            raise ValueError(f"Unknown dispatcher mode: {mode!r}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, description: str) -> EvidenceResponse:
        tool_calls = self._route(description)
        if not tool_calls:
            return EvidenceResponse(
                found=False,
                data="",
                note="Dispatcher could not map this request to a collection action.",
            )

        parts: list[str] = []
        tiers: list[str] = []
        any_found = False

        for tool_name, inputs in tool_calls:
            found, raw = self._run_tool(tool_name, inputs)
            target = inputs.get("target", "?")
            query  = inputs.get("command") or inputs.get("oid") or inputs.get("filter", "")
            tier   = TRUST_TIERS.get(tool_name, "unknown")

            if not found:
                parts.append(f"[{tool_name} | target={target} | query={query!r} → NOT FOUND: {raw}]")
                continue

            any_found = True
            tiers.append(tier)
            parsed = parsers.parse(raw, tool_name, query, self._client, self._model)
            parts.append(
                f"[source={target} | protocol={tool_name} | query={query!r} | trust={tier}]\n"
                + json.dumps(parsed, indent=2)
            )

        note = f"trust_tier={_min_trust(tiers)}" if tiers else "no data returned"
        return EvidenceResponse(found=any_found, data="\n\n".join(parts), note=note)

    def close(self) -> None:
        """Close all open sessions."""
        for session in self._sessions.values():
            try:
                session.close()
            except Exception:
                pass
        self._sessions.clear()

    # ------------------------------------------------------------------
    # Routing — Haiku decides which tool(s) to invoke
    # ------------------------------------------------------------------

    def _route(self, description: str) -> list[tuple[str, dict]]:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=512,
            system=_DISPATCHER_SYSTEM,
            tools=COLLECTION_TOOLS,
            tool_choice={"type": "auto"},
            messages=[{
                "role": "user",
                "content": (
                    f"Network topology:\n{json.dumps(self._topology, indent=2)}\n\n"
                    f"Investigator request: {description}"
                ),
            }],
        )
        return [
            (block.name, block.input)
            for block in response.content
            if block.type == "tool_use"
        ]

    # ------------------------------------------------------------------
    # Tool execution — registry dispatch
    # ------------------------------------------------------------------

    def _run_tool(self, name: str, inputs: dict) -> tuple[bool, str]:
        handler = self._handlers.get(name)
        if handler is None:
            return False, f"'{name}' not available in {self._mode!r} mode."
        return handler(inputs)

    # -- Replay handlers -----------------------------------------------

    def _ssh_cli_replay(self, inputs: dict) -> tuple[bool, str]:
        target  = inputs["target"]
        command = inputs.get("command") or inputs.get("cmd") or inputs.get("query", "")
        if not command:
            return False, "ssh_cli requires a command."
        filename = re.sub(r"[^\w]+", "_", command.strip().lower()).strip("_") + ".txt"
        path = self._recordings_dir / "ssh_cli" / target / filename
        if not path.exists():
            return False, f"No recording at ssh_cli/{target}/{filename}"
        raw = path.read_text()
        if len(raw) > SIZE_LIMIT:
            raw = raw[:SIZE_LIMIT] + f"\n\n[TRUNCATED at {SIZE_LIMIT} chars — refine your query]"
        return True, raw

    # -- Live handlers -------------------------------------------------

    def _ssh_cli_live(self, inputs: dict) -> tuple[bool, str]:
        target  = inputs["target"]
        command = inputs.get("command") or inputs.get("cmd") or inputs.get("query", "")
        if not command:
            return False, "ssh_cli requires a command."
        key = ("ssh", target)
        if key not in self._sessions:
            creds = self._creds.get("ssh", target)
            if creds is None:
                return False, f"No SSH credentials for {target}."
            try:
                from netmiko import ConnectHandler
            except ImportError:
                raise RuntimeError("pip install netmiko to use live SSH collection.")
            self._sessions[key] = ConnectHandler(
                device_type=creds.get("device_type", "cisco_ios"),
                host=creds.get("host", target),
                username=creds["user"],
                password=creds.get("password"),
                key_file=creds.get("key_file"),
                port=int(creds.get("port", 22)),
            )
        try:
            return True, self._sessions[key].send_command(command)
        except Exception as e:
            return False, str(e)


# ------------------------------------------------------------------
# Credential store
# ------------------------------------------------------------------

class CredentialStore:
    """Credential lookup interface. Secrets never reach any LLM."""

    def get(self, protocol: str, target: str) -> dict | None:
        raise NotImplementedError


class _NullCredentialStore(CredentialStore):
    def get(self, protocol: str, target: str) -> dict | None:
        return None


class EnvCredentialStore(CredentialStore):
    """Loads credentials from a JSON file or the HUNTER_CREDS environment variable."""

    def __init__(self, path: str | Path | None = None) -> None:
        import os
        raw = os.environ.get("HUNTER_CREDS") or (
            Path(path).read_text() if path and Path(path).exists() else "{}"
        )
        self._store: dict = json.loads(raw)

    def get(self, protocol: str, target: str) -> dict | None:
        return self._store.get(protocol, {}).get(target)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _min_trust(tiers: list[str]) -> str:
    """Return the least-trusted tier in the list."""
    rank = lambda t: _TRUST_RANK.index(t) if t in _TRUST_RANK else len(_TRUST_RANK)
    return max(tiers, key=rank)
