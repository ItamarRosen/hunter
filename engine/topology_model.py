"""TopologyModel: trust-tiered map of observed network state.

Evidence flows in from the ActiveDiscoveryCollector (source_type='DEVICE_REPORTED')
and in future from other sources (NMS imports, static config baselines, ...).
The model computes discrepancies between observed state and the declared topology.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any


@dataclass
class DiscoveredNode:
    """A device seen in LLDP/CDP/ARP but whose internal state could not be pulled."""
    device_id: str
    discovered_via: str  # e.g. "LLDP/CDP at depth 1"
    reason: str          # "no_recording" | "connection_failed" | "unsupported_device_type"


@dataclass
class TopologyEvidence:
    device_id: str
    command: str
    source_type: str      # "DEVICE_REPORTED" | "STATIC_CONFIG" | ...
    trust_tier: str       # "ssh_cli" | "snmp" | "off_device_tap" | ...
    evidence_ref: str     # human-readable provenance, e.g. "edge-rtr01 / show ip route"
    parsed: dict          # normalized output from engine.parsers.parse()


class TopologyModel:
    """Trust-tiered live network map built from multiple evidence sources.

    Call update() to ingest evidence; query snapshot() for the merged view and
    discrepancies() for items that conflict with or are absent from the
    declared static topology.
    """

    def __init__(self, static_topology: dict[str, Any]) -> None:
        self._static = static_topology
        self._evidence: list[TopologyEvidence] = []
        self._not_interrogable: list[DiscoveredNode] = []

        self._known_device_ids: set[str] = {
            d["id"] for d in static_topology.get("devices", [])
        }
        self._known_networks: list[ipaddress.IPv4Network] = [
            ipaddress.ip_network(s["cidr"], strict=False)
            for s in static_topology.get("segments", [])
        ]

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def update(self, evidence: TopologyEvidence) -> None:
        self._evidence.append(evidence)

    def mark_not_interrogable(self, device_id: str, discovered_via: str, reason: str) -> None:
        """Record a device seen in neighbor tables that could not be interrogated."""
        self._not_interrogable.append(DiscoveredNode(device_id, discovered_via, reason))

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Merged view of all collected evidence, annotated with provenance."""
        nodes: list[dict] = []
        routes: list[dict] = []
        arp_entries: list[dict] = []
        neighbors: list[dict] = []

        for ev in self._evidence:
            prov = {"_device": ev.device_id, "_trust": ev.trust_tier, "_ref": ev.evidence_ref}
            for n in ev.parsed.get("nodes", []):
                nodes.append({**n, **prov})
            for r in ev.parsed.get("routes", []):
                routes.append({**r, **prov})
            for a in ev.parsed.get("arp_entries", []):
                arp_entries.append({**a, **prov})
            for n in ev.parsed.get("neighbors", []):
                neighbors.append({**n, **prov})

        return {
            "nodes": nodes,
            "routes": routes,
            "arp_entries": arp_entries,
            "neighbors": neighbors,
            "evidence_sources": [
                {
                    "device": ev.device_id,
                    "command": ev.command,
                    "trust_tier": ev.trust_tier,
                    "source_type": ev.source_type,
                }
                for ev in self._evidence
            ],
        }

    def not_interrogable_nodes(self) -> list[dict[str, Any]]:
        """Devices discovered via LLDP/CDP/ARP but whose internal state could not be pulled."""
        return [
            {"device_id": n.device_id, "discovered_via": n.discovered_via, "reason": n.reason}
            for n in self._not_interrogable
        ]

    def discrepancies(self) -> list[dict[str, Any]]:
        """Items that conflict with or are absent from the declared topology.

        Checks two categories:
        - external_route: any route (any type) to a public IP destination
        - undocumented_segment: a STATIC route to an internal subnet not in the topology
        - unknown_neighbor: LLDP/CDP neighbor not listed in the topology devices
        """
        result: list[dict] = []

        for ev in self._evidence:
            for route in ev.parsed.get("routes", []):
                disc = _check_route(route, ev, self._known_networks)
                if disc:
                    result.append(disc)

            for neighbor in ev.parsed.get("neighbors", []):
                disc = _check_neighbor(neighbor, ev, self._known_device_ids)
                if disc:
                    result.append(disc)

        return result


# ------------------------------------------------------------------
# Per-item checks
# ------------------------------------------------------------------

def _check_route(
    route: dict,
    ev: TopologyEvidence,
    known_networks: list[ipaddress.IPv4Network],
) -> dict | None:
    dest = route.get("destination", "")
    if not dest:
        return None
    try:
        net = ipaddress.ip_network(dest, strict=False)
    except ValueError:
        return None

    if net.prefixlen == 0:
        return None  # default route

    if _is_external(net):
        return {
            "type": "external_route",
            "severity": "high" if net.prefixlen == 32 else "medium",
            "device": ev.device_id,
            "trust_tier": ev.trust_tier,
            "detail": (
                f"Route to external IP {dest} via {route.get('next_hop', '?')} "
                f"(type={route.get('type', '?')})"
            ),
            "evidence_ref": ev.evidence_ref,
            "route": route,
        }

    route_type = route.get("type", "")
    if (
        route_type.startswith("S")
        and 8 <= net.prefixlen <= 30
        and not _in_known_segments(net, known_networks)
    ):
        return {
            "type": "undocumented_segment",
            "severity": "low",
            "device": ev.device_id,
            "trust_tier": ev.trust_tier,
            "detail": f"Static route to segment {dest} not declared in topology",
            "evidence_ref": ev.evidence_ref,
            "route": route,
        }

    return None


def _check_neighbor(
    neighbor: dict,
    ev: TopologyEvidence,
    known_device_ids: set[str],
) -> dict | None:
    raw_name = neighbor.get("device_id") or neighbor.get("neighbor_id") or ""
    short_name = raw_name.lower().split(".")[0]
    if not short_name or short_name in known_device_ids:
        return None
    return {
        "type": "unknown_neighbor",
        "severity": "medium",
        "device": ev.device_id,
        "trust_tier": ev.trust_tier,
        "detail": (
            f"LLDP/CDP neighbor '{raw_name}' on {ev.device_id} "
            f"port {neighbor.get('local_interface', '?')} not in topology"
        ),
        "evidence_ref": ev.evidence_ref,
        "neighbor": neighbor,
    }


# ------------------------------------------------------------------
# Network classification helpers
# ------------------------------------------------------------------

_RFC1918: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]


def _is_external(net: ipaddress.IPv4Network) -> bool:
    return not any(net.subnet_of(rfc) for rfc in _RFC1918)


def _in_known_segments(net: ipaddress.IPv4Network, known: list[ipaddress.IPv4Network]) -> bool:
    return any(net.subnet_of(k) or k.subnet_of(net) or net.overlaps(k) for k in known)
