#!/usr/bin/env python
"""Replay-mode demo: seed-based topology crawl via TopologyCrawl.

Starts from a single seed device, interrogates it, discovers adjacent devices
via LLDP/CDP neighbor tables, and crawls outward until the frontier empties or
max_depth is reached.  Devices found in neighbor tables but with no recording
are marked DISCOVERED / NOT_INTERROGABLE.

Prints:
  - Crawl order (seed → depth-1 neighbors → depth-2 ...)
  - TopologyModel snapshot (routes, ARP, neighbors across all interrogated devices)
  - Discrepancies vs the declared topology
  - NOT_INTERROGABLE nodes (coverage gaps)

Usage:
  python run_discovery.py [scenario] [seed_device_id]
  python run_discovery.py env_006_replay_demo edge-rtr01
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from engine.collectors.discovery import TopologyCrawl
from engine.topology_model import TopologyModel

ROOT = Path(__file__).parent
ENVIRONMENTS_DIR = ROOT / "environments"

PARSER_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_SEED = "edge-rtr01"


def main(scenario_name: str = "env_006_replay_demo", seed: str = DEFAULT_SEED) -> None:
    load_dotenv()
    client = anthropic.Anthropic()

    topology_path = ENVIRONMENTS_DIR / scenario_name / "topology.json"
    if not topology_path.exists():
        sys.exit(f"No topology.json at {topology_path}")
    topology = json.loads(topology_path.read_text())

    topo_model = TopologyModel(static_topology=topology)
    crawl = TopologyCrawl(
        client=client,
        model_name=PARSER_MODEL,
        scenario=scenario_name,
        topology_model=topo_model,
        mode="replay",
    )

    # ---- Crawl ---------------------------------------------------------
    print(f"Scenario:  {scenario_name}")
    print(f"Seed:      {seed}")
    print(f"Mode:      replay\n")
    print("Crawl log:")
    crawl_order = crawl.run(seed=seed, max_depth=3)

    print(f"\nCrawl order: {' → '.join(crawl_order)}")

    # ---- Snapshot ------------------------------------------------------
    print(f"\n\n{'='*60}")
    print("  TopologyModel Snapshot")
    print(f"{'='*60}")
    snapshot = topo_model.snapshot()

    print(f"\nEvidence sources ({len(snapshot['evidence_sources'])}):")
    for src in snapshot["evidence_sources"]:
        print(f"  {src['device']:12}  {src['command']:<24}  [{src['trust_tier']}]")

    if snapshot["routes"]:
        print(f"\nRoutes ({len(snapshot['routes'])}):")
        for r in snapshot["routes"]:
            via = r.get("next_hop") or "—"
            print(
                f"  {r.get('type', '?'):5}  {r.get('destination', '?'):22}"
                f"  via {via:18}  [{r['_device']}]"
            )

    if snapshot["arp_entries"]:
        print(f"\nARP entries ({len(snapshot['arp_entries'])}):")
        for a in snapshot["arp_entries"]:
            print(
                f"  {a.get('ip', '?'):16}  {a.get('mac', '?'):18}"
                f"  {a.get('interface', '?'):<22}  [{a['_device']}]"
            )

    if snapshot["neighbors"]:
        print(f"\nLLDP/CDP neighbors ({len(snapshot['neighbors'])}):")
        for n in snapshot["neighbors"]:
            print(
                f"  {n.get('device_id', '?'):16}"
                f"  local={n.get('local_interface', '?'):12}"
                f"  remote={n.get('remote_interface', '?'):12}"
                f"  [{n['_device']}]"
            )

    # ---- Discrepancies -------------------------------------------------
    print(f"\n\n{'='*60}")
    print("  Discrepancies")
    print(f"{'='*60}")
    discs = topo_model.discrepancies()
    if not discs:
        print("\nNone found.")
    else:
        for d in discs:
            sev = d.get("severity", "?").upper()
            print(f"\n  [{sev}] {d['type']}")
            print(f"    Device:  {d['device']}  (trust={d['trust_tier']})")
            print(f"    Detail:  {d['detail']}")
            print(f"    Ref:     {d['evidence_ref']}")

    # ---- Coverage gaps -------------------------------------------------
    not_interrogable = topo_model.not_interrogable_nodes()
    if not_interrogable:
        print(f"\n\n{'='*60}")
        print("  NOT_INTERROGABLE (discovered but no data pulled)")
        print(f"{'='*60}")
        for n in not_interrogable:
            print(f"\n  {n['device_id']}")
            print(f"    Discovered via:  {n['discovered_via']}")
            print(f"    Reason:          {n['reason']}")
            print(f"    Coverage:        DEVICE_REPORTED state unknown — "
                  f"treat as unverified, not clean")


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "env_006_replay_demo"
    seed = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_SEED
    main(scenario, seed)
