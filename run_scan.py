#!/usr/bin/env python
"""Stage 1: credential-free network discovery — runs live, no credentials needed.

ARP cache + ping sweep → TCP port scan → classify → mark seed candidates.
Feeds every discovered node into the TopologyModel as SCAN_OBSERVED.

Usage:
  python run_scan.py [subnet]          # e.g. 192.168.0.0/24
  python run_scan.py                   # auto-detect local subnet
"""

from __future__ import annotations

import sys
from pathlib import Path

from engine.collectors.scan import NetworkScanner, detect_local_subnet
from engine.topology_model import TopologyModel

ROOT = Path(__file__).parent


def main(subnet: str | None = None) -> None:
    if subnet is None:
        subnet = detect_local_subnet()

    topo_model = TopologyModel(static_topology={"devices": [], "segments": []})
    scanner = NetworkScanner(scenario="scan_live")

    hosts = scanner.scan_segment(
        subnet=subnet,
        topology_model=topo_model,
    )

    # ---- Device list ---------------------------------------------------
    print(f"\n\n{'='*64}")
    print(f"  Discovered devices on {subnet}  ({len(hosts)} hosts)")
    print(f"{'='*64}")

    for h in hosts:
        tag = ""
        if h.seed_candidate:
            tag = "  *** SEED CANDIDATE"
        elif h.classification == "infrastructure":
            tag = "  [infrastructure]"
        print(f"\n  {h.ip:<16}  {h.mac or '??:??:??:??:??:??':<17}  "
              f"{h.mac_vendor or '':12}  {h.classification}{tag}")
        if h.hostname:
            print(f"    hostname:  {h.hostname}")
        if h.mgmt_protocols:
            ports_str = "  ".join(f"{p}:{MGMT_PORTS_DISPLAY.get(p, p)}" for p in h.open_ports)
            print(f"    mgmt:      {ports_str}")
        print(f"    found by:  {', '.join(h.discovery_methods)}")

    # ---- Seed candidates -----------------------------------------------
    seeds = [h for h in hosts if h.seed_candidate]
    print(f"\n\n{'='*64}")
    print(f"  Seed candidates ({len(seeds)})")
    print(f"  (infrastructure devices with reachable management ports)")
    print(f"{'='*64}")

    if not seeds:
        print("\n  None found — no infrastructure device with an open management port.")
        print("  Options: check credentials for router, or widen port list.")
    else:
        for h in seeds:
            protos = ", ".join(h.mgmt_protocols)
            print(f"\n  {h.ip}  ({h.mac_vendor or 'unknown vendor'})")
            print(f"    hostname:    {h.hostname or '—'}")
            print(f"    mgmt ports:  {protos}")
            print(f"    needs creds: {_cred_hint(h.mgmt_protocols)}")

    # ---- Topology model nodes ------------------------------------------
    snapshot = topo_model.snapshot()
    print(f"\n\n{'='*64}")
    print(f"  TopologyModel  ({len(snapshot['nodes'])} SCAN_OBSERVED nodes)")
    print(f"{'='*64}")
    for n in snapshot["nodes"]:
        seed_flag = "  [SEED CANDIDATE]" if n.get("seed_candidate") else ""
        print(f"  {n['ip']:<16}  {n['classification']:<14}{seed_flag}")


MGMT_PORTS_DISPLAY = {
    22: "ssh", 23: "telnet", 80: "http", 179: "bgp",
    443: "https", 8080: "http-alt", 8443: "https-alt",
    8291: "winbox", 8728: "routeros",
}


def _cred_hint(protocols: list[str]) -> str:
    if "ssh" in protocols:
        return "SSH (username + password or key)"
    if "telnet" in protocols:
        return "Telnet (username + password)"
    if "snmp" in protocols:
        return "SNMP community string"
    return "check open ports above"


if __name__ == "__main__":
    subnet_arg = sys.argv[1] if len(sys.argv) > 1 else None
    main(subnet_arg)
