"""Stage 1 — credential-free network scanner.

No credentials, no prior knowledge: reads the local interface, pings the subnet,
re-reads the ARP cache, TCP-connects management ports, reverse-DNS resolves, then
classifies each host as endpoint or infrastructure and marks seed candidates.

All discovered hosts are fed into the TopologyModel as SCAN_OBSERVED evidence,
a new mid-low trust tier sitting below DEVICE_REPORTED (which requires credentials
and SSH access) and well below TAP_OBSERVED (which requires an independent vantage).

ARP presence is the more reliable sub-case: a host must have sent a real L2 frame
to appear here. Port/fingerprint data is what the device chose to advertise.

No extra dependencies — uses Python stdlib + macOS/Linux built-in tools only.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engine.topology_model import TopologyEvidence, TopologyModel

RECORDINGS_DIR = Path(__file__).parent.parent.parent / "recordings"

# Management ports we probe — presence is the main infrastructure signal.
MGMT_PORTS: dict[int, str] = {
    22:   "ssh",
    23:   "telnet",
    80:   "http",
    179:  "bgp",
    443:  "https",
    161:  "snmp",       # UDP — checked separately
    8080: "http-alt",
    8443: "https-alt",
    8291: "winbox",     # MikroTik
    8728: "routeros",   # MikroTik API
}

# OUI prefixes (first 8 chars of MAC, lowercase) known to belong to network gear.
# Not exhaustive — a hit strongly suggests infrastructure; a miss is inconclusive.
_INFRA_OUIS: set[str] = {
    "00:00:0c", "00:1a:70", "00:17:5a", "58:f3:9c",  # Cisco
    "00:1b:17", "00:26:0b", "2c:6b:f5",              # Juniper
    "68:ff:7b", "f0:9f:c2", "ec:08:6b", "50:c7:bf",  # TP-Link
    "00:1e:14", "f4:ce:46", "24:a4:3c", "80:2a:a8",  # Ubiquiti
    "a8:f9:4b", "00:0b:86", "94:b4:0f",              # Aruba / HPE
    "ac:84:c6", "dc:9f:db", "6c:3b:6b",              # MikroTik
    "00:09:0f", "08:5b:0e", "90:6c:ac",              # Fortinet
    "b8:27:eb", "dc:a6:32", "e4:5f:01",              # Raspberry Pi (often FRR)
    "00:0f:4b", "00:a0:c9",                           # Intel NIC (some routers)
}

_INFRA_PORTS: set[int] = {22, 23, 161, 179, 8291, 8728}

# Abbreviated OUI → vendor name for display.
_OUI_VENDOR: dict[str, str] = {
    "00:00:0c": "Cisco",     "00:1a:70": "Cisco",
    "00:1b:17": "Juniper",   "00:26:0b": "Juniper",
    "68:ff:7b": "TP-Link",   "f0:9f:c2": "TP-Link",   "ec:08:6b": "TP-Link",
    "00:1e:14": "Ubiquiti",  "f4:ce:46": "Ubiquiti",  "24:a4:3c": "Ubiquiti",
    "a8:f9:4b": "Aruba",
    "ac:84:c6": "MikroTik",  "dc:9f:db": "MikroTik",
    "00:09:0f": "Fortinet",
    "b8:27:eb": "RPi",       "dc:a6:32": "RPi",       "e4:5f:01": "RPi",
}


@dataclass
class ScannedHost:
    ip: str
    mac: str = ""
    mac_vendor: str = ""
    hostname: str = ""
    open_ports: list[int] = field(default_factory=list)
    mgmt_protocols: list[str] = field(default_factory=list)
    classification: str = "endpoint"
    seed_candidate: bool = False
    discovery_methods: list[str] = field(default_factory=list)


class NetworkScanner:
    """Credential-free Stage 1 scanner: ARP sweep → port scan → classify."""

    def __init__(self, scenario: str = "scan_live") -> None:
        self._scenario = scenario

    def scan_segment(
        self,
        subnet: str | None = None,
        topology_model: TopologyModel | None = None,
        port_timeout: float = 0.5,
        ping_workers: int = 64,
        port_workers: int = 32,
    ) -> list[ScannedHost]:
        """Full Stage 1 pass: discover, enrich, classify, optionally feed model."""
        if subnet is None:
            subnet = detect_local_subnet()

        print(f"[scan] subnet: {subnet}")

        hosts: dict[str, ScannedHost] = {}

        # Seed from existing ARP cache — fast, no probing.
        _read_arp_cache(hosts)
        print(f"[scan] ARP cache: {len(hosts)} host(s)")

        # Ping sweep to discover additional live hosts and populate ARP cache.
        print(f"[scan] ping sweep ({ping_workers} workers)…")
        _ping_sweep(subnet, hosts, workers=ping_workers)
        _read_arp_cache(hosts)
        print(f"[scan] after sweep: {len(hosts)} host(s)")

        # TCP connect scan on management ports.
        print(f"[scan] port scan ({port_workers} workers, timeout={port_timeout}s)…")
        _port_scan(list(hosts.values()), timeout=port_timeout, workers=port_workers)

        # Reverse-DNS and classify.
        for host in hosts.values():
            if not host.hostname:
                host.hostname = _rdns(host.ip)
            host.mac_vendor = _oui_vendor(host.mac)
            host.classification = _classify(host)
            host.seed_candidate = (
                host.classification == "infrastructure"
                and bool(host.mgmt_protocols)
            )

        result = sorted(hosts.values(), key=lambda h: _ip_sort_key(h.ip))

        if topology_model is not None:
            _feed_model(topology_model, result, subnet)

        return result


# ------------------------------------------------------------------
# Network interface detection
# ------------------------------------------------------------------

def detect_local_subnet() -> str:
    """Parse ifconfig to find the active private interface and return its subnet."""
    try:
        out = subprocess.check_output(["ifconfig", "-a"], text=True, timeout=5)
    except Exception:
        return "192.168.0.0/24"

    for block in re.split(r"\n(?=\S)", out):
        # Skip loopback and inactive interfaces.
        if "lo0" in block or "LOOPBACK" in block or "status: inactive" in block:
            continue
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[\da-f]+|\d+\.\d+\.\d+\.\d+)", block)
        if not m:
            continue
        ip = m.group(1)
        if ip.startswith("127.") or not _is_private(ip):
            continue
        netmask_raw = m.group(2)
        if netmask_raw.startswith("0x"):
            n = int(netmask_raw, 16)
            netmask = ".".join(str((n >> (24 - i * 8)) & 0xFF) for i in range(4))
        else:
            netmask = netmask_raw
        try:
            return str(ipaddress.ip_interface(f"{ip}/{netmask}").network)
        except ValueError:
            continue

    return "192.168.0.0/24"


# ------------------------------------------------------------------
# Host discovery
# ------------------------------------------------------------------

def _read_arp_cache(hosts: dict[str, ScannedHost]) -> None:
    try:
        out = subprocess.check_output(["arp", "-a", "-n"], text=True, timeout=5)
    except Exception:
        return
    for line in out.splitlines():
        # macOS: ? (192.168.0.1) at 68:ff:7b:15:59:68 on en0 ...
        m = re.match(r"\S+ \((\d+\.\d+\.\d+\.\d+)\) at ([\da-f:]{17})", line)
        if m:
            ip, mac = m.group(1), m.group(2)
            if ip not in hosts:
                hosts[ip] = ScannedHost(ip=ip)
            hosts[ip].mac = mac
            _add_method(hosts[ip], "arp_cache")


def _ping_sweep(subnet: str, hosts: dict[str, ScannedHost], workers: int = 64) -> None:
    network = ipaddress.ip_network(subnet, strict=False)
    ips = [str(ip) for ip in list(network.hosts())[:510]]

    def ping(ip: str) -> None:
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "500", ip],
                capture_output=True, timeout=2,
            )
            if r.returncode == 0:
                if ip not in hosts:
                    hosts[ip] = ScannedHost(ip=ip)
                _add_method(hosts[ip], "ping")
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(ping, ips))


# ------------------------------------------------------------------
# Port scanning
# ------------------------------------------------------------------

def _port_scan(hosts: list[ScannedHost], timeout: float = 0.5, workers: int = 32) -> None:
    def scan_one(host: ScannedHost) -> None:
        for port, proto in MGMT_PORTS.items():
            if port == 161:
                continue  # UDP — skip for TCP scan
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                connected = s.connect_ex((host.ip, port)) == 0
                s.close()
                if connected and port not in host.open_ports:
                    host.open_ports.append(port)
                    host.mgmt_protocols.append(proto)
            except Exception:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(scan_one, hosts))


# ------------------------------------------------------------------
# Classification
# ------------------------------------------------------------------

def _classify(host: ScannedHost) -> str:
    oui = host.mac[:8].lower()
    if oui in _INFRA_OUIS:
        return "infrastructure"
    if set(host.open_ports) & _INFRA_PORTS:
        return "infrastructure"
    return "endpoint"


# ------------------------------------------------------------------
# TopologyModel integration
# ------------------------------------------------------------------

def _feed_model(topology_model: TopologyModel, hosts: list[ScannedHost], subnet: str) -> None:
    nodes = [
        {
            "ip": h.ip,
            "mac": h.mac,
            "mac_vendor": h.mac_vendor,
            "hostname": h.hostname,
            "open_ports": h.open_ports,
            "mgmt_protocols": h.mgmt_protocols,
            "classification": h.classification,
            "seed_candidate": h.seed_candidate,
            "discovery_methods": h.discovery_methods,
        }
        for h in hosts
    ]
    topology_model.update(TopologyEvidence(
        device_id=f"scan:{subnet}",
        command="ping_sweep+arp+port_scan",
        source_type="SCAN_OBSERVED",
        trust_tier="scan_observed",
        evidence_ref=f"Stage 1 scan of {subnet}",
        parsed={"nodes": nodes},
    ))


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _oui_vendor(mac: str) -> str:
    return _OUI_VENDOR.get(mac[:8].lower(), "")


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (0, 0, 0, 0)


def _add_method(host: ScannedHost, method: str) -> None:
    if method not in host.discovery_methods:
        host.discovery_methods.append(method)
