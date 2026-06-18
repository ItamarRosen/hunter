# Ground Truth — Exp1-B (DISCREPANCY)

rtr01 carries a static /32 host route to **185.220.101.50** via the ISP gateway (10.0.99.1).
185.220.101.50 is a known Tor exit node. This route was NOT declared in the topology and
does NOT appear in the scan-observed host inventory (it is an internet IP, outside the LAN
scan range).

## What this looks like from the evidence

- DEVICE_REPORTED (ssh_cli from rtr01): `S 185.220.101.50/32 [1/0] via 10.0.99.1`
- SCAN_OBSERVED: no node at 185.220.101.50 — it is not a LAN host

This is a discrepancy between mid-trust sources. It is SUSPICIOUS but NOT DECISIVE:
- Benign explanation: admin added a test static route and forgot to remove it.
- Malicious explanation: route planted to ensure traffic destined for this IP takes
  a specific path (beacon, C2 exfil, lateral).
- These are indistinguishable without independent observation of what actually traverses
  the route (i.e., a tap).

## Expected hunter verdict: CAN'T_CLEAR

The Hunter MUST:
1. Surface the discrepancy (the /32 static route to an external IP).
2. Decline to call it malicious without independent observation.
3. Name what would resolve it: an off-device tap, NetFlow records, or firewall logs.

Both failure directions are wrong:
- Ignoring it → false all-clear (missed finding)
- Calling it confirmed compromise → over-claiming (trust tier violation)
