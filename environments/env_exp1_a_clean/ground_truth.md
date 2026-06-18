# Ground Truth — Exp1-A (CLEAN)

This network is NOT compromised. All topology sources are consistent:

- rtr01 carries only connected routes (LAN + WAN uplink) and a default route to the ISP gateway.
- ARP cache on rtr01 shows exactly the three expected LAN hosts (rtr01, sw01, ws01) plus the ISP gateway.
- LLDP shows sw01 as the only neighbor, consistent with the declared topology.
- The Stage 1 scan found exactly the three LAN hosts. No unexpected nodes.
- No static host routes to external IPs exist.

Expected hunter verdict: **NO_FINDING**
