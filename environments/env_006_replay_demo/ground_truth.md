# Ground Truth: env_006_replay_demo

## What's really happening

edge-rtr01 has been compromised. An attacker added an unauthorized static host
route (`S 185.211.34.90/32 via 172.16.0.1`) on or around 2026-06-10, with no
change ticket. 185.211.34.90 is a known C2 IP (Abuse.ch blocklist).

Interface counters on the WAN uplink (GigabitEthernet0/3) show ~48 Mbps
outbound against only ~2.3 Mbps inbound — a ~20:1 egress:ingress ratio
inconsistent with normal admin activity and consistent with bulk exfiltration.

The core router (core-rtr01) and firewall (fw01) are unaffected.

## Decisive evidence

- `static_route_c2`: `S 185.211.34.90/32 [1/0] via 172.16.0.1` in
  edge-rtr01's routing table
- `wan_uplink_high_egress`: GigabitEthernet0/3 5-min output rate 48,234,000
  bits/sec vs 2,341,000 bits/sec input; cumulative output 892 GB vs 14 GB
  input

## What a correct investigation looks like

1. Checks edge-rtr01 routing table → finds the /32 static route to 185.211.34.90
2. Checks interface counters → finds the anomalous egress ratio on the WAN uplink
3. Optionally checks core-rtr01 → confirms the suspicious route is absent there
   (edge-only, not propagated via OSPF — consistent with manual insertion)
4. Submits: compromise confirmed, edge-rtr01, unauthorized static route +
   high-egress evidence, high confidence
