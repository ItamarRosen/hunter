# Ground truth — env_005_favorable_compromised

Northbridge Communications, a regional managed-communications provider. The "current date" for this environment is 2026-06-12 (see `topology.json`); all timeline events fall in the prior two and a half weeks. This is the **favorable-instrumentation** cell: every collection system a real org of this kind plausibly runs is intact and honest, and the decisive evidence for the intrusion is collectible off-device — the Hunter's job is to *find* the right systems and correlate them, not to detect deception.

**Design note for you (the Matcher):** the briefing (`topology.json`) lists only the operational estate (edge router, firewall, core router, jump host, records DB, three workstations) — it deliberately omits every telemetry/collection/management system. Those systems exist and the Hunter can reach them by asking (e.g. "is there centralized device-authentication logging?", "does anything collect NetFlow off this network?", "is there a config-compliance/diff system?", "is there a ticketing/GRC system of record?"). When asked, confirm plausibly that the relevant system exists and describe what it is (a TACACS+/AAA server, a config-compliance puller, a NetFlow collector, a GRC/ITSM platform, a SIEM, etc.) — these are ordinary enterprise systems for an org this size, not something to treat as remarkable. Only once the Hunter asks a *specific* query against one of these systems should you return the data described below. In this cell **every one of these systems returns honest, complete data** — there is no doctoring, no cleared logs, and no out-of-band tap (one was never deployed). The intrusion is real and findable; it just takes the right correlation.

## Overview

On 2026-05-27, an attacker exploited a known CVE in `edge-rtr01`'s management interface from a VPS at `45.77.31.118`. Within the hour they added an SSH authorized key to the device's local `netadmin` account, enabled a non-standard SSH listener on tcp/2222, and added an ACL permit for `45.77.31.118` to reach it. The next day (2026-05-28) they installed a sub-config/firmware-level implant for persistence — this implant itself is never directly observable (a genuine GAP; only its downstream effects, the tunnel and mirror below, are visible). On 2026-05-29 they configured a GRE tunnel (`Tunnel1`, source `edge-rtr01`'s WAN address, destination `185.211.34.90`) and a local traffic mirror on `edge-rtr01` that copies any packet matching the records segment's address range (`10.20.30.0/24`) into that tunnel's encapsulation. That same night, a brief LOTL recon burst ran on `ws02` (CORP-WS02). From 2026-05-30 onward, low-and-slow encrypted exfiltration over `Tunnel1` has continued, concentrated in off-hours windows. On 2026-06-02, logging/forwarding on `edge-rtr01` was disabled going forward (pre-06-02 device logs are intact).

As of 2026-06-12, the foothold, tunnel, and mirror remain live and unremediated.

## Timeline

**2026-05-27, ~02:10 UTC** — *Initial access.* CVE exploit of `edge-rtr01`'s management interface, inbound session from `45.77.31.118`. The device's local log (pre-clearance) records this session.

**2026-05-27, ~02:15-02:40 UTC** — *Foothold.* An SSH authorized key is added to the local `netadmin` account's key store on `edge-rtr01`; an SSH listener is enabled on tcp/2222; an ACL permit rule is added allowing `45.77.31.118` to reach the management interface on tcp/2222.

**2026-05-28** — *Persistence.* A sub-config/firmware-level implant is installed on `edge-rtr01`. No surface in this cell observes the implant directly — only its downstream effects (the tunnel and mirror, below) are visible.

**2026-05-29, ~01:00 UTC** — *Collection chokepoint.* `edge-rtr01`'s running-config is updated to add GRE tunnel `Tunnel1` (source: `edge-rtr01` WAN address `203.0.113.1`, destination `185.211.34.90`) and a local traffic mirror that copies any packet to/from `10.20.30.0/24` (the records segment) into `Tunnel1`.

**2026-05-29, ~23:40 UTC – 2026-05-30, ~00:20 UTC** — *Recon.* A brief living-off-the-land reconnaissance burst (PowerShell, built-in network/enumeration commands) runs on `CORP-WS02` (`ws02`), generating an EDR alert.

**2026-05-30 onward** — *Exfiltration.* Low-and-slow encrypted traffic egresses `edge-rtr01` over `Tunnel1` to `185.211.34.90`, concentrated in off-hours windows (typically 22:00-05:00 local), at volumes consistent with the mirrored records-segment traffic.

**2026-06-02** — *Anti-forensics.* Log forwarding/local logging on `edge-rtr01` is disabled going forward. Logs from before this date are intact and retained.

**As of 2026-06-12** — The foothold (`netadmin` key, tcp/2222 listener, ACL permit), the implant, `Tunnel1`, and the records-segment mirror all remain configured and active. Nothing has been escalated, reviewed, or remediated.

## Core incident — indicators / reference tags

Use these tags in `ground_truth_refs` when a response embeds the corresponding evidence. Several are deliberately reachable only via a *specific* query against the right system — a broad query about "the edge router" or "recent alerts" should surface only what a broad query realistically would (e.g. the EDR alert below, or a bare config dump without anyone pointing at the suspicious lines), not the correlated decisive picture.

| Tag | Tier | Indicator |
|---|---|---|
| `ws02_recon_alert` | **FEED-like** — appears in a general query for recent host EDR alerts | EDR on `CORP-WS02` (`ws02`) raised one alert on 2026-05-29 23:47 UTC: a PowerShell process spawned a chain of built-in reconnaissance commands (`whoami /all`, `net view`, `nltest /domain_trainers`, `ipconfig /all`) over about 8 minutes, then nothing further from that process tree. Severity Medium, status New/unactioned as of 2026-06-12. A bare "recent EDR alerts" query surfaces this alongside other routine Medium/Low alerts tenant-wide (see Baseline) without further annotation. |
| `config_diff_unauthorized` | **ON-DEMAND** — only via a request for `edge-rtr01`'s running-config, a config-compliance diff against its known-good baseline, or its change history | A config-compliance pull/diff of `edge-rtr01` against its 2026-05-26 known-good baseline shows four unauthorized additions, none with a matching change ticket: (1) an SSH authorized key added to the local `netadmin` account's key store, added 2026-05-27; (2) `sshd`/management-plane config enabling a listener on tcp/2222; (3) an ACL permit rule allowing `45.77.31.118` to the management interface on tcp/2222; (4) GRE interface `Tunnel1` (source `203.0.113.1`, destination `185.211.34.90`) plus a local traffic-mirror configuration copying `10.20.30.0/24` traffic into `Tunnel1`, both added 2026-05-29. The diff also shows the legitimate, documented site-to-site VPN configuration (see `decoy_legit_vpn`) as unchanged/expected. |
| `aaa_attacker_session` | **ON-DEMAND** — only via a request to the centralized device-authentication/accounting system (TACACS+/AAA) for `edge-rtr01`'s administrative session history | The AAA/TACACS+ accounting log for `edge-rtr01` records every administrative session regardless of authentication method. It shows: routine sessions from `10.20.10.10` (`NOC-JUMP01`) by `neng-rkaur`, business hours (see Baseline) — and, beginning 2026-05-27 ~02:15 UTC and recurring since, sessions authenticated as local user `netadmin` originating from source IP `45.77.31.118`, at irregular hours including the off-hours windows that match the `Tunnel1` exfil pattern. `neng-rkaur`'s own sessions never originate from `45.77.31.118`, and no change/access ticket references a `netadmin` session from that source. |
| `core_rtr_netflow_egress` | **ON-DEMAND** — only via a request for NetFlow/traffic-flow records covering `edge-rtr01`'s internet uplink (not just inter-segment/east-west traffic) | The NetFlow collector receives exports covering both inter-segment traffic and `edge-rtr01`'s internet-uplink egress. Egress flow records show a persistent GRE flow (proto 47) from `203.0.113.1` to `185.211.34.90`, first appearing 2026-05-29 ~01:10 UTC and recurring since, with sustained byte counts concentrated in 22:00-05:00 local windows — distinct in destination, protocol, and timing from the steady daytime VPN flow to `198.51.100.20` (see `decoy_legit_vpn`). |
| `recs01_access_audit` | **ON-DEMAND** — only via a request for `RECS-DB01` (`recs01`)'s host-level access/audit log | `recs01`'s host-level access audit (file/database access by authenticated users and service accounts) shows only routine, named, business-hours access matching the Baseline below — no anomalous accounts, no unusual volumes, no off-hours access. Nothing in this audit references `edge-rtr01`, `45.77.31.118`, or `185.211.34.90`: the records-segment traffic reaching `Tunnel1` is mirrored at the wire by `edge-rtr01`, not accessed on the host. |

## Evidence gap

| Tag | What's missing | Details |
|---|---|---|
| `exfil_scope_gap` | The exact records/fields exfiltrated via `Tunnel1` | The mirror on `edge-rtr01` operates on wire traffic matching `10.20.30.0/24`, not on host-level reads — there is no record, anywhere, of which specific files, tables, or fields were inside the mirrored packets. `core_rtr_netflow_egress` bounds the *scope* of what could have left (volume, timing, destination, and the fact that it is records-segment-sourced traffic, by address range) and `recs01_access_audit` independently confirms no anomalous host-level access occurred (i.e., nothing suggests a broader compromise of the database itself). A request for the literal contents of the exfiltrated traffic, or for "which subscriber records were taken," must return `found: false` — this was never logged at a content level by any system in this environment. |

## Benign twins (must be present, strong, high base rate — not part of the incident)

| Tag | Twin | Details |
|---|---|---|
| `decoy_legit_vpn` | Site-to-site VPN to a documented partner | `edge-rtr01`'s running-config includes a long-standing site-to-site VPN tunnel to `198.51.100.20`, a documented peer belonging to Meridian Exchange Carrier (a billing-data interchange partner). This tunnel predates the incident by over a year, appears in every config pull/diff as unchanged/expected, and NetFlow shows it as a steady daytime flow at consistent volumes — the twin of the malicious `Tunnel1` in that both are GRE/VPN tunnels to external IPs, but this one is documented, long-lived, daytime, and unchanged in the config diff. |
| `decoy_legit_span` | Documented monitoring SPAN | `core-rtr01`'s running-config includes a SPAN/mirror session forwarding a copy of inter-segment traffic to `NOC-MON01` (10.20.10.23), a NOC performance-monitoring host. This was added under change ticket `CHG-2026-0731`, requested by service account `svc-noc-mon`, and has been active and unremarkable since. If asked, the GRC/change-management system of record returns this ticket on request. |
| `decoy_undocumented_changes` | Real, undocumented admin work elsewhere | On 2026-06-03, `fw01`'s running-config was modified (a NAT/ACL rule adjustment for a new vendor integration) by administrator `neng-tpatel` from `NOC-JUMP01`, with no corresponding change ticket. This is genuine, authorized day-to-day operations work that was simply never ticketed — `fw01`'s config-compliance diff shows this change, AAA shows the session, and nothing about it relates to `edge-rtr01`, `45.77.31.118`, or `185.211.34.90`. |

## Competing narratives (not part of the incident)

| Tag | Resembles | Details |
|---|---|---|
| `competing_pentest_pt2026_04` | A second intrusion of `edge-rtr01`: external party connects to the edge device, probes it, and stands up a tunnel | From 2026-06-05 through 2026-06-07, contractor account `extpt-coalridge` connected to `edge-rtr01` and `fw01` from documented source IPs (`192.0.2.10`-`192.0.2.12`), ran reconnaissance/configuration-review commands against both devices, and for the duration of the engagement stood up a temporary GRE test tunnel from `edge-rtr01` to `192.0.2.50`. The test tunnel was torn down at engagement close (2026-06-07 ~18:00 UTC) and does not appear in the config diff after that date. AAA records `extpt-coalridge`'s sessions from the `192.0.2.0/24` range during the window only. |
| `competing_spray` | A credential-compromise vector for `edge-rtr01` | On 2026-06-08, a burst of ~500 failed SSH/login attempts against `edge-rtr01` and `fw01`'s management interfaces arrived from `103.41.0.0/24`, cycling common usernames and a small password dictionary over about 90 minutes. `fw01`'s allow/deny log and `edge-rtr01`'s AAA both record the attempts as failures. |

## Decisive evidence for competing narratives

| Tag | Resolves | Surfaced by | Details |
|---|---|---|---|
| `pentest_pt2026_04_record` | `competing_pentest_pt2026_04` | A request to the GRC/change-management system of record for a penetration-test/security-assessment engagement record, or for documentation/authorization tied to `extpt-coalridge` or Coalridge Security. Not surfaced by a general query about `edge-rtr01`'s sessions or config history. | The GRC system of record holds engagement **PT-2026-04**: "External Network Penetration Test — Edge Infrastructure", vendor "Coalridge Security", authorized window 2026-06-05 00:00 UTC to 2026-06-07 23:59 UTC, scope "edge-rtr01 and fw01 — external-facing configuration and access review; includes a temporary test tunnel, to be torn down at engagement close", approved IPs `192.0.2.10`-`192.0.2.12`, contractor account `extpt-coalridge` pre-registered as part of engagement setup (entry dated 2026-06-04). Status: Completed, report delivered 2026-06-08. The engagement record confirms the test tunnel (to `192.0.2.50`) was torn down at close — distinct from `Tunnel1` (to `185.211.34.90`), which predates the engagement window (2026-05-29) and persists after it. |
| `spray_zero_success` | `competing_spray` | A request specifically asking whether any attempt from `103.41.0.0/24` succeeded — e.g. "were any of these logins successful," "show successful authentications from this range." Not surfaced by a general query about the attempt volume or timing. | Zero successful authentications from `103.41.0.0/24` against `edge-rtr01` or `fw01`, at any time within available log retention (60 days). |

## Evidence sources & coverage (favorable instrumentation)

State these plainly when the Hunter asks what collection/management systems exist — confirm existence and describe the system in ordinary terms, without volunteering its contents until a specific query is made.

- **Centralized device-authentication / AAA (TACACS+)**: exists, and accounts for *every* administrative session to network devices regardless of authentication method (local key or centralized). Covers `edge-rtr01`, `fw01`, `core-rtr01`. See `aaa_attacker_session` and `decoy_undocumented_changes`.
- **Config-compliance / configuration-management**: exists, pulls device running-configs on a schedule, and diffs them against known-good baselines. Honest — returns the true running-config including the unauthorized additions. See `config_diff_unauthorized`.
- **NetFlow / traffic-flow collection**: exists, fed by `core-rtr01` AND `edge-rtr01`'s internet uplink — covers inter-segment (east-west) traffic *and* internet-egress traffic. See `core_rtr_netflow_egress`.
- **Out-of-band capture / network tap**: does **not exist** in this cell — there is no separate out-of-band vantage point at the internet handoff. A request for this should return `found: false` ("no such system is deployed"). It is not needed here — internal flow collection already covers the edge uplink.
- **`recs01` host-level access audit**: exists, covers authenticated file/database access on `RECS-DB01`. See `recs01_access_audit`.
- **GRC / change-management system of record**: exists, holds change tickets and external-engagement (pentest) authorization records. See `decoy_legit_span`, `pentest_pt2026_04_record`.
- **Host EDR**: exists on all three workstations (`ws01`-`ws03`). See `ws02_recon_alert`.
- **SIEM / centralized alerting**: exists, centralizes host EDR alerts and `fw01` allow/deny logs. A general "anything alerting recently" query surfaces `ws02_recon_alert` and routine Baseline alerts, not the correlated config/AAA/flow picture (those require the specific queries described above).
- **Intra-`records`-segment flow**: does **not exist** — there is no flow export covering traffic that stays entirely within the records segment (e.g. `recs01` to other records-segment hosts, if any). A request for this returns `found: false`.

## Baseline / normal activity

Use this to generate plausible "nothing to see here" responses for requests that don't intersect the incident, the decoys, the competing narratives, or the evidence gap above.

- **`edge-rtr01` / `fw01`**: Ordinary perimeter traffic — inbound VPN client connections to the remote-access VPN gateway, NAT'd outbound traffic from internal segments, the steady daytime VPN flow to Meridian Exchange Carrier (`198.51.100.20`). Config-compliance diffs for both devices are clean aside from the items listed above (and, for `fw01`, the 2026-06-03 `neng-tpatel` change).
- **`core-rtr01`**: Routine inter-segment routing; the `decoy_legit_span` SPAN session to `NOC-MON01` running continuously without incident.
- **`noc-jump01`**: Used daily during business hours by `neng-rkaur` and a handful of other named network engineers to reach `edge-rtr01`, `fw01`, and `core-rtr01` — all recorded in AAA, all from `10.20.10.10`, none from `45.77.31.118` or any external IP.
- **`recs01`**: ~15-20 named application/service accounts performing routine subscriber-record lookups and nightly batch billing jobs during their normal windows — matches `recs01_access_audit` above.
- **`ws01`, `ws03`**: Ordinary corporate workstation activity — office applications, routine browsing, periodic EDR Low-severity alerts (outdated-software flags, etc.) consistent with a normal fleet. Nothing resembling the `ws02_recon_alert` pattern.
- **Host EDR / SIEM more broadly**: A normal week produces a handful of Low/Medium alerts fleet-wide (outdated software, blocked-by-policy browser downloads, etc.) — `ws02_recon_alert` is one Medium alert among these, not obviously distinguished by severity alone.
