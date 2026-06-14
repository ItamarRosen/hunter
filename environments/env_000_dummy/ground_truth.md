# Ground truth — env_000_dummy

This network has been compromised. The intrusion below is the planted incident the Hunter is meant to uncover. The "current date" for this environment is 2026-06-12 (see `topology.json`) — all timeline events fall in the few days prior, well within a "last 7 days" or "last 2 weeks" query window.

## Overview

A phishing email opened on FIN-ALICE (ws01) led to a backdoor, credential theft, lateral movement to the domain controller (dc01), persistence on the DC, and exfiltration of Finance documents from the file server (fs01) — all over the course of a few hours overnight on 2026-06-09, preceded by initial access on 2026-06-08.

## Timeline

**2026-06-08, ~14:32 (Mon, business hours)** — *Initial access*
Alice Chen (achen) receives an email with subject "Invoice #84512 — Payment Overdue" from a spoofed vendor address, with attachment `Invoice_84512.xlsm`. She opens it and enables macros. The macro drops `winupdate32.exe` into `C:\Users\achen\AppData\Roaming\Microsoft\Windows\winupdate32.exe` and adds a Run-key persistence entry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper` pointing at it. The backdoor begins beaconing to `185.220.101.47` over HTTPS (443), roughly every 5 minutes.

**2026-06-09, ~02:14 (Tue, off-hours)** — *Credential access on ws01*
Via the backdoor, the attacker briefly spawns a process (`svchost_helper.exe`) that accesses `lsass.exe` on ws01 and dumps credential material. Among the recovered credentials are cached domain credentials for `CORP\bnguyen` (Bob Nguyen, IT admin) — Bob had RDP'd into ws01 on 2026-06-05 for a support ticket, leaving his credentials cached on the machine.

**2026-06-09, ~02:31 (Tue, off-hours)** — *Lateral movement to dc01*
Using `CORP\bnguyen`'s credentials, the attacker opens an RDP session (logon type 10, RemoteInteractive) from ws01 (10.10.10.21) to dc01 (10.10.0.10). This is anomalous on two counts: it's ~5.5 hours outside Bob's normal working hours, and it originates from Alice's workstation rather than Bob's own (IT-BOB, 10.10.10.35) — Bob is not logged into anything at this time.

**2026-06-09, ~02:40 (Tue, off-hours)** — *Persistence on dc01*
From the dc01 session, the attacker:
- Creates a scheduled task named `MicrosoftEdgeUpdateTaskMachine`, running `powershell.exe -enc <base64>` daily at 03:00, which re-establishes a connection to `185.220.101.47`.
- Creates a new local account `svc_backup` on dc01 and adds it to the local Administrators group, as a secondary persistence mechanism.

**2026-06-09, ~02:55–03:10 (Tue, off-hours)** — *Exfiltration via fs01*
Still using `CORP\bnguyen`'s session on dc01, the attacker connects via SMB to `\\CORP-FS01\Finance\Confidential` (fs01, 10.10.0.20) and copies several files — Q2 financial statements, a payroll spreadsheet, and draft M&A documents — to a staging folder `C:\Windows\Temp\sysdiag\` on dc01. The staged files are compressed into `sysdiag_2026-06-09.zip`, which is then uploaded to `185.220.101.47` via the scheduled task's outbound connection at ~03:10.

**2026-06-10 onward** — *Dormancy*
The ws01 backdoor continues its ~5-minute beacon to `185.220.101.47`, low-and-slow, blending into normal outbound web traffic. The dc01 scheduled task fires daily at 03:00 as configured. No further escalation has occurred as of the current date (2026-06-12).

## Indicators of compromise / reference tags

Use these tags in `ground_truth_refs` when a response embeds the corresponding evidence:

| Tag | Indicator |
|---|---|
| `phishing_email` | Email "Invoice #84512 — Payment Overdue", attachment `Invoice_84512.xlsm`, on ws01, 2026-06-08 ~14:32 |
| `backdoor_ws01` | `C:\Users\achen\AppData\Roaming\Microsoft\Windows\winupdate32.exe`, Run key `WindowsUpdateHelper`, process `svchost_helper.exe` |
| `c2_ip` | External IP `185.220.101.47`, HTTPS/443 beacon (~5 min interval) from ws01 and (daily 03:00) from dc01 |
| `credential_theft` | LSASS access on ws01 by `svchost_helper.exe`, ~02:14 2026-06-09 |
| `lateral_movement_rdp` | RDP logon (type 10) to dc01, source 10.10.10.21, account `CORP\bnguyen`, 2026-06-09 ~02:31 |
| `persistence_scheduled_task` | Scheduled task `MicrosoftEdgeUpdateTaskMachine` on dc01, runs `powershell.exe -enc <base64>` daily at 03:00 |
| `persistence_local_account` | New local admin account `svc_backup` created on dc01 |
| `exfil_fs01` | SMB access to `\\CORP-FS01\Finance\Confidential` from dc01 under `bnguyen`, ~02:55–03:10 2026-06-09; staging at `C:\Windows\Temp\sysdiag\sysdiag_2026-06-09.zip` on dc01 |

## Baseline / normal activity

Use this to generate plausible "nothing to see here" responses for requests that don't intersect the incident above.

- **Working hours**: Mon–Fri, 08:00–18:00 local. Most interactive logons cluster 07:45–09:00 and 17:00–18:30.
- **Alice Chen (achen)**: logs into ws01 only. Normal activity: Outlook, Excel, browser (finance SaaS sites), periodic SMB reads from `\\CORP-FS01\Finance` (not `Confidential`) during business hours.
- **Bob Nguyen (bnguyen)**: IT admin with domain admin rights. Normal activity: RDP sessions to dc01, fs01, and various workstations *during business hours* for support — these are routine and not suspicious on their own. The 2026-06-09 ~02:31 RDP to dc01 from ws01's IP is the anomaly (time + source), not the account or destination in isolation.
- **fs01**: routine SMB traffic from workstations during business hours. A legitimate nightly backup job runs 01:00–01:45 (account `CORP\svc_backupjob`, reads from all shares, writes to a backup target) — a separate, pre-existing process not connected to the incident. Don't treat all off-hours fs01 activity as automatically suspicious; this backup job is normal.
- **dc01**: routine AD/DNS query traffic, periodic GPO refreshes, normal admin logons from bnguyen during business hours.
- **fw01**: normal outbound HTTPS to common SaaS/cloud destinations from workstations; no notable inbound beyond the site-to-site VPN. No prior alerts or incidents on this network.
