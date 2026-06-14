# Ground truth — env_001_noisy

This network has been compromised. The intrusion below is the planted incident the Hunter is meant to uncover — it is the **same incident** as in `env_000_dummy`, unchanged in timeline, techniques, and indicators. What's different in this environment is the surrounding noise: more devices, more users, and a set of deliberate **benign lookalikes** (decoys) that resemble pieces of the real incident but are unrelated, legitimate activity. The "current date" for this environment is 2026-06-12 (see `topology.json`) — all timeline events fall in the few days prior, well within a "last 7 days" or "last 2 weeks" query window.

## Overview

A phishing email opened on FIN-ALICE (ws01) led to a backdoor, credential theft, lateral movement to the domain controller (dc01), persistence on the DC, and exfiltration of Finance documents from the file server (fs01) — all over the course of a few hours overnight on 2026-06-09, preceded by initial access on 2026-06-08. This is the real, ground-truth incident and should be reported in full, exactly as in env_000.

Layered on top of this incident, this environment contains a larger cast of devices and users going about ordinary business, several of whom happen to do things that — in isolation — pattern-match against pieces of the real incident (an odd Run-key entry, an off-hours RDP session, a newly-created local admin account, a bulk zip-and-upload job, other phishing emails, etc.). None of these are part of the intrusion. A good investigation should surface the real incident in full *and* correctly avoid escalating these look-alikes into findings.

## Timeline (unchanged from env_000)

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

## Indicators of compromise / reference tags (unchanged from env_000)

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

## Benign lookalikes / decoys (NEW in env_001 — not part of the incident)

These are real, legitimate activities in this environment that happen to resemble one of the IOCs above. **They are not evidence of compromise.** When a request would plausibly surface one of these, weave it in as ordinary, explainable activity — don't hint that it's a decoy, and don't have it lead anywhere. If a response surfaces one of these, set `embeds_ground_truth` to `false` (it is not incident evidence) but include the matching tag below in `ground_truth_refs`, so engagement with red herrings can be tracked separately from engagement with the real incident.

| Tag | Lookalike for | Details |
|---|---|---|
| `decoy_c2_beacon` | `c2_ip` | ws05 (ENG-MIKE) runs a signed third-party dev-telemetry agent (`DevTelemetryAgent.exe`, part of a CI/CD toolchain Mike uses) that beacons over HTTPS/443 roughly every 5 minutes to `52.94.236.248`, a well-known AWS-owned IP serving the vendor's telemetry endpoint (resolves cleanly via reverse DNS to the vendor's domain). Same cadence and protocol as the real C2 beacon, but a different, attributable, reputable destination and a signed process. |
| `decoy_persistence_tool` | `backdoor_ws01` | ws04 (HR-PRIYA) has an unsigned binary `C:\Users\psharma\AppData\Roaming\CorpTools\HRPortalSync.exe`, with a Run-key entry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HRSyncAgent`. This was pushed via GPO by IT in 2025 to sync HR records with the HR portal on srv02; it's unsigned, lives under AppData, and has a generic name — superficially similar shape to `backdoor_ws01` — but it's a known, documented internal tool (helpdesk ticket HD-2025-1187 covers its deployment) with no network activity beyond HTTPS to srv02 during business hours. |
| `decoy_lsass_access` | `credential_theft` | Every workstation (ws01–ws06) runs the corporate EDR agent (`CorpEDR.exe`), whose credential-protection module periodically opens `lsass.exe` with `PROCESS_QUERY_LIMITED_INFORMATION` to monitor for credential-dumping tools — logged several times per day on every host, including ws01. This is routine background noise. The real `credential_theft` finding (svchost_helper.exe doing a full `comsvcs.dll` MiniDump of lsass.exe at 02:14 on ws01) is a distinct, much more invasive access from a different, unsigned process — it should stand out against this EDR baseline, not be confused with it. |
| `decoy_offhours_rdp` | `lateral_movement_rdp` | On 2026-06-07 (Sun) at ~23:40, a pre-provisioned third-party MSP support account (`CORP\msp_vendor`, restricted rights, no domain admin) RDPs (logon type 10) into srv02 (CORP-APP01) from a known vendor IP range over the VPN, to apply a patch per change ticket CHG-2026-0512. Off-hours + RDP + an unusual account — like the real lateral movement — but a different night, different account, different destination, and fully documented in change management. |
| `decoy_scheduled_task` | `persistence_scheduled_task` | dc01 (and most other Windows hosts) also has the genuine, pre-existing scheduled task `MicrosoftEdgeUpdateTaskMachineCore`, auto-created by the Edge browser installer, running `"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c` on Microsoft's randomized daily update schedule. Its name is a near-match for the malicious `MicrosoftEdgeUpdateTaskMachine` task, so a name-based search for "Edge update task" returns both — only the one without `Core` and running `powershell.exe -enc` is malicious. |
| `decoy_new_admin_account` | `persistence_local_account` | On 2026-06-10, Sarah Kim (skim, IT/security) creates a new local account `svc_monitoring` on srv02 and srv03 and adds it to the local Administrators group on both, as part of rolling out a new monitoring agent (change ticket CHG-2026-0520). Same "new local admin account created within days of the incident" shape as `svc_backup` on dc01, but on different hosts, created during business hours by a known admin, and tied to a documented change. |
| `decoy_bulk_backup_upload` | `exfil_fs01` | Every Sunday at 04:00, srv03 (CORP-BKP01) runs a scheduled job (`CloudBackupSync`, running as `svc_backupjob`) that reads all departmental shares from fs01 — including `Finance\Confidential` — compresses them into a dated archive (e.g. `weekly_backup_2026-06-07.zip`), and uploads it via HTTPS to `backup.corp-cloudvault.com`, an allow-listed third-party backup provider. Same "bulk SMB read across shares, zip, upload over HTTPS" shape as the real exfiltration, but on a recurring documented schedule, by a known service account, to a sanctioned destination — not 185.220.101.47. |
| `decoy_phishing_noise` | `phishing_email` | On 2026-06-08, the mail gateway / spam filter log shows three other "Invoice" / "Payment overdue"-themed phishing emails from spoofed vendor domains, also delivered that day to ws03 (dpark), ws04 (psharma), and bws01 (treilly). Two were quarantined by the spam filter before delivery; the one that reached psharma was seen and reported via the "Report Phishing" button, with no attachment opened and no process execution. Phishing attempts against multiple staff on this date are common background noise — only Alice's (ws01) resulted in an opened attachment and macro execution. |

## Baseline / normal activity

Use this to generate plausible "nothing to see here" responses for requests that don't intersect the incident or the decoys above.

- **Working hours**: Mon–Fri, 08:00–18:00 local at HQ. Most interactive logons cluster 07:45–09:00 and 17:00–18:30. The branch office (bws01) keeps the same hours but is one timezone behind HQ.
- **Alice Chen (achen, ws01, Finance)**: logs into ws01 only. Normal activity: Outlook, Excel, browser (finance SaaS sites), periodic SMB reads from `\\CORP-FS01\Finance` (not `Confidential`) during business hours.
- **Bob Nguyen (bnguyen, ws02, IT admin)**: domain admin rights. Normal activity: RDP sessions to dc01, fs01, srv02, srv03, and various workstations *during business hours* for support — routine and not suspicious on their own. The 2026-06-09 ~02:31 RDP to dc01 from ws01's IP is the anomaly (time + source), not the account or destination in isolation.
- **David Park (dpark, ws03, Sales)**: logs into ws03 only. Normal activity: CRM SaaS (Salesforce-like), Outlook, video-call apps, occasional VPN calls with the branch office. Targeted by one of the decoy phishing emails (quarantined).
- **Priya Sharma (psharma, ws04, HR)**: logs into ws04 only. Normal activity: Outlook, the HR portal and payroll system on srv02, periodic SMB reads from `\\CORP-FS01\HR`. Runs the `HRPortalSync.exe` tool (decoy_persistence_tool) continuously in the background. Received and reported one of the decoy phishing emails.
- **Mike Torres (mtorres, ws05, Engineering)**: logs into ws05 only, holds local admin rights on his own workstation for development work. Normal activity: IDE, local dev servers, GitHub, CI/CD tooling, and the `DevTelemetryAgent.exe` beacon (decoy_c2_beacon). Occasional SSH/RDP to a dev environment not otherwise modeled here.
- **Sarah Kim (skim, ws06, IT/security)**: domain admin rights alongside bnguyen; manages the EDR console (CorpEDR) and runs periodic vulnerability scans during business hours. Created the `svc_monitoring` account on 2026-06-10 (decoy_new_admin_account) as part of a documented monitoring rollout.
- **Tom Reilly (treilly, bws01, branch Sales)**: logs into bws01 only. Normal activity: Outlook, CRM SaaS, occasional VPN-based RDP to srv02 for expense reports. Received and reported one of the decoy phishing emails. No prior incidents at the branch.
- **fs01**: routine SMB traffic from workstations during business hours across Finance, HR, Sales, and IT shares. A legitimate nightly backup job runs 01:00–01:45 (account `CORP\svc_backupjob`, reads from all shares, writes to srv03) — pre-existing, not connected to the incident. The same account also runs the weekly Sunday 04:00 cloud-upload job (decoy_bulk_backup_upload). Don't treat all off-hours fs01 activity as automatically suspicious.
- **dc01**: routine AD/DNS query traffic, periodic GPO refreshes, normal admin logons from bnguyen and skim during business hours, plus the benign `MicrosoftEdgeUpdateTaskMachineCore` task (decoy_scheduled_task).
- **srv02 (CORP-APP01)**: routine HTTPS traffic from HR/Finance workstations (psharma, achen's read-only access) during business hours for the HR portal and expense system. Hosts the `svc_monitoring` account (decoy_new_admin_account) and was the target of the decoy off-hours MSP RDP session on 2026-06-07.
- **srv03 (CORP-BKP01)**: receives the nightly 01:00–01:45 backup writes from fs01 via svc_backupjob, and runs the weekly Sunday 04:00 cloud-upload job (decoy_bulk_backup_upload). Also hosts the `svc_monitoring` account.
- **fw01**: normal outbound HTTPS to common SaaS/cloud destinations from all workstations (including the decoy_c2_beacon traffic from ws05, which resolves cleanly); the site-to-site VPN to bfw01 carries routine branch traffic plus the decoy MSP RDP session to srv02. No prior alerts or incidents on this network.
- **bfw01 / branch office**: NATs bws01's traffic out locally and carries HQ-bound traffic over the VPN to fw01. No notable inbound beyond the VPN tunnel.
