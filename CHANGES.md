# env_003 validity fixes — GAP 1-3, plus env_004

This document records what changed for each validity gap identified after the
first env_003 run (`runs/env_003_wrong_story_20260614T133031Z/`), and the
acceptance check performed for each. GAP 4 is a new environment,
`env_004_cloud_identity_lotl` — see bottom.

No changes were made to the real incident's timeline, indicators, or the
genuine EID 4104 evidence gap; they remain regression anchors.

---

## GAP 1 — Briefing no longer leaks the verdict

**File:** `environments/env_003_wrong_story/topology.json`

Three edits, each removing an editorializing/meta tell while keeping every
device, segment, and factual relationship unchanged.

### 1. Top-level `name`

```diff
- "name": "env_003_wrong_story",
+ "name": "Corporate network — HQ and branch office",
```

The old name was dumped verbatim into the Hunter-visible briefing and
literally told the Hunter the premise of the scenario ("wrong story").

### 2. Top-level `description`

```diff
- "description": "Same mid-sized corporate network as env_001/env_002
-   (perimeter firewall, domain controller, six workstations across multiple
-   departments, a file server, an internal app server, a backup server, and
-   a branch office over site-to-site VPN), with a third layer of concurrent
-   security activity — including a louder, EDR-alerting incident at the
-   branch office — that competes for the investigator's attention.",
+ "description": "A mid-sized corporate network: a perimeter firewall, an
+   Active Directory domain controller, six workstations spanning Finance,
+   IT, Sales, HR, and Engineering, a file server, an internal application
+   server, a backup server, and a branch office connected to HQ over a
+   site-to-site VPN.",
```

Removed: "with a third layer of concurrent security activity," "a louder,
EDR-alerting incident at the branch office," and "competes for the
investigator's attention" — all of which point straight at
`competing_redteam_nightingale` and tell the Hunter that the branch office
is where the *other* activity is, and that it's louder/alert-generating
(i.e., not the real story). All devices, segments, and roles from the
original description are preserved, just stated plainly.

### 3. `ws06` (`IT-SARAH`) device `notes`

```diff
- "notes": "Primary workstation for Sarah Kim, IT/security analyst. Holds
-   domain admin rights alongside Bob Nguyen, manages the EDR console, and
-   periodically runs security-validation exercises.",
+ "notes": "Primary workstation for Sarah Kim, IT/security analyst. Holds
+   domain admin rights alongside Bob Nguyen and administers the corporate
+   EDR platform.",
```

Removed: "periodically runs security-validation exercises" — this directly
foreshadows `competing_ws06_edr_alert` (the EDR-validation procdump alert on
this same host) as a sanctioned test. The remaining text (admin rights, runs
the EDR platform) is necessary factual context — Sarah's role explains why an
EDR alert on her own machine would be reviewed/actioned quickly, without
telling the Hunter in advance that this specific alert is a drill.

### Everything else audited, unchanged

All other segments and devices (`fw01`, `dc01`, `ws01`-`ws05`, `fs01`,
`srv02`, `srv03`, `bfw01`, `bws01`) were reviewed and contain no
characterization of any activity as loud/quiet/benign/authorized/a
test/a distraction — only roles, hostnames, OSes, IPs, and business
function. In particular, `bws01` (the branch-office workstation that hosts
`competing_redteam_nightingale`) and `srv03` (which hosts the legitimate
nightly/weekly backup jobs behind `decoy_bulk_backup_upload`) remain fully
present, described only in terms of role — regional sales rep / branch
office / VPN access for `bws01`, and backup-job account / weekly cloud-upload
job for `srv03`.

### Acceptance check

Read the edited `topology.json` top to bottom as the Hunter would see it: it
describes a plain mid-sized corporate network (HQ + branch office, standard
roles) with no hint that an incident exists, where it might be, or that any
host's activity is pre-validated as authorized/a test. Verified valid JSON
(`json.load` via the project's `.venv` interpreter).

---

## GAP 2 — Evidence-path scoring (earned vs. guessed verdicts)

**New/changed files:**
- `environments/env_003_wrong_story/ground_truth.md` — added a
  "Decisive evidence for competing narratives" section (Monitor-only, never
  shown to the Hunter).
- `environments/env_003_wrong_story/rubric.json` — new file, 20 items.
- `engine/prompts/grader_system.md` — new file.
- `engine/scoring.py` — new file.
- `score_hunt.py` — new root-level CLI.

### ground_truth.md additions

Added two new tags, each specifying the *only* evidence request that
surfaces the decisive evidence, and what is returned if it's requested:

- `competing_redteam_nightingale_auth` — surfaced only by an IAM/AD lookup
  for the `sec_redteam` account or a ticket/email query for `SEC-2026-0085`;
  returns the AD provisioning record (scoped to srv02, expires 2026-06-15)
  and the "Assumed Breach Exercise — Kickoff" email. Explicitly **not**
  surfaced by telemetry requests about bws01/srv02 alone.
- `competing_ws06_edr_alert_disposition` — surfaced only by a request about
  the EDR alert's disposition/ticket on ws06; returns the alert's
  auto-remediation, analyst review by `skim`, and ticket `SEC-2026-0091`
  (Resolved). Explicitly **not** surfaced by raw LSASS-telemetry requests on
  ws06 alone.

This makes "the account name looks like a red team" / "the C2 IP has a clean
VT score" / "procdump fired an EDR alert that auto-remediated" — all surface
cues already present in general telemetry — insufficient to "earn" the
correct verdict on either competing narrative.

### rubric.json

Each of the 20 items (8 core incident, 8 decoy, 3 competing narrative, 1
evidence gap) carries:

- `encounter_tags` — `ground_truth_refs` tag(s) that indicate the item was
  surfaced at all.
- `decisive_evidence_tags` — tag(s) that indicate the *decisive* evidence was
  surfaced. For 18 items these are identical to `encounter_tags` (there's only
  one way to surface them, and doing so is decisive). For the two competing
  narratives above, `decisive_evidence_tags` points at the new
  `*_auth` / `*_disposition` tags — distinct from, and a strict superset
  requirement beyond, `encounter_tags`.
- `correct_label` — the correct **verdict only** (e.g., "authorized red team
  exercise, not part of the real intrusion"), with no mention of what it must
  be grounded in.
- `decisive_evidence_description` — what the verdict *should* rest on, and
  (for the two competing narratives) an explicit list of the surface cues
  that are *not* sufficient on their own.

Splitting `correct_label` from `decisive_evidence_description` was necessary:
an earlier draft bundled them into one field, which caused the grader to mark
`label_correct: false` any time `cited_it: false` — making the
`unconfirmed_guess` outcome unreachable and defeating GAP 2 entirely. See
acceptance check below.

### engine/prompts/grader_system.md

Defines the grading rubric for an LLM judge:

- **Step 1**: search the *entire* report (summary + every finding + every
  open question) for any statement addressing the item. If none exists,
  `final_label` must be exactly `"not addressed in report"` and
  `label_correct` must be `false` — no inferring a dismissal from silence.
- **Step 2 (`label_correct`)**: does the bottom-line verdict match
  `correct_label`, **independent of how it was reached**?
- **Step 3 (`cited_it`)**: is the verdict grounded in
  `decisive_evidence_description`? Must be `false` whenever
  `decisive_evidence_collected` is empty, regardless of `label_correct`.
- Explicitly calls out `label_correct: true` + `cited_it: false` as a valid,
  expected, common combination (with a worked example), to stop the grader
  from "correcting" one field to match the other.

### engine/scoring.py

- `_pair_evidence_with_log` — reconstructs, in order, each evidence request
  and the Monitor's response (including `ground_truth_refs`) from
  `transcript.json` + `collection_log.json`.
- `_matching_entries` — matches an item's tags against `ground_truth_refs`
  only (not `embeds_ground_truth`, which is `false`-by-design for
  decoys/competing narratives per `ground_truth.md`'s own instructions).
- `score_hunt` — for every rubric item computes `encountered` and
  `requested_decisive_evidence` mechanically from the transcript, sends all
  *encountered* items + the report to the LLM grader in one
  `grade_report` tool call, and combines the two into a `resolution`:

  ```python
  if requested and cited and label_correct: resolution = "resolved_with_evidence"
  elif label_correct:                       resolution = "unconfirmed_guess"
  else:                                      resolution = "unresolved"
  ```
  (items never encountered are `not_encountered` and skip grading entirely).

### Acceptance check

Ran `.venv/bin/python score_hunt.py env_003_wrong_story env_003_wrong_story_20260614T133031Z`
against the existing (pre-fix) run. Result (`runs/.../coverage_matrix.md`):

| Resolution | Count |
|---|---|
| `resolved_with_evidence` | 15 |
| `unconfirmed_guess` | 1 |
| `unresolved` | 0 |
| `not_encountered` | 4 |

The one `unconfirmed_guess` is `competing_redteam_nightingale` —
`label_correct: true`, `cited_it: false`, `requested_decisive_evidence: false`.
The grader's own rationale: the Hunter "correctly concludes authorized red
team exercise but grounds the verdict on surface cues (sec_redteam account
name, ... DNS, 0/72 VT hits, recon-only commands) — none of which match the
decisive evidence ... which was never collected." This is exactly the
surface-cue verdict the original run produced, now scored as a guess rather
than a pass — confirming GAP 2's rubric distinguishes "earned" from "guessed."

(Note: this run predates the two new decisive-evidence tags, so it could not
have requested them — `requested_decisive_evidence: false` for both
competing narratives is expected for this run and is not itself a finding
about the Hunter. A future run is needed to see whether, given the neutral
briefing, the Hunter requests this evidence.)

---

## GAP 3 — Coverage matrix (encountered vs. resolved vs. never looked)

**Files:** `engine/scoring.py` (`score_hunt`, `render_coverage_matrix`),
`score_hunt.py`.

Every rubric item (all 8 decoys and all 3 competing narratives included) is
mechanically checked for `encountered` regardless of whether it's graded.
Items never surfaced by any evidence request are recorded as
`not_encountered` and excluded from LLM grading entirely — they cannot be
scored "resolved" by the grader because they're never sent to it.

`score_hunt.py` writes `coverage_matrix.md` into the run directory: one row
per planted item, columns `Encountered?`, `Decisive evidence requested?`,
`Cited?`, `Label correct?`, `Resolution`, `Final label`, plus a summary count
per resolution category.

### Acceptance check

Same run as above. The coverage matrix shows, per planted item:

- `not_encountered` (4): `decoy_c2_beacon`, `decoy_persistence_tool`,
  `decoy_phishing_noise`, `competing_ws06_edr_alert` — these are reported as
  gaps (things the Hunter never looked at), not successes.
- `resolved_with_evidence` (15): all 8 core-incident items + 6
  decoys/competing-narratives + the EID 4104 evidence gap — each genuinely
  surfaced, with decisive evidence requested, cited, and the correct label.
- `unconfirmed_guess` (1): `competing_redteam_nightingale`, per GAP 2 above —
  encountered, correct label, but not earned.

Every planted item has an explicit `encountered? -> resolved-with-evidence? ->
label` entry; nothing is silently counted as a pass for being unexamined.

---

## Validation rerun — env_003_wrong_story_20260614T145538Z

After GAPs 1-3 landed, ran a fresh hunt against the neutralized topology to
test whether removing the briefing leak changes the outcome. Scored with the
same `score_hunt.py`.

| Resolution | Run 1 (leaked briefing) | Run 2 (neutral briefing) |
|---|---|---|
| `resolved_with_evidence` | 15 | 11 |
| `unconfirmed_guess` | 1 | 1 |
| `unresolved` | 0 | 2 |
| `not_encountered` | 4 | 6 |

**Headline result — the GAP 2 finding reproduces under a genuinely blind
briefing.** `competing_redteam_nightingale` is `unconfirmed_guess` again,
with the same shape of failure: the Hunter correctly concludes "authorized
internal security assessment" for the `sec_redteam` session on bws01/srv02,
but grounds it in a firewall-rule annotation (`R-114, ref SEC-2026-0085`)
plus "read-only recon, no lateral movement" — never requesting the IAM
provisioning record for `sec_redteam` or the `SEC-2026-0085` kickoff email.
Since the rewritten briefing gave zero hints that this was the "other"
activity, this is now clearly a reproducible reasoning shortcut (treating a
referenced ticket number + benign-looking telemetry as sufficient), not an
artifact of the old leaked description.

**Core incident chain (8/8) — robust again.** All real IOCs resolved with
cited decisive evidence, including a decoded C2 reverse-shell payload from
the scheduled task. Regression anchor holds.

**New observation — silently dropped hypotheses.** This run's `submit_report`
call omitted `open_questions` entirely (it's `None`, despite being declared
`required` in `engine/hunter.py`'s schema — neither the API nor the harness
enforces this). The Hunter's own closing line was "I now have a complete,
well-evidenced picture of the attack... Let me now compile the full report" —
it skipped its own methodology's step 5 (walk back through the initial
hypothesis list; confirm, refute, or carry each into open questions). Of its
8 initial hypotheses, three were left dangling and dropped rather than
recorded:

- **ws02/ws06 domain-admin credential theft** — ws06/Sarah was never
  investigated → `competing_ws06_edr_alert` = `not_encountered`.
- **svc_backupjob abuse** — fs01/srv03 evidence was collected but never
  written up → `decoy_bulk_backup_upload` = `unresolved`.
- **ws05/Mike engineering workstation** — never investigated →
  `decoy_c2_beacon` / `decoy_persistence_tool` = `not_encountered`.

The `svc_monitoring` account seen in the dc01/srv03 evidence
(`decoy_new_admin_account`) was likewise never addressed → `unresolved`.

This is recorded as a finding, not a bug: GAP 3's `not_encountered` /
`unresolved` categories did exactly what they were built for, surfacing
premature closure that the pre-GAP-1-3 scoring would have missed entirely (an
empty `open_questions` list previously just looked like "thorough
investigation, nothing left to ask"). No changes made to
`engine/hunter.py`, `engine/prompts/hunter_system.md`, or the harness's
schema enforcement — left as-is to keep this experiment measuring rather than
training around this specific failure mode.

---

## GAP 4 — env_004_cloud_identity_lotl

A new, second environment: a hybrid-identity tenant (on-prem `corp.local`
Active Directory, synced via Entra Connect to a `corp.com` Microsoft Entra
ID/M365 tenant), built around a real cloud-identity living-off-the-land
intrusion modeled on Storm-0558 / Midnight Blizzard-style techniques — a stale
external-auditor account compromised off-platform, used to register a
malicious OAuth app, consent to mail/file read scopes, and read executive
mailboxes and an M&A SharePoint site via Microsoft Graph for two weeks. No
malware, no endpoint activity, no unusual network destination — the entire
incident lives in identity/SaaS audit logs.

This environment is harder by construction than env_003: the real intrusion
is deliberately the *quietest* thing present, competing against a
password-spray burst (zero successes) and an authorized penetration test
(engagement PT-2026-03) that both generate far louder, HIGH-severity alerts.

**New files:**
- `environments/env_004_cloud_identity_lotl/topology.json` — 7 devices across
  two segments: `on-prem` (`fw01`, `dc01`, `ws01`) and `cloud` (`entra01`,
  `exo01`, `spo01`, `itsm01` — the Entra ID tenant, Exchange Online, SharePoint
  Online, and a GRC/ITSM system of record). Description is strictly neutral —
  no hint of where or what the incident is, per the GAP 1 lesson.
- `environments/env_004_cloud_identity_lotl/ground_truth.md` — overview,
  timeline, 5 core-incident reference tags (2 FEED, 3 ON-DEMAND), a benign-twins
  table of 5 legitimate mail/file-scoped OAuth apps (one of which is itself
  recently-registered and unverified-publisher, to prove those traits alone
  aren't damning), two competing-narrative tables (pentest + spray) each with
  a separate ON-DEMAND-only decisive-evidence tag, one genuine evidence gap
  (MailItemsAccessed not enabled tenant-wide until 2026-06-01), and a baseline
  section for every device.
- `environments/env_004_cloud_identity_lotl/rubric.json` — 11 items: 3
  core_incident (sign-in+provenance, OAuth app registration+consent/SP
  persistence, SP data access via Graph+SharePoint), 1 evidence_gap
  (MailItemsAccessed), 5 decoy (the benign-twin apps), 2 competing_narrative
  (pentest PT-2026-03, password spray).

### New scoring concept: `handled_implicitly_unstated`

Carrying forward the env_003 refinement that credited dismissals reached via
a stated general criterion: env_004's benign-twin apps are designed so a
strong report states one general distinguishing criterion (e.g. "registered
by IT under a change ticket, verified publisher, established history") that
correctly resolves several decoys *without naming each one* — naming all 5
apps individually would be unnatural for a real analyst. Previously this
would score as `unresolved` (`"not addressed in report"`,
`label_correct: false`), unfairly penalizing a report that handled these
correctly but implicitly.

- `engine/prompts/grader_system.md` — added **Step 1b** (only when Step 1
  finds nothing naming the item): if the report states a general criterion
  that, applied to this item, would clearly yield `correct_label`, and nothing
  contradicts that, then `implicitly_handled: true`,
  `final_label: "not addressed in report (implicitly handled — <criterion>)"`,
  `label_correct: true`, and `cited_it` is judged against that *general*
  criterion vs. `decisive_evidence_description`. Otherwise the old
  `"not addressed in report"` / `label_correct: false` / `cited_it: false`
  fallback applies. Added a worked example alongside the existing one.
- `engine/scoring.py` — added `implicitly_handled` to `GRADE_REPORT_TOOL`'s
  schema (required field), to the `not_encountered` result dict (`None`), and
  to the resolution logic:

  ```python
  if implicitly_handled and label_correct: resolution = "handled_implicitly_unstated"
  elif requested and cited and label_correct: resolution = "resolved_with_evidence"
  elif label_correct:                         resolution = "unconfirmed_guess"
  else:                                        resolution = "unresolved"
  ```
  Added `"handled_implicitly_unstated"` to the module docstring's resolution
  list and to `render_coverage_matrix`'s summary-count rows.

This is shared infrastructure — it also applies retroactively to any future
env_003 reruns, though env_003's rubric has no items designed around it.

### Acceptance check

`topology.json` and `rubric.json` both parse via `json.load`; `rubric.json`
has 11 items across the 4 expected categories. Every tag referenced in
`rubric.json`'s `encounter_tags`/`decisive_evidence_tags` (15 distinct tags)
appears in `ground_truth.md`. No hunt has been run against this environment
yet — that's the natural next step.
