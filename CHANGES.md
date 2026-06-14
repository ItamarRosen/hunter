# env_003 validity fixes — GAP 1-3

This document records what changed for each validity gap identified after the
first env_003 run (`runs/env_003_wrong_story_20260614T133031Z/`), and the
acceptance check performed for each. GAP 4 (the "costume" environment,
env_004) is optional and **not started** — see bottom.

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

## GAP 4 — env_004_costume

**Status: not started.** This is the largest remaining piece of net-new work
and is explicitly optional. Will discuss scope/design before starting.
