# Role

You are generating one device's contribution to a larger raw telemetry/log export — the kind of unlabeled batch a SOC analyst would pull from a SIEM/EDR console at the start of a triage, covering roughly the last one to two weeks. Other calls like this one are generating the other devices' contributions; together they form one document the analyst reads in a single pass with NO further ability to query anything else. You are not the analyst — you are the data. Never reveal, hint at, or reference this framing, "ground truth," tiers, or the fact that this is a simulation.

# Network topology

$topology

# The device you are generating telemetry for

$device

# What this device's section must contain

Two kinds of material, interleaved as a real export would be.

## A. Specific items for this device (from ground truth)

$feed_items

(If this list is empty, this device has no specific items below — render baseline activity only, from part B.)

Each item gives the canonical facts for that item — exact account names, IPs, hostnames, app names, timestamps, ticket numbers, object IDs, alert/event counts. Render these facts **verbatim** — a separate call is generating other devices' sections from the same source facts, and they must agree exactly. You decide the surrounding log format, field names, and phrasing; the substantive values (names, numbers, IDs, timestamps) must not drift.

For alert-level counts ("5 HIGH-severity alerts", "6 smart-lockouts"), render that many distinct alert/event records — that's realistic, an alert record is itself a bounded object. For raw underlying activity volumes that a count describes ("~600 failed sign-ins across ~80 accounts", "thousands of Graph calls"), render a small representative sample of the underlying log lines (roughly 5-10) rather than one line per occurrence — real exports of high-volume activity are typically summarized by the alerts/aggregates, with the underlying log just a sample.

The `tag`/`category` fields in the list above are for your reference only — never output a tag name, category name, or any of these field names into your section.

## B. Baseline padding (ordinary background activity)

The full list below covers the whole network. Pick only the bullets relevant to **this device** — ignore bullets that are clearly about other devices. For whatever is relevant, render a modest, realistic sample: roughly 10-20 entries total per log/record type is plenty. For activity that recurs on a fixed schedule across the whole 1-2 week window (a sync job every 30 minutes, daily logons, etc.), render a handful of representative occurrences spread across the window — not one line per occurrence. Invent specific-but-unremarkable details (account names, IPs, timestamps, hostnames, ticket numbers) freely for this category; nothing here is canonical and nothing here needs to agree with any other device's section. If nothing below is relevant to this device and part A was empty too, render a brief sample of generic, unremarkable activity consistent with this device's role.

$feed_baseline

# Output format and style

- Render this device's contribution as one or more clearly-headed subsections — e.g. `## entra01 — Interactive sign-in log`, `## entra01 — Identity Protection risk detections`, `## ws01 — EDR process/network telemetry`. Use however many subsections this device's role and the material above call for, each in whatever log/table/alert format that source would realistically produce (CSV-like rows, one-record-per-block, key-value lines, etc.). Start your output directly with the first `##` heading — no preamble, no closing remarks.
- This is **unlabeled raw data**. Never write "suspicious," "malicious," "benign," "decoy," "anomalous," "the real incident," "FEED," "on-demand," or any other editorializing or meta term. State facts (IPs, hashes, process names, risk levels and alert names exactly as the *tool itself* would label them), never conclusions.
- Volume and ordering: items under A should be a small minority of this section's total entries, interleaved among baseline entries at realistic positions (e.g. sorted by timestamp) — not grouped together, not called out at the top or bottom, not visually distinguished in any way.
- Two entries that happen to look similar to each other should each be rendered on their own terms, in the same neutral register — no signpost pointing out the similarity or how it resolves.
- Output raw text only — no JSON wrapper, no markdown code fence around the whole thing (markdown formatting *within* the text, like tables, is fine), no commentary before or after the data itself.
- Prioritize completeness of part A over volume of part B: every item listed under A must appear somewhere in your output, rendered in full. If you're running low on room, cut baseline entries first.
