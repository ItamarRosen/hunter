# Reversing the Asymmetry, Part II
## Build log and design record

Working title. This is a running log for the sequel to the first writeup. It captures the design decisions behind the POC and the reasoning behind them, while that reasoning is still fresh, so the eventual writeup can be reconstructed from real notes instead of memory. The first piece tested whether the judgment held on idealized evidence. This one asks whether it survives real, messy, partial collection in a virtual network.

I keep the "why" here, not just the "what," because the why is the part that is hardest to recover later.

---

### 1. The thesis, sharpened

The first writeup's title was always the bet, and this is the cleaner statement of it.

The asymmetry never changes shape. It is always "be right everywhere versus be right once." What changes is who holds which end.

At the perimeter it points at the defender. I have to cover every way in. The attacker needs one gap, at a time and by a method of his choosing. That is the defender's dilemma, and it is why prevention played alone loses.

The moment the attacker is inside and trying to operate, the same structure inverts. To keep doing his job unseen, he now has to stay consistent and hidden in every place his activity leaves a mark: every redundant record, every cross-referencing source, over time. I only have to find one mark he could not suppress, or one inconsistency he could not keep straight. He inherits my old burden. Be perfect everywhere.

The honest conditions, so this stays a thesis and not a slogan:

- It is powered by observation the attacker does not fully control. Redundant, partly independent sources, plus, where it exists, a vantage he cannot fake. Strip all independent observation away and the lever weakens.
- It bites on action, not presence. A dormant implant leaves little to be inconsistent about. But a dormant implant is not doing his job. The instant he moves, exfiltrates, persists, or communicates, he has to generate effects across things he cannot all reach.
- It raises his cost even when it does not guarantee the catch. To stay consistent across sources he does not own, he has to cage himself: low and slow, only over paths he controls, never touching what he cannot doctor. The more he hides, the less he can do.
- The floor is real. A patient, well resourced adversary who controls a large fraction of the sources, coordinates the lies perfectly, stays operationally minimal, and avoids whatever independent vantage exists can defeat this. No method catches that one with certainty. The honest output there is "I cannot rule it out," not "clean."

---

### 2. What changes from Part I

Part I ran on idealized evidence. The Hunter was handed clean, hand authored telemetry, and the result was about judgment: it could hunt, and the hard part was calibration, knowing when it had decisive proof and saying "I cannot tell" when it did not.

Part II keeps the same judgment and changes everything underneath it. The evidence now arrives through a real collection path, parsed from real tool output, with real gaps. The question of this writeup is narrow and falsifiable: does the calibration survive the move to real, messy, partial collection, or do the new layers break it.

---

### 3. The architecture

Four components, strict boundaries.

**Hunter.** Unconstrained reasoning. It is given the network and an open task, and it reasons about where an intruder would be. It has exactly one tool, request_evidence, with a description that names no protocols, vendors, or data sources. The reason is the core design principle: showing the Hunter a menu of capabilities corrupts its reasoning. It starts asking "which of my tools fits" instead of "what does this network demand." So the menu is hidden from it.

**Dispatcher.** It takes the Hunter's free form request and maps it to concrete queries. The real collection tools live here, not in the Hunter. It runs live or from recordings, it reports back when something is not collectable, and it tags every piece of evidence with where it came from and how far to trust it.

**Parser.** It turns raw vendor output into uniform, structured evidence. One small model per protocol. The Hunter never sees a raw vendor format.

**Verifier.** A second pass over the verdict. Three outcomes: confirm, can't clear, no finding. It forces the verdict down to "can't tell" when the deciding evidence is absent, and a final gate rejects any verdict not carried by cited evidence.

---

### 4. The trust model

Evidence is never just true. It carries the trust of its source.

Three tiers, using topology as the worked example:

- **Documented:** the organization's claimed map. A claim, not ground truth. An intruder may have added paths it does not show, or edited the docs.
- **Device reported:** routing tables, ARP, neighbor discovery. Reported by the devices. A compromised device lies: it hides a route, fakes a neighbor, omits the tunnel.
- **Tap observed:** what the wire actually carries. The attacker owns the device but not the observation point, so this is the ground truth.

Topology is not special. It is evidence with a provenance and a tier, handled by the same trust tagging as everything else. The Hunter does not get a separate topology brain. It weighs a router's self report against a tap observation the same way it weighs a corruptible host agent against the tap.

The discrepancies between the three are the signal. A path the tap carries that no routing table and no diagram admits is the covert tunnel. A route a device advertises that the tap never carries is a lie or just idle. "Settling" the topology is not resolving it to one fact. It is holding all three and reasoning over the gaps.

---

### 5. The tap, and independence

The tap is a logical role, not a physical box. What I need is an observation vantage independent of the thing being monitored. Physical hardware taps are the purest and rarest way to get it. In practice it is SPAN or port mirroring, flow export, cloud traffic mirroring, or existing sensors and flow logs. For the virtual lab it is just packet capture on the virtual link.

Two independences, and I need both:

- **Independence from the customer's map.** Active self discovery means I do not need their diagram or their documentation. I build my own picture by querying routing and neighbor state. But this is independence from their map, not from their access. I still need a foothold: reachability to the network, and for the device level topology, credentials. Discovery is not free. Without a login I can find which hosts exist and what they expose, but the rich internal topology needs access the operator grants, which is a normal onboarding step. So "they have no map" costs me nothing. "I have no access" costs me everything.
- **Independence from the adversary.** Only the off device tap gives me this, because active discovery still queries devices, and a compromised device lies to my query just as it lies in its docs.

The tap's importance scales with how much infrastructure the adversary owns. For host level intrusions the network devices are already independent of the attacker, and cross source consistency alone is strong. For the network infrastructure case, where the attacker owns the routers, the device sources are all suspect and the independent vantage is what saves me. The tap matters most in exactly the hardest niche, and least in the broad market.

"No good tap here" is not a failure. The tap's independence is a dial that sets how decisive I can be. Where it is strong I confirm or clear outright. Where it is weak I still surface inconsistencies, but I land more often, and correctly, at "I cannot be sure." The calibration layer is what makes that honest instead of a guess.

---

### 6. Collection design

Topology is built from a fusion, not one source.

- **Active self discovery** is the primary builder: query routing tables, neighbor discovery, traceroute, SNMP and LLDP walks. Fast, near complete, independent of any customer artifact. This is why I do not just passively wait.
- **The passive tap** is the trust layer: it verifies the actively discovered map against ground truth and flags the gaps. Incomplete on its own, but that is not its job.
- **The documented map** is an optional prior. A claim to check if it exists, no loss if it does not.

Coverage is the honest limit. If a key element's traffic never crosses the tap, passive verification is blind to it. Active discovery still establishes that the element exists, so I am not ignorant of it, I just cannot verify it. So I model my own coverage explicitly. Every element is either within tap coverage, and therefore verifiable, or discovered but unobserved, and therefore not. "I saw no bad traffic" and "there is no bad traffic" are different claims, and I never collapse them.

Standard tools already do the discovery. SNMP, CDP, LLDP, ICMP, ARP for active, flow analysis for passive, compiled into a source of truth. The whole network management and NDR world does this. The plumbing is commodity, so I reuse it rather than rebuild it. What none of them do is treat the map as adversarial: documented versus device versus tap as a trust hierarchy where the disagreement is the signal, paired with calibrated "I cannot verify this." That layer is the contribution. Mapping is solved. Trustworthy adversarial mapping is not.

What the adversary actually does, against sources he owns: suppress and omit (hide the route, drop the neighbor, blind the agent), fabricate and spoof (fake an identity, spoof an IP or MAC, show decoy routes), lie selectively when watched, tamper with the management plane or the source of truth store, poison ARP, MAC, and routing tables. Against the tap he can do none of that. He can only avoid its coverage or blend into its noise. He can dodge it or hide in it. He cannot make it say something false. The bind: to vanish from the device sources he has to contradict the independent vantage, and the contradiction is the signal.

---

### 7. Engineering decisions

**Record and replay.** The collectors run live once against the lab, capture the raw responses, and the test suite replays the recordings. Live mode validates the collector against real output. Replay mode runs every agent and seed cheaply and deterministically. The fixtures are real captures, not guesses about format.

**Model tiering, for cost.** The Hunter runs on the cheap tier during development and the expensive tier only for final quality runs. The dispatcher and parser run on the cheapest tier. The verifier sits in the middle. Prompt caching on the static context. A hard prepaid cap as the ceiling.

**Replay first, vertical slice first.** Build the full loop on one protocol from a recording before any real collection or breadth. Live collectors are a discrete capture step, not part of the slice.

**Honest labeling.** A protocol stood up and queried for real is validated end to end. One fed only a real capture is parser validated but query unvalidated. One on a hand crafted fixture is unvalidated against reality, and it is flagged as a gap rather than left to imply more than it proves.

**Tool choice for the collectors.** A plain SSH and CLI library (Netmiko) that returns raw output to the parser, not a normalizing library or a network management platform that would pre resolve the data and bypass the parser. The collector fetches raw text. Normalization is the parser's job. The trust tiered model is mine to build, because nothing off the shelf is adversarial aware.

---

### 8. Testing methodology

The eval is half the deliverable, not an afterthought.

Ground truth is the whole problem. I can only test what I have an answer key for, so I build environments where I planted the truth.

The scenario matrix, the same axes as Part I, now through the real pipeline:

- **Clean.** Tests false accusation.
- **Compromised, evidence collectable.** Tests detection.
- **Compromised, evidence not collectable.** Correct answer is "can't clear." Tests the three verdict discipline.
- **Clean but suspicious.** The false positive trap.
- **Optional:** telemetry carrying attacker controlled strings, an injection probe.

What I measure is not accuracy. It is the two cardinal failures (missed intrusion, false accusation), the calibration between them (did it hold at "I cannot tell" when the proof was absent), the evidence faithfulness (right verdict for the right reason, read from the transcript), and the verifier's efficacy (did it catch the overreach).

How I grade: I read the transcripts against the answer keys. No automated grader, because a grader as fallible as the Hunter cannot mark its own homework, and Part I already showed graders break. Multiple seeds per scenario, because the agent is stochastic and "right seven of ten, false all clear three of ten" is a calibration failure invisible in a single run.

One subtlety worth recording: the early smoke test is not re-proving Part I's result. The judgment is the control, already validated. The new code, the abstract tool, the dispatcher, the parser, the replay layer, is the unknown. A wrong verdict now points at the new plumbing, most likely a parser that dropped a decisive detail or a dispatcher that mismapped an intent, not at the model. It is an integration test wearing a calibration test's clothes.

---

### 9. Honest limitations, carried forward

- Small N. A handful of hand built environments is a demonstration and a failure finder, not a benchmark. No percentages.
- Idealized to real is the open question, not a settled result.
- The perfect, coordinated, operationally minimal adversary who also avoids the vantage is the floor. Unbeaten in theory. The claim is only that it is vanishingly rare and pays an enormous price in constraint to stay there.
- Coverage gaps are blind spots, recorded as blind spots, never as innocence.

---

### 10. Open threads and next steps

- Stand up the minimal lab: FRR for routing, tcpdump for the tap, osquery for the host. Validate each collector against real output. Capture recordings.
- Build the scenario matrix as real captures plus answer keys.
- Run the matrix in replay, cheap tier first, then the expensive tier for the final runs.
- Grade by reading transcripts. Write up what works, what broke, and what is validated versus a known gap.
- The headline the writeup has to answer: did the calibration survive real collection.

---

### 11. A possible shape for the sequel

Not fixed, just a starting structure that mirrors the journey:

1. Recap the bet in one page: the asymmetry pointed the right way.
2. What changed from Part I: idealized evidence to real collection, and why that is the real test.
3. The architecture, and the one principle that drove it (the unconstrained Hunter).
4. The trust model: three tiers, the tap, and why topology is just evidence.
5. Building it: record and replay, the collectors, the cost discipline, what I reused versus what I had to build.
6. The virtual lab and the scenario matrix.
7. The runs: what held, what broke, read from the transcripts.
8. Limitations, stated plainly, and what a Part III would have to settle.

Keep the voice of the first one. Plain words. Short sentences where they earn it. Limitations up front, no overclaiming, no false modesty. Let the failures carry the interest, the way they did the first time.

---

### 12. Research questions, committed before any runs

These are written during the design phase, before a single environment has been run. The point is honesty. Questions written after the results quietly drift toward whatever turned up, so committing them in advance means the answers, whatever they are, get reported against a fixed target. Each one is phrased so that "no" is a real possible outcome. A question with no possible "no" is not a research question.

1. **Does the calibration survive real collection?** When evidence arrives through the real pipeline instead of hand authored text, does the Hunter keep the sharp separation from Part I: confirm on decisive proof, refuse to accuse clean networks, hold at "I cannot tell" when the deciding evidence is absent? A "no" is the Hunter over trusting normalized evidence and confirming on thinner proof, or hedging everywhere and losing the clean three way split.

2. **Does the collection layer deliver evidence faithfully, or fail in ways that look like calibration failures?** Can a wrong verdict be attributed to the model rather than the plumbing? A "no" is the parser dropping or distorting a decisive detail, or the dispatcher mismapping an intent, so a verdict flips for reasons unrelated to the Hunter's judgment. This is also the methodological backbone. If these two cannot be separated, none of the other answers can be trusted.

3. **Is the trust tiering operationally real, or only architecture?** When evidence is tagged by source and trust, does the Hunter actually distrust a device report the tap contradicts, weight the tap as ground truth, and reason from the documented versus observed gap? A "no" is the Hunter ignoring the tags and treating everything as equally true, which would make the trust model decoration.

4. **Does the system degrade honestly under coverage gaps?** When the decisive evidence sits outside what the tap can see, does the Hunter land at "can't clear," and does it keep "I did not observe it" separate from "it is clean"? A "no" is it reading silence as innocence and clearing a network it could not see into. This is the cardinal coverage error.

5. **(Exploratory) Can attacker controlled strings in the collected data steer the parser or the Hunter?** Here a "no" is the good outcome and a "yes" is a real, reportable weakness. Marked exploratory because the matrix may only fit one injection scenario.

With a handful of environments these get answered as "what was observed," not "what was proven." Committing them in advance buys authenticity, not statistical weight.

A note on precedence. The record that these came before the findings is the commit history, not any date written in this file. The questions go into the repo now, in their own commit, ahead of any results commit. That public timeline is what does the work. The point was never the date. It was committing before looking.

---

*Log started during the design phase. To be appended as the lab comes up, the matrix is built, and the runs come in.*
