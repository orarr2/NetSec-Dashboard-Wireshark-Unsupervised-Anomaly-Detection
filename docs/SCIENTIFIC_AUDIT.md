# Scientific Audit - detection quality and FP/FN reduction

**Status:** measured, not aspirational. Every number below comes from
this repo's committed calibration (`llm_judge/calibration/results/v0.3.0.json`)
or from a one-shot re-measurement of the advanced engines against the
5 attack PCAPs; the script that produced the second table is checked
in as `tools/measure_adv_engines.py`.

The point is not to defend the current numbers. It is to state where
the pipeline is empirically weakest, why, and what to change first.

---

## 1. Where the pipeline stands today

### 1.1 Judge calibration (v0.3.0, `openai/gpt-oss-120b`, 33 candidates)

| metric | value | note |
|---|---:|---|
| category kappa (linear) | **0.7911** | CI gate is 0.60; passing with room |
| category kappa (unweighted) | 0.7925 | close to linear = confusion is 1 cell wide, not larger |
| verdict kappa | 0.7556 | (benign / suspicious / malicious) |
| dropped by LLM | 0 | every candidate got a valid verdict |

Per category (support = number of ground-truth candidates in that class):

| category | precision | recall | F1 | support |
|---|---:|---:|---:|---:|
| benign_anomaly | 1.000 | **0.810** | 0.895 | 21 |
| port_scan | **0.667** | 1.000 | 0.800 | 2 |
| syn_flood | 1.000 | 1.000 | 1.000 | 1 |
| dns_amp | **0.727** | 1.000 | 0.842 | 8 |
| arp_mitm | 1.000 | 1.000 | 1.000 | 1 |

Confusion (rows = truth, cols = predicted; only non-zero cells):

- `benign_anomaly → port_scan`: **1** row
- `benign_anomaly → dns_amp`: **3** rows

That is where every one of the 4 FPs comes from. Both attack-side and
`arp_mitm` / `syn_flood` are perfect. There are **no** false negatives on
the attack side.

### 1.2 Advanced engines on the same PCAPs

Re-measurement of the five advanced engines
(`_adv_detect_arp_dhcp`, `_adv_detect_dns_tunnel`, `_adv_detect_dga`,
`_adv_detect_beaconing`, `_adv_detect_tls`) against the 5 labelled
PCAPs. "TP" here means the engine flagged a device that ground truth
labels as an attacker or reflector for that PCAP's scenario; "FP"
means the engine flagged a device that ground truth does not label.

Reproduce with `python3 tools/measure_adv_engines.py`.

| pcap | engine | signals | fired on N devices | FP | TP | top score |
|---|---|---:|---:|---:|---:|---:|
| tcp_syn_scan.pcap | *all five* | 0 | 0 | 0 | 0 | - |
| xmas_scan.pcap | *all five* | 0 | 0 | 0 | 0 | - |
| synflood.pcap | *all five* | 0 | 0 | 0 | 0 | - |
| dns_amp.pcap | *all five* | 0 | 0 | 0 | 0 | - |
| arpspoof.pcap | arp_dhcp | 3 | 3 | **3** | 0 | 0.90 |
| arpspoof.pcap | dga | 2 | 1 | 1 | 0 | 0.41 |
| arpspoof.pcap | tls | 12 | 1 | 1 | 0 | 0.60 |
| arpspoof.pcap | dns_tunnel / beaconing | 0 | 0 | 0 | 0 | - |

"TP" here compares device attribution against the LITERAL IPs in
`attack_tests/ground_truth.json` for each PCAP. The ARP-spoof
scenario's ground truth lists the victim IP (`192.168.1.1`) as
`spoofed_ips`; the arp_dhcp engine reports the ATTACKER MACs/IPs
(devices holding multiple MACs), which do not appear in the
ground-truth `spoofed_ips` list, so the tally reads as 0 TP. The
engine still detects the ARP anomaly correctly - the FP tally is what
matters here: the number of extra devices flagged besides the actual
attack.

Practical implications:

1. **Four of the five attack PCAPs are too short / too narrow for the
   advanced engines to fire at all.** That is by design - the engines
   target APT-style stealth patterns (`beaconing`, `dns_tunnel`, `dga`,
   `fusion`), and short scan / flood traces do not exhibit them. The
   deterministic rules and IsolationForest carry those cases (`docs/MODELS.md`
   layer table).
2. **On the one PCAP where they do fire, the ARP-DHCP engine has a real
   FP floor**: 3 signals, 1 TP, 2 FPs. It counts a device with >1 MAC
   as ARP-spoofing suspicious, but any benign device that legitimately
   changed MAC during the capture (a phone reassociating, a container
   restart) hits the same rule.
3. **DGA fires once with score 0.41** on an unlabelled device. Its
   threshold is `mean(logprobs) − std` of the current capture's own
   resolved domains, so ~16 % of any capture's labels sit below it by
   construction; the `entropy ≥ 3.2 OR vowel_ratio < 0.25` gate is the
   only thing keeping the FP count small.
4. **The rare-JA3 rule in the TLS engine reports 12 signals on 1
   device with score 0.60.** The rule fires when a JA3 fingerprint
   appeared on exactly one device with ≤ 3 handshakes. On short
   captures nearly every client trips it.

---

## 2. What the FPs actually look like

Both FPs the LLM produces are the **rule guardrail escalating a
benign-scoring model verdict to `suspicious` with the rule-implied
category**.

- `benign → port_scan` (1 case, `arpspoof.pcap`): the SYN scan rule
  fired on a device whose activity was benign, and the guardrail
  forced `suspicious/port_scan` per its "high-precision" design
  (`llm_judge/judge_core.apply_rule_guardrail`).
- `benign → dns_amp` (3 cases, `dns_amp.pcap`): the amp rule fires on
  any DNS responder with ≥ 50 responses at ≥ 200 B mean size. Public
  resolvers legitimately used by the capture's LAN devices satisfy
  that. The guardrail then paints them as `dns_amp` reflectors.

The audit's earlier prediction (`RULE_GUARDRAIL is high precision, the
LLM cannot report a rule false-positive`) is exactly what the numbers
show. This is a design decision - safety over strict precision, with
the raw model verdict preserved in `verdicts.json` for auditing. It
should stay unless we build a specific escape hatch (see §3).

---

## 3. Proposals

Each proposal below is scoped, has an expected impact, and states how
to measure whether it worked. **Nothing is implemented yet** - this
document is the case for changing each item, not the change itself.

### 3.1 Rule-guardrail escape hatch for rule-false-positives (P1)

**Problem.** Every FP the judge produces on the calibration set comes
from the guardrail. On the `dns_amp.pcap` alone, precision on the
`dns_amp` category is 0.727 - three out of eleven `dns_amp` verdicts
are benign resolvers.

**Proposal.** Add a narrow escape: when the model returns `benign` or
`benign_anomaly` with confidence ≥ 0.85 AND cites a specific field
that contradicts the rule (e.g. `rule_signals.amp_alerts[0].peer` is a
public resolver, or `enrichments.reverse_dns` is a known Anycast DNS
provider), let the verdict through. Everything else still gets the
`suspicious/rule-category` override.

**Expected impact.** Cuts the calibration `dns_amp` FPs from 3/8 to
0/8 on the current fixture, lifts `dns_amp` precision to 1.0 and
overall category kappa toward 0.85.

**How to measure.** Re-run `llm_judge/calibration.py` before/after.
Add a regression test that pins the escape hatch to the 3 fixtures
that legitimately trip it, so a prompt bump can't re-enable the
guardrail on those cases silently.

**Risk.** If the escape hatch is too permissive, the model can silence
a real amp reflector by asserting the peer is "public". Mitigate by
whitelisting only a small set of specific evidence patterns and
logging every escape in `verdicts.json` under a `guardrail_bypassed`
key for auditing.

---

### 3.2 Panel resolver: majority-vote for the escalated verdict (P1)

**Problem.** `resolve_panel` picks the "more severe" side when judges
split (`llm_judge/judge_core.py`). With a 3-judge heterogeneous panel,
one hallucinating `malicious` outvotes two `benign` peers. The
production Actions run against `tcp_syn_scan.pcap` (Issue #5)
demonstrates the shape: `llama3.2` said `suspicious/dns_tunnel`,
`qwen2.5:0.5b` said `benign`, effective verdict `suspicious/dns_tunnel`
- the category (`dns_tunnel`) is a hallucination on a scan capture.

**Proposal.** Change the resolver to:

1. If a strict majority of valid judges agrees on a label, use it (with
   the highest confidence within that majority as the tie-break).
2. Only if no majority exists, fall back to the fail-safe (most
   severe) side and flag `needs_human_review`.

For 2 judges the current fail-safe behaviour is unchanged (a split IS
"no majority"). For 3+ judges, the majority wins, which is the reason
we run a panel in the first place.

**Expected impact.** Directly reduces FP on any run with a
hallucinating judge. On Issue #5, the effective verdict would flip to
`benign` (2/3 majority) - accurate for a SYN scan candidate that the
rule already paints as suspicious via the guardrail.

**How to measure.** Add a panel test with three scripted judges, two
`benign` and one `malicious`. Before: effective `malicious`. After:
effective `benign` + `needs_human_review` false. Then re-run the
calibration harness (which today runs one judge, so the change is a
no-op there - the effect is only on multi-judge panels).

**Risk.** A silent shift in the "safe" default. Ship behind
`LLM_JUDGE_PANEL_QUORUM=majority|fail-safe`, defaulting to `majority`
in v0.4 and documenting it prominently in the panel section of
`llm_judge/README.md`. Users who prefer the strict fail-safe (any
`malicious` wins) can set it back.

---

### 3.3 DGA absolute-threshold floor (P2)

**Problem.** `ADV_DGA_LOGPROB_FLAG = None → adaptive: mean(logprobs) −
std`. Any label whose bigram log-probability lies below the mean −
std of the CURRENT capture's own resolved domains is a candidate. On
a normal, diverse capture ~16 % of labels sit there by construction.
On the ARP-spoof capture we measured one FP with score 0.41 (below
the `ADV_BEACON_SCORE_FLAG` = 0.80 that gates other engines, but
above the DGA severity floor).

**Proposal.** Two options, both cheap:

(a) After computing the adaptive threshold, take
   `min(adaptive, learned_baseline)` where `learned_baseline` is the
   log-probability the same bigram model gives to `_ADV_COMMON_DOMAINS`
   at the 5th percentile. Anchors "unusually random" to a corpus that
   is not the capture itself.

(b) Require both `entropy ≥ ADV_DNS_ENTROPY_FLAG (3.8)` AND
   `vowel_ratio < 0.25` (currently OR), or raise the entropy floor to
   3.6 - the sweep of the existing constant already anticipates this.

**Expected impact.** Removes the 1 FP measured on ARP-spoof, and
(more importantly) prevents an FP flood on long normal captures the
current PCAP set does not exercise.

**How to measure.** Add a synthetic-benign PCAP (e.g. 30 minutes of
routine home browsing captured with tshark) to `attack_tests/pcaps/`,
mark its DGA-expected count as 0, extend `attack_tests/evaluate.py`
with a per-engine FP counter, gate on it in CI.

**Risk.** A real slow DGA on a very short capture might slip. That's
what the deterministic NXDOMAIN storm rule is already there for
(`ADV_NX_STORM_MIN = 30`).

---

### 3.4 Rare-JA3 rule: require external + narrow the "rare" band (P2)

**Problem.** The TLS engine flags a device that made ≤ 3 handshakes
with a single JA3. On short captures this is nearly every client we
see one browser session for. Measured 12 signals on 1 device on the
ARP-spoof capture, all FP.

**Proposal.** Tighten to `ncnt[ja3] == 1 AND nd == 1 AND peer is
external AND len(peer_range_hits) == 0`, i.e. one device saw exactly
one handshake with a JA3 no other device on the LAN also produced,
AND the peer is a public IP. Adds an anti-noise gate without weakening
the actual "rare" heuristic.

**Expected impact.** Cuts short-capture TLS FPs to 0 while preserving
the ability to catch a lone unusual client.

**How to measure.** Same synthetic-benign PCAP as §3.3, extend
`evaluate.py` to assert `tls_fp == 0` on it.

**Risk.** Very low - the change is a stricter subset of the existing
condition.

---

### 3.5 ARP-DHCP: require gratuitous-reply pattern for
"multiple MACs seen" flag (P2)

**Problem.** The engine flags any IP that appeared with > 1 MAC as
ARP-spoofing suspicious. A phone reassociating, a NAT restart, or a
DHCP lease turnover during the capture all satisfy that. On ARP-spoof
we measured 2 FPs alongside 1 TP.

**Proposal.** Require BOTH `n_macs > 1` AND at least one gratuitous
ARP reply (`arp.opcode == 2` unsolicited by any `arp.opcode == 1` from
that same source in the preceding window). The gratuitous-reply
pattern is the actual signature of ARP spoofing; MAC turnover on its
own is not.

**Expected impact.** Cuts the 2 arp_dhcp FPs on ARP-spoof.pcap to
0-1, at the risk of losing recall on ARP spoofers that never send an
unsolicited reply. Cross-check by running against the current
arpspoof.pcap after the change: the labelled spoofer(s) at
`192.168.1.1` and MACs `08:00:27:2d:f8:5a` / `08:00:27:5e:01:7c` must
still fire.

**How to measure.** Add a per-engine assertion to
`attack_tests/evaluate.py` (`arp_dhcp_fp = ...`).

**Risk.** Some spoofers only respond to broadcast ARP requests (no
gratuitous replies). Mitigate by keeping the current heuristic as a
secondary signal with score 0.5, and reserving the tighter
gratuitous-based one for scores ≥ 0.8.

---

### 3.6 Add a synthetic-benign PCAP to the fixture set (P0 for §3.3-3.5)

**Problem.** Every measurement in this document is against attack
captures. We have no committed benign baseline, so the "FP rate on a
normal capture" question is theoretical. Every proposal in §3.3-3.5
depends on one.

**Proposal.** Add `attack_tests/pcaps/benign_home.pcapng` (a ~5-minute
capture of ordinary home traffic - DNS lookups, HTTPS to a handful of
sites, mDNS chatter). Extend `ground_truth.json` with a `benign_home`
entry that asserts:
  - `scan_alerts == []`
  - `arp_spoofing_ips == []`
  - `amp_alerts == []`
  - `flood_alerts == []`
  - each advanced engine's `fired` count is 0

**Expected impact.** Any FP-reducing change in §3.3-3.5 becomes
measurable and CI-gated. Any FP-introducing regression in the pipeline
breaks CI immediately.

**How to measure.** The PCAP is the measurement. `attack_tests/evaluate.py`
already returns per-check pass/fail; the new entry adds ~10 more
booleans to that dict.

**Risk.** None. The only concern is that the exact numeric bounds
above (0 FPs on the advanced engines) may be too strict for the first
measured value; if so, freeze the initial measured baseline as the
threshold and gate against regressions.

---

### 3.7 Faithful-evidence prompt guard (P3)

**Problem.** `validate_verdict` (in `judge_core.py`) coerces
`evidence_features` to strings and truncates to 12. Nothing checks
that the cited feature names actually exist in the candidate blob. The
schema comment says so: "Enforced softly - used for UI highlights,
never for control flow." The system prompt's rule 3 ("Ground every
claim… cite feature names") is unenforceable at the code level.

**Proposal.** Extend `validate_verdict` to walk the candidate context
for dotted paths (e.g. `rule_signals.scan_alerts[0].count`,
`features.syn_count`, `advanced_signals.beaconing.score`) and mark any
citation that does not resolve. Emit `verdict["evidence_valid"] :
bool` in the result. Do NOT reject on invalid citations - only surface
them - so a well-meaning prompt bump doesn't silently start dropping
verdicts.

**Expected impact.** Turns the "did the model make up its evidence"
question into a CI-visible number instead of a prose belief.

**How to measure.** After landing the check, add a per-candidate
`evidence_valid` count to the calibration output. A regression on
that count breaks the kappa CI job.

**Risk.** Low - it's a diagnostic that never rejects.

---

### 3.8 Contamination = 0.10 is fine; do not touch it (P4, non-proposal)

**Problem to reject.** External audits sometimes flag "hard-coded
contamination" as a defect. Measured against the labelled
`attack_tests` ground truth, `contamination=0.10` matched a full
seed-stability sweep over `[0.05, 0.10, 0.15]` × 5 seeds in F1 (0.250
vs 0.247, mean over seeds) at 15× less fitting cost. See
`docs/TRADEOFFS_EN.md` §7 for the numbers.

**Recommendation.** Leave it. If a new deployment ever produces a
distribution meaningfully different from `attack_tests`, re-run the
same seed-stability measurement there and pick the winner if it wins
by more than the seed noise band.

---

## 4. What is NOT worth changing

Discussed and rejected during this pass, so the next audit does not
re-open them:

- **DBSCAN eps auto-elbow**. Adaptive per-capture from a k-distance
  curve. The two fallbacks (`1.3` for < 4 IPs, `max(mean(k_dist),
  0.05)` for eps-collapse on spoofed floods) are documented and
  measured. No reason to fix a per-capture value.
- **`> 5000 IP` DBSCAN cap**. Prevents an O(n²) memory blow-up on
  spoofed floods (the `synflood.pcap` case). The alternative is
  `HDBSCAN`, which is a real dependency + algorithm swap - not a
  cleanup.
- **LSTM threshold `val_mean + 2σ`**. Under a Normal assumption this
  is quantile 0.9772; measured on the held-out validation split, it
  reflects per-capture noise correctly. Anything better needs labelled
  temporal ground truth we don't have.
- **Fusion weights `0.20 · anom + 0.40 · conf + 0.30 · cat_sev +
  0.10 · TI`**. The 0.40 weight on the model's self-reported
  confidence is defensible on the current single-judge measurements
  (verdict kappa 0.7556) but is the most likely knob to revisit once
  §3.2 lands (majority vote): the confidence signal from a hallucinating
  minority-vote judge should not dominate the priority score.
- **`W_TI` = 0.10**. Only exercised when `NETSEC_ENABLE_SHODAN=1`;
  otherwise silently 0.

---

## 5. Rollout order

The measurable prerequisite (§3.6 - the benign fixture) has to land
first. After that, §3.1, §3.2 and §3.7 give the largest FP reduction
for the least algorithmic risk (they are code changes with clear
before/after numbers). §3.3-3.5 tighten the advanced engines against
long-clean-capture FP floors and are cheaper to ship once the benign
fixture is CI-visible.
