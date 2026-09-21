# C2 Detection: Signatures and Behavioural Analysis

Network detection engineering across five packet captures and five malware
families, measuring what signature detection and interval-based behavioural
analysis each catch, where each one is blind, and why.

Every figure in this repository was measured. The raw output that produced
each one is committed alongside it.

---

## The data

```
five captures      457,229 packets, 9h 20m of traffic
four malicious     NetSupport RAT x2, StealC v2, Emotet, Formbook, STRRAT
one benign         self-captured control, 338,523 packets, 2h 47m
```

Captures are not committed. Sources and SHA256 hashes: `docs/captures.md`
Indicator reference: `data/ground-truth.md`

---

## Headline results

### ET Open baseline

```
530 true positives    0 false positives    precision 1.00
```

Counting only threat-claiming categories. That figure is less impressive than
it looks, and this repository says so: every sample was already analysed
before the rules were written. ET Open's own port-based NetSupport rule scored
264 on one capture and 0 on the next when the C2 changed port.

### Four custom rules

```
sid       what it detects                  fires on          benign FP
----------------------------------------------------------------------
1000001   NetSupport, no threshold         264 + 48 alerts       0
          (baseline, not deployed)
1000002   NetSupport, rate limited           5 +  1 alerts       0
1000003   self-signed placeholder cert      27 alerts            0
1000004   NetSupport operator session        3 alerts            0
```

```
264 -> 5      same match logic plus a threshold, no detection lost
survived      a C2 address change AND a port change, rule unmodified
16 of 17      Emotet C2 servers found by one rule with no address in it
14 ms         from the last beacon check-in to the operator taking control
0             false positives on 338,523 packets of benign traffic
```

Detail and raw output: `results/custom-rules.md`, `results/custom/`

### Behavioural detection

```
contamination   flagged   true positives   precision   recall
--------------------------------------------------------------
0.05                6            0           0.000      0.00
0.10               12            0           0.000      0.00
0.20               24            2           0.083      1.00
```

Detail: `results/comparison.md`, `results/ml/`

---

## The central finding

Ranked by how steady their check-in intervals are, most regular first:

```
0.000160   45.131.214.85              MALICIOUS   NetSupport C2 2026
0.000902   www.msftconnecttest.com    benign      60 s poller
0.001218   38.146.28.242              MALICIOUS   NetSupport C2 2025
0.001888   detectportal.firefox.com   benign      30 s poller
```

Malicious, benign, malicious, benign. Any threshold that catches both C2
servers also catches both benign scripts.

At the connection level no malicious group appears in the top fifteen at all.
The most regular traffic on these networks is NTP, at 0.000009 - eighteen
times steadier than the most rhythmic C2 in the data.

```
signatures know WHAT     blind to encryption, blind to anything new
timing knows HOW         blind to intent
neither knows WHY
```

Interval analysis is a triage filter, not a detector. It finds automation.
Deciding whether that automation is hostile takes something else.

---

## What defeated the behavioural arm

Four mechanisms, each measured, each with a named family:

```
keep-alive         NetSupport, STRRAT   102 check-ins -> 1 conn.log row
domain rotation    Formbook             ~20 domains, 1-3 requests each
C2 IP rotation     Emotet               17 servers, 2 above the floor
burst transfer     StealC               400 KB in one request, no rhythm
```

Every one of them cost the signature approach nothing. A signature only has to
see the traffic once.

---

## Repository layout

```
rules/              four custom Suricata rules, plus the baseline variant
analysis/           Zeek log parsing, feature extraction, isolation forest
data/               ground truth indicators and the measured feature tables
results/            measured output - baseline, custom, ml, comparisons
docs/               capture sources, methodology, findings
.github/workflows/  CI: suricata -T on every push to rules/
```

---

## Tooling

```
Suricata 8.0.6       signature detection, ET Open ruleset (52,466 rules)
Zeek 8.2.2           protocol logging and connection metadata
pandas 3.0.5         feature extraction
scikit-learn 1.9.0   isolation forest
```

---

## Honest limits

```
durability proven for one rule only
   sid 1000001 and 1000002 are tested against two independent captures of
   the same malware with different infrastructure. sid 1000003 and 1000004
   have one capture each.

no rule here can name a malware family
   Every family name in this repository comes from a threat-intelligence
   lookup or a capture's source page, not from a detection.

one benign control host
   "Zero false positives" means zero on one Windows VM over 2h47m. A
   production network has far more variety.

two malicious rows out of 117
   Too few to train or validate a supervised model. Unsupervised detection
   was the only defensible option, and its precision reflects that.
```

Full scope statement: `docs/methodology.md`

---

## Where to start reading

```
results/comparison.md     the coverage table and the argument
results/custom-rules.md   each rule, what it matches, what it measured
docs/findings.md          tooling traps, analysis decisions, corrections
docs/methodology.md       how every number was produced
data/ground-truth.md      every indicator, marked verified or third-party
```