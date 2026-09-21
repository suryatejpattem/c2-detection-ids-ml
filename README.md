# C2 Detection: Signatures and Behavioural Analysis

[![Validate Suricata rules](https://github.com/suryatejpattem/c2-detection-ids-ml/actions/workflows/validate-rules.yml/badge.svg)](https://github.com/suryatejpattem/c2-detection-ids-ml/actions/workflows/validate-rules.yml)

Network detection engineering across five packet captures and five malware
families, measuring what signature detection and interval-based behavioural
analysis each catch, where each one is blind, and why.

Every figure in this repository was measured, and the raw output that
produced it is committed alongside. Nothing is estimated.

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

## Pipeline

```
5 pcap files
   |
   +---> Zeek 8.2.2 ------> conn.log, http.log, ssl.log
   |                              |
   |                              v
   |                     analysis/build_features.py
   |                              |
   |                   +----------+----------+
   |                   |                     |
   |                   v                     v
   |          features_http.csv       features_conn.csv
   |             6 groups                117 groups
   |                   |                     |
   |                   v                     v
   |              rcv ranking         isolation forest
   |
   +---> Suricata 8.0.6 --> ET Open baseline, 52,466 rules
                        \
                         -> rules/local.rules, 4 custom rules
```

---

## Repository layout

```
c2-detection-ids-ml/
|
|-- README.md
|-- .gitignore
|
|-- .github/workflows/
|   `-- validate-rules.yml        CI: suricata -T on every push to rules/
|
|-- rules/
|   |-- README.md                 layout, and how local.rules is generated
|   |-- local.rules               deployable set: sids 1000002-1000004
|   `-- individual/
|       |-- rule1.rules           sid 1000001  NetSupport, no threshold
|       |-- rule2.rules           sid 1000002  NetSupport, rate limited
|       |-- rule3.rules           sid 1000003  self-signed placeholder cert
|       `-- rule4.rules           sid 1000004  NetSupport operator session
|
|-- analysis/
|   |-- zeek_reader.py            parses Zeek logs via the #fields header
|   |-- build_features.py         inter-arrival gaps, both detectors
|   |-- run_isolation_forest.py   unsupervised scoring, 3 contaminations
|   `-- requirements.txt          pinned versions
|
|-- data/
|   |-- ground-truth.md           every indicator, marked [V] or [U]
|   |-- features_http.csv         6 request-level groups
|   |-- features_conn.csv         117 connection-level groups
|   `-- conn_scored.csv           117 groups + isolation forest scores
|
|-- results/
|   |-- comparison.md             the coverage table and the argument
|   |-- custom-rules.md           each rule: match, result, limits
|   |-- baseline/                 ET Open alert summaries, per capture
|   |-- custom/                   raw fast.log from every rule run
|   |   |-- anchor-2026.log                    5 alerts
|   |   |-- c2-2025.log                        4 alerts
|   |   |-- sunnystation-2022.log             27 alerts
|   |   |-- dirtyrat-2024.log                  0 alerts  (empty, correct)
|   |   |-- benign.log                         0 alerts  (empty, the FP test)
|   |   |-- rule1-baseline-anchor-2026.log   264 alerts
|   |   `-- rule1-baseline-c2-2025.log        48 alerts
|   `-- ml/
|       |-- isolation-forest-output.txt
|       `-- rcv-ranking.txt
|
`-- docs/
    |-- captures.md               sources + SHA256 of every pcap
    |-- methodology.md            how every number was produced
    `-- findings.md               tooling traps, decisions, corrections
```

---

## How a rule is built (the loop)

Every rule went through the same steps. Using sid 1000001 as the example.

**1. Measure the indicator in the capture**

```
tshark -r 2026-02-28-traffic-analysis-exercise.pcap \
       -Y 'http.request' -T fields -e http.request.uri -e http.user_agent \
  | sort | uniq -c
```

264 identical POSTs to `/fakeurl.htm` with User-Agent
`NetSupport Manager/1.3`. No IP and no port go into the rule - those are what
the attacker changes.

**2. Write the rule with a local sid**

sids 1000000-1999999 are reserved for local rules and cannot collide with
ET Open.

**3. Syntax check before touching any traffic**

```
suricata -T -S rules/individual/rule1.rules -l /tmp
```

**4. Run against the captures it should fire on**

```
suricata -r <capture>.pcap -S rules/individual/rule1.rules -l <outdir>
wc -l <outdir>/fast.log
```

`-S` with a capital S loads only that file and ignores the 52,466 ET Open
rules, so the count is attributable to one rule. Lowercase `-s` would add to
them.

**5. Run against benign.pcap**

```
suricata -r benign.pcap -S rules/individual/rule1.rules -l <outdir> -k none
```

`-k none` because the benign capture was taken on the sending host, where
24.4% of packets carry checksums the network card had not filled in yet.
Without it a quarter of the false-positive test is silently skipped.

**6. Record both numbers**

A rule is not validated by what it catches. Every count in this repository
comes with its benign result beside it.

Not every rule worked first time. sid 1000003 is at rev 3 - the first two
versions had the address direction backwards and matched nothing, which
testing against both a target and the benign capture caught immediately.

---

## Measurement method

```
TP    an alert on traffic that data/ground-truth.md records as malicious
FP    an alert on benign.pcap
FN    a documented threat the rule did not fire on

precision = TP / (TP + FP)
```

Counting rule for the ET Open baseline - only categories that claim something
is malicious count as detections:

```
counted        ET MALWARE, ET TROJAN, ET REMOTE_ACCESS, ET DROP,
               ET EXPLOIT_KIT, ET JA3
counted        ET INFO, SURICATA parser and engine anomalies -
separately     these claim nothing is malicious
excluded       164,392 invalid-checksum decoder alerts on benign.pcap,
               a capture artifact that would not occur on a network tap
```

Benign window: 338,523 packets, 2h 47m, one Windows 11 VM, no malware.

---

## Results

### Custom rules

| sid | detects | anchor 2026 | c2 2025 | sunnystation | dirtyrat | benign FP |
|---|---|---|---|---|---|---|
| 1000001 | NetSupport, no threshold (baseline, not deployed) | 264 | 48 | 0 | 0 | **0** |
| 1000002 | NetSupport, rate limited | 5 | 1 | 0 | 0 | **0** |
| 1000003 | self-signed placeholder certificate | 0 | 0 | 27 | 0 | **0** |
| 1000004 | NetSupport operator session | 0 | 3 | 0 | 0 | **0** |

```
264 -> 5      same match logic plus a threshold, no detection lost
survived      a C2 address change AND a port change, rule unmodified
16 of 17      Emotet C2 servers found by one rule with no address in it
14 ms         from the last beacon check-in to the operator taking control
0             false positives on 338,523 packets of benign traffic
```

Detail: `results/custom-rules.md` - raw output: `results/custom/`

### ET Open baseline

```
530 true positives    0 false positives    precision 1.00
```

Less impressive than it looks, and this repository says so: every sample was
already analysed before those rules were written. ET Open's own port-based
NetSupport rule scored 264 on one capture and 0 on the next when the C2
changed port.

### Behavioural detection

| contamination | flagged | true positives | precision | recall |
|---|---|---|---|---|
| 0.05 | 6 | 0 | 0.000 | 0.00 |
| 0.10 | 12 | 0 | 0.000 | 0.00 |
| 0.20 | 24 | 2 | 0.083 | 1.00 |

`contamination` tells the model what fraction of rows to call anomalous, so
the flagged count is decided before the model reads anything. All three
settings are reported rather than the best one.

Detail: `results/comparison.md` - raw output: `results/ml/`

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

Every one of them cost the signature approach nothing. A signature only has
to see the traffic once.

---

## Tooling

```
Suricata 8.0.6       signature detection, ET Open ruleset (52,466 rules)
Zeek 8.2.2           protocol logging and connection metadata
pandas 3.0.5         feature extraction
scikit-learn 1.9.0   isolation forest
Ubuntu 24.04.2 LTS   analysis host
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