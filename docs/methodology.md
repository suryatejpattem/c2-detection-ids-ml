# Methodology

How every figure in this repository was produced, in the order it was
produced. Anyone with the five captures can repeat all of it.

Capture sources and hashes: `captures.md`
What the work found: `findings.md`

---

## Environment

```
Ubuntu in a VirtualBox VM
Suricata 8.0.6 RELEASE
ET Open ruleset, 52,466 rules, downloaded with suricata-update
Zeek 8.2.2
Python 3, pandas and scikit-learn - see analysis/requirements.txt
```

---

## Order of work

```
1  verify capture integrity     sha256sum against docs/captures.md
2  Zeek                         conn.log, http.log and other default logs
3  Suricata baseline            ET Open unmodified, per capture
4  feature extraction           inter-arrival gaps per group
5  behavioural detectors        rcv ranking, then isolation forest
6  custom rules                 written from indicators measured above
7  custom rule testing          all five captures, benign included
```

Step 6 deliberately follows steps 2 to 5. Every indicator in the four custom
rules was measured in these captures first. None was copied from a public
threat report.

---

## 1. Zeek

```
zeek -C -r <capture>.pcap
```

`-C` disables checksum validation. Without it Zeek silently discards every
outbound packet of `benign.pcap` and produces `http.log` rows with empty
method, uri and host fields. The four downloaded captures do not need it,
but it was used throughout for consistency.

---

## 2. Suricata baseline

```
suricata -r <capture>.pcap -l <outdir>
suricata -r benign.pcap  -l <outdir> -k none
```

`-k none` disables checksum validation and is used on `benign.pcap` only.
Suricata's own offload detection samples the first 1,000 packets, measured
2.8%, and left validation on - hiding 164 alerts from one of the pollers.

Raw output: `results/baseline/`

### Counting rule

Only categories that claim something is malicious are counted as detections:

```
counted        ET MALWARE, ET TROJAN, ET REMOTE_ACCESS, ET DROP,
               ET EXPLOIT_KIT, ET JA3

counted        ET INFO           an observation, not an accusation
separately     SURICATA ...      engine and parser anomalies

excluded       IPv4/TCPv4/UDPv4 invalid checksum decoder alerts on
               benign.pcap - 164,392 of them, a capture artifact that
               would not occur on a network tap
```

Without that rule stated, a precision figure means nothing.

---

## 3. Feature extraction

```
analysis/zeek_reader.py        parses Zeek logs using the #fields header
analysis/build_features.py     builds both feature tables
```

Two detectors, differing only in what they group by:

```
Detector 1   http.log   grouped by (id.orig_h, host)
                        one event per HTTP request
                        size feature: request_body_len

Detector 2   conn.log   grouped by (id.orig_h, id.resp_h, id.resp_p)
                        one event per TCP connection
                        size feature: orig_bytes
```

For each group:

```
sort the timestamps            Zeek does not guarantee time order
gaps = consecutive differences
require at least 10 events     fewer than 9 gaps says nothing

median_gap                     typical interval
mad_gap                        median absolute deviation of the gaps
rcv = mad_gap / median_gap     steadiness, outlier resistant

mean_gap, std_gap
cv = std_gap / mean_gap        steadiness, outlier sensitive

median_bytes                   typical payload size
```

`rcv` is the metric used for ranking. `cv` is kept in the table so the
difference can be inspected - see `findings.md` section 2.

Output: `data/features_http.csv` (6 rows), `data/features_conn.csv`
(117 rows).

### Labelling

```
malicious          address appears in the indicator list in ground-truth.md
benign-synthetic   the two PowerShell pollers written for this project
benign             any group in benign.pcap not matching the above
unknown            anything else in a malicious capture
```

`unknown` is used honestly: a host in an infected capture that no source
names is not evidence of anything either way, and it is never counted as a
false positive.

---

## 4. Isolation forest

```
analysis/run_isolation_forest.py
```

```
features        n_events, median_gap, mad_gap, rcv, median_bytes
transform       log1p on n_events, median_gap, mad_gap, median_bytes
                rcv is already a ratio and is not transformed
                StandardScaler on all five
model           n_estimators 200, random_state 42
contamination   0.05, 0.10, 0.20 - all three reported
```

`contamination` tells the model what fraction of rows to call anomalous, so
the number flagged is decided before the model reads anything. All three
settings are reported rather than the best one.

Output: `data/conn_scored.csv`, `results/ml/isolation-forest-output.txt`

---

## 5. Custom rules

```
suricata -T -S rules/local.rules -l /tmp                  syntax check
suricata -r <capture>.pcap -S rules/local.rules -l <dir>  detection run
suricata -r benign.pcap -S rules/local.rules -l <dir> -k none
```

`-S` with a capital S loads only the named file and ignores ET Open, so each
count is attributable to one rule set and nothing else. Lowercase `-s` would
add to the 52,466.

All four rules use sids in the 1000000-1999999 range reserved for local
rules, so none can collide with an ET Open sid.

Every rule was run against all five captures, `benign.pcap` included. A rule
is not validated by what it catches alone.

Raw output: `results/custom/`
Per-rule detail: `results/custom-rules.md`

---

## Time zones

Suricata writes `fast.log` in the machine's local time. `ground-truth.md`
records UTC. Correlating the two without noticing costs five hours. Every
timestamp in this repository states its zone.

---

## What was not done

Stated so the scope is not overread.

```
no rules for Formbook, StealC or STRRAT
   ET Open already names all three correctly. The four custom rules target
   gaps that were measured, not threats already covered.

no supervised learning
   features_conn.csv has 2 malicious rows out of 117. That is not enough to
   train on, and not enough to validate against. Unsupervised detection was
   the only defensible option.

no payload decryption
   Emotet's C2 traffic is TLS. Nothing in this repository reads it. The
   certificate metadata is all that was available.

no threat intelligence lookups performed by any detector
   Malware family names come from the capture source pages and from
   ground-truth.md. No rule or model in this repository attributes a family.

one benign control host
   benign.pcap is a single Windows 11 VM over 2h47m. "Zero false positives"
   means zero on that file. A production network has far more variety.
```

---

## Reproducing a single figure

Example - the claim that sid 1000002 reduces 264 alerts to 5:

```
suricata -r 2026-02-28-traffic-analysis-exercise.pcap \
         -S rules/individual/rule1.rules -l /tmp/baseline
wc -l /tmp/baseline/fast.log          # 264

suricata -r 2026-02-28-traffic-analysis-exercise.pcap \
         -S rules/individual/rule2.rules -l /tmp/limited
wc -l /tmp/limited/fast.log           # 5
```

Both output files are also committed, at
`results/custom/rule1-baseline-anchor-2026.log` and
`results/custom/anchor-2026.log`.