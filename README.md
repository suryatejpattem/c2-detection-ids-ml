# C2 Detection: Signatures and Behavioural Analysis

Network detection engineering across five packet captures, comparing what
signature-based detection and interval-based behavioural analysis each catch,
and where each one is blind.

Five malware families are present: NetSupport RAT (two separate deployments),
StealC v2, Emotet, Formbook, and STRRAT. A self-captured benign control
provides the negative class.

## Status

Work in progress. The ET Open baseline, the behavioural detectors, and four
custom Suricata rules are complete and measured. The coverage comparison and
final write-up are in development.

## Repository layout

```
analysis/     Python: Zeek log parsing, feature extraction, anomaly detection
data/         ground truth indicators and measured feature tables
docs/         capture sources and methodology
results/      measured output
rules/        custom Suricata rules
```

## Tooling

```
Suricata 8.0.6        signature detection, ET Open ruleset
Zeek 8.2.2            protocol logging and connection metadata
pandas, scikit-learn  feature extraction and unsupervised detection
```

## Captures

Packet captures are not committed. Sources and SHA256 hashes are in
`docs/captures.md`.

## Ground truth

`data/ground-truth.md` records every known indicator per capture, with each
fact marked as independently verified or recorded from a third party. All
measurements are made against that file.

## Rules and results

`rules/README.md` explains the rule layout. Measured per-capture results for
every custom rule are in `results/custom-rules.md`.