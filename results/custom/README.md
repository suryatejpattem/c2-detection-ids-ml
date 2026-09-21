# Raw alert output

Every alert line produced by `rules/local.rules` on each capture, written by
Suricata as `fast.log`. These are the files the counts in
`../custom-rules.md` were taken from.

```
anchor-2026.log          5 alerts     sid 1000002
c2-2025.log              4 alerts     sid 1000002 x1, sid 1000004 x3
sunnystation-2022.log   27 alerts     sid 1000003
dirtyrat-2024.log        0 alerts     empty file
benign.log               0 alerts     empty file - the false positive test
```

An empty file is the result, not a missing file. Zero alerts on
`benign.pcap` is what "no false positives" means.

The two baseline files are sid 1000001 run on its own - the unthresholded
rule that sid 1000002 is measured against:

```
rule1-baseline-anchor-2026.log   264 alerts
rule1-baseline-c2-2025.log        48 alerts
```

Compare those counts with `anchor-2026.log` and `c2-2025.log` to see the
alert reduction directly.

The benign run used `-k none`. See `../../docs/captures.md` for why.
