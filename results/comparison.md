# Coverage Comparison

What each detection approach caught across the five captures, what it missed,
and why. Every figure is measured. Nothing here is estimated.

## The three surfaces

```
ET Open          52,466 rules, unmodified. Counted here are only the
                 threat-claiming categories: ET MALWARE, ET TROJAN,
                 ET REMOTE_ACCESS, ET DROP, ET EXPLOIT_KIT, ET JA3.
                 ET INFO alerts and SURICATA engine anomalies are counted
                 separately because they claim nothing is malicious.

custom rules     Four rules written from indicators measured in these
                 captures. Full results in results/custom-rules.md

timing analysis  Two unsupervised detectors over Zeek logs.
                 Detector 1 groups http.log by (client, host).
                 Detector 2 groups conn.log by (client, server, port).
                 Both need at least 10 events in a group before any
                 statistic can be computed. Below that floor a group is
                 never scored at all.
```

## Headline

```
threat                        ET Open   custom   timing analysis
---------------------------------------------------------------------------
NetSupport 2026 beacon          264        5     found, most regular of all
NetSupport 2025 beacon           48        1     found
NetSupport operator session     256 *      3     invisible to both detectors
StealC exfiltration               4        0     scored, ranked last
Formbook                         29        0     below the 10-event floor
Emotet                           74        27    2 of 17 C2 servers
STRRAT                          103        0     below the 10-event floor
benign 30 s poller                0        0     FALSE POSITIVE
```

`*` those 256 are `SURICATA HTTP request missing protocol`, a generic parser
anomaly. It is not a threat-claiming rule and does not name anything.

## Regularity rankings

The metric is `rcv` = median absolute deviation of the gaps / median gap.
Lower means more regular. A perfect metronome scores 0.

### Connection level, top 15 of 117 groups

```
rcv         capture       destination                label
------------------------------------------------------------------
0.000009    anchor        10.2.28.2:123              NTP
0.000010    sunnystation  172.16.0.1:137             NetBIOS
0.000027    anchor        10.2.28.255:137            NetBIOS
0.000028    anchor        10.2.28.2:137              NetBIOS
0.000041    sunnystation  172.16.0.1:137             NetBIOS
0.000072    benign        10.0.2.3:67                DHCP
0.000087    benign        ff02::16                   IPv6 multicast
0.000102    benign        224.0.0.252:5355           LLMNR
0.000103    sunnystation  172.16.0.1:137             NetBIOS
0.000104    benign        ff02::1:3:5355             LLMNR
0.001701    benign        151.101.193.91:80          CDN
0.002176    benign        151.101.65.91:80           CDN
0.002191    benign        151.101.1.91:80            CDN
0.002491    benign        151.101.129.91:80          CDN
0.050210    dirtyrat      23.52.9.222:443            unknown
```

Not one malicious group appears. The only two rows labelled malicious in the
whole file score `rcv` 0.194376 and 0.333258 and rank far below this.

The single most regular thing on any of these networks is NTP, at 0.000009.

### Request level, all 6 groups

```
rcv         capture   destination                 label              n
--------------------------------------------------------------------------
0.000160    anchor    45.131.214.85               MALICIOUS         264
0.000902    benign    www.msftconnecttest.com     benign-synthetic   28
0.001218    c2_2025   38.146.28.242               MALICIOUS          48
0.001888    benign    detectportal.firefox.com    benign-synthetic  318
0.225332    anchor    msedge...microsoft.com      unknown            30
0.632745    c2_2025   79.141.165.202              MALICIOUS          22
```

Malicious, benign, malicious, benign. Any threshold that catches both C2
servers also catches both benign pollers.

NTP at 0.000009 is roughly 18 times more regular than the most rhythmic C2 in
this data, which scores 0.000160.

## Isolation forest

Five features: `n_events`, `median_gap`, `mad_gap`, `rcv`, `median_bytes`.
Four are passed through `log1p` first; all five are standardised. 117
connection-level groups, of which 2 are labelled malicious.

```
contamination   flagged   true positives   precision   recall
--------------------------------------------------------------
0.05                6            0           0.000      0.00
0.10               12            0           0.000      0.00
0.20               24            2           0.083      1.00
```

`contamination` is not a discovery. It is an instruction telling the model what
fraction of the data to call anomalous, so the flagged count is decided before
the model looks at anything.

At 0.20 the model found both malicious groups and 22 other things. To catch
2 real detections an analyst reads 24 alerts.

What it flagged first was `8.8.8.8:53` with 3,274 events and `rcv` 0.977902 -
Google DNS, the least regular high-volume host in the data. The model was built
to find outliers, and the most unusual row is not the most malicious one.

## Per threat

```
NetSupport 2026 beacon
  ET Open       264 (sid 2035892, URI + User-Agent)
                264 (sid 2013926, port 443 hardcoded)
  custom          5 (sid 1000002)
  timing        found - rcv 0.000160, the most regular group in http.log
  conn.log      ABSENT - keep-alive produced 1 row, below the 10-event floor

NetSupport 2025 beacon
  ET Open        48 (sid 2035892)
                  0 (sid 2013926 - the C2 moved to port 1203 and it broke)
  custom          1 (sid 1000002)
  timing        found - rcv 0.001218
  conn.log      ABSENT - same keep-alive, 1 row

NetSupport operator session
  ET Open       256 generic parser anomalies, unnamed
  custom          3 (sid 1000004)
  timing          0 - Zeek's HTTP parser rejected the frames, so they never
                  entered http.log, and conn.log saw the same single row

StealC exfiltration
  ET Open         4 (StealC_V2 x3, StealC x1)
  custom          0 - no rule written for it
  timing        scored and ranked LAST - rcv 0.632745. A 400 KB burst
                transfer has no rhythm to measure.

Formbook
  ET Open        29 (FormBook CnC Checkin)
  custom          0 - no rule written for it
  timing          0 - roughly 20 domains at 1-3 requests each. With a
                10-event floor there was nothing to score.

Emotet
  ET Open        74 JA3 alerts, 17 unique C2 servers, family named wrongly
                as "Possible Dridex"
  custom         27 (sid 1000003), 16 unique C2 servers, family not named
  timing        2 of 17 C2 servers cleared the 10-event floor.
                Recall ceiling 12% before the model ran.

STRRAT
  ET Open       102 (STRRAT CnC Checkin) + 1 (Spamhaus DROP, same IP)
  custom          0 - no rule written for it
  timing          0 - 102 check-ins, 1 conn.log row, 0 http.log rows.
                Port 12132 was never parsed as HTTP.

benign 30 s poller
  ET Open         0 threat-claiming alerts
  custom          0
  timing        scored 4th most regular in the entire data set, between
                the two live C2 servers.
```

## What each approach is blind to

```
signatures       cannot read encrypted payloads
                 fail the moment a string changes
                 cannot tell a dormant beacon from a live intrusion
                 ET Open scored precision 1.00 here only because every
                 sample was already known when the rules were written

timing analysis  needs repetition, so any of these defeats it:
                   keep-alive       NetSupport, STRRAT -> 1 conn.log row
                   domain rotation  Formbook -> 1-3 requests per domain
                   C2 IP rotation   Emotet -> 17 servers, 2 scoreable
                   burst transfer   StealC -> no rhythm at all
                 and it cannot tell intent: it ranked a benign poller
                 above a live C2 server

both             cannot attribute traffic to a malware family from network
                 data alone. Every family name in this repository came from
                 a threat-intelligence lookup, not from detection.
```

## The conclusion

```
signatures know WHAT     blind to encryption, and to anything new
timing knows HOW         blind to intent
neither knows WHY
```

Interval analysis is a triage filter, not a detector. The most regular traffic
on these networks is NTP - eighteen times steadier than the C2 being hunted.
It finds automation. Deciding whether that automation is hostile takes
something else.