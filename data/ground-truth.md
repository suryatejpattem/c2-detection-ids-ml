# Ground Truth

Reference list of known indicators for every capture used in this project. All
precision and recall figures in this repository are measured against this file.
If an entry here is wrong, every downstream number is wrong, and nothing will
error to warn us.

**Timestamp policy: every time in this file is UTC.**

The pcap format stores UTC epoch seconds. `capinfos` and `tshark` render them in
local time by default, which caused a real misreading early in this work. Use
`TZ=UTC capinfos <file>` or `tshark -t ud`. Suricata's `fast.log` writes local
time; those values are converted here.

**Verification markers:**

- `[V]` verified directly from the capture, or stated on the source page
- `[U]` unverified — recorded from a third party, not independently checked

Nothing marked `[U]` was used to make a decision.

---

# 1. 2026-02-28 — "Easy As 123" — NetSupport RAT

Referred to throughout as **anchor**. Primary capture for the HTTP detector.

## Provenance

| Field | Value |
|---|---|
| Source | https://www.malware-traffic-analysis.net/2026/02/28/index.html |
| Type | training exercise (answers in a password-protected PDF) |
| File | `2026-02-28-traffic-analysis-exercise.pcap` |
| SHA256 | `3dc470f5490ec15b4024c513e87c67e0b17caeae2a2ce3d83541be24ef407e61` |
| SHA1 | `d4755b2b695a8c0bf53407f7978b675619ce8b55` |

## File characteristics `[V]`

```
packets              15,512
size                 6,581 kB  (6,333 kB data)
duration             15,689.205001 s  =  4 h 21 m 29 s
first packet (UTC)   2026-02-28 19:55:06.482909
last packet  (UTC)   2026-03-01 00:16:35.687910
data rate            403 bytes/s
average packet       408.31 bytes
strict time order    True
```

The capture crosses midnight UTC into 2026-03-01. A filter scoped to
"2026-02-28" silently drops the final 16 minutes.

## Network

| Role | Value | Marker |
|---|---|---|
| Infected host | `10.2.28.88` | `[V]` |
| Hostname | `DESKTOP-TEYQ2NR` | `[V]` from `dhcp.log` |
| DHCP domain | `mshome.net` | `[V]` from `dhcp.log` |
| Gateway / DNS | `10.2.28.2` | `[V]` |
| Broadcast | `10.2.28.255` | `[V]` |
| Other device present | `brads-MBP` (Mac, no IP recorded) | `[V]` from `dhcp.log` |

The hostname was recovered from the DHCP request, not from the answers PDF.
Windows includes its computer name when requesting an address.

## Malicious indicators

| Field | Value | Marker |
|---|---|---|
| Malware family | NetSupport Manager RAT | `[V]` stated on source page |
| C2 address | `45.131.214.85` | `[V]` |
| C2 port | TCP 443 | `[V]` |
| Protocol | cleartext HTTP on port 443, not TLS | `[V]` verified with tshark |
| Method | `POST` | `[V]` |
| URI | `http://45.131.214.85/fakeurl.htm` | `[V]` |
| User-Agent | `NetSupport Manager/1.3` | `[V]` |
| Activity start per source | 2026-02-28 19:55 UTC | `[V]` |

The source page's stated start time matches the first packet at 19:55:06 UTC —
a six-second difference. The capture begins at the incident.

All 264 requests were byte-for-byte identical in method, URI and User-Agent.

## Measured characteristics `[V]`

```
HTTP requests to C2        264     agreed by tshark, Zeek and Suricata
TCP connections to C2        1     keep-alive, victim source port 51912
inter-arrival gaps         263
median gap             60.082894 s
MAD                        0.0096 s
rcv (MAD / median)      0.000160
260 of 262 gaps between 60.07 and 60.28 s
2 remaining gaps: 0.36 s and 0.20 s  (registration burst at infection)
```

One TCP connection carrying 264 requests. `conn.log` therefore holds a single
row for this C2, with zero measurable intervals.

---

# 2. 2025-08-20 — SmartApeSG to NetSupport RAT to StealC v2

Referred to throughout as **c2_2025**.

## Provenance

| Field | Value |
|---|---|
| Source | https://www.malware-traffic-analysis.net/2025/08/20/index.html |
| Type | blog entry (indicators listed on the page) |
| File | `2025-08-20-SmartAgeSG-Netsupport-RAT-with-StealCv2.pcap` |
| SHA256 | `24de7b31a2248763c4fd3e92acfc6b6fa9462b129c7b4ff8024932407ebeae4b` |
| SHA1 | `b263fef4225930d8ea3d0d7037a36ddda17371f5` |

The filename on disk reads `SmartAgeSG`; the post title reads `SmartApeSG`.
Commands in this repository use the on-disk spelling.

## File characteristics `[V]`

```
packets              61,609
size                 68 MB  (67 MB data)
duration             4,628.741194 s  =  1 h 17 m 09 s
first packet (UTC)   2025-08-20 17:48:04.044056   (13:48:04 EDT)
last packet  (UTC)   2025-08-20 19:05:12.785250   (15:05:12 EDT)
average packet       1,093.99 bytes
packet rate          13 packets/s
```

Only 8 IP conversations exist in the whole capture, nearly all malicious. This
capture has a very weak benign baseline.

## Network

| Role | Value | Marker |
|---|---|---|
| Infected host | `10.8.20.101` | `[V]` |
| Gateway / DNS | `10.8.20.1` | `[V]` |

## Malicious indicators

| Address | Role | Evidence | Marker |
|---|---|---|---|
| `38.146.28.242:1203` | NetSupport C2 | HTTP content + ET sid 2035892 | `[V]` |
| `79.141.165.202:80` | StealC CnC | ET sids 2066280, 2066559 | `[V]` |
| `45.61.150.28` | payload download, 44 MB inbound in 138.4 s | traffic volume | `[V]` |
| `172.86.90.13` | early stage, 193 frames over 124.6 s | traffic pattern | `[V]` |
| `209.59.180.92` | early stage, 114 frames over 125.8 s | traffic pattern | `[V]` |
| `23.23.49.179:443` | ZPHP delivery domain in TLS SNI (`islonline.org`) | ET sid 2061388 | `[V]` |
| `104.26.1.231:80` | NetSupport geolocation lookup | ET sid 2034559 | `[V]` |

`79.141.165.202` was originally recorded as suspected exfiltration based only on
its byte pattern — 6.1 MB outbound in 89.1 seconds. ET Open subsequently named
it StealC CnC, confirming the inference from an independent source.

## NetSupport C2 details `[V]`

```
C2                 38.146.28.242 : 1203
protocol           cleartext HTTP on port 1203
URI                /fakeurl.htm                  SAME as the 2026 capture
User-Agent         NetSupport Manager/1.3        SAME as the 2026 capture
TCP connections    1  (keep-alive, victim source port 63910)
```

Between the two captures the operator changed the server address and the port,
but the URI and User-Agent — compiled into the malware itself — did not change.

## Two behavioural phases on one connection `[V]`

```
14:01:00.473916 EDT   first NetSupport check-in
  ...                 48 check-ins, median gap 60.107639 s
14:45:03.280010 EDT   LAST check-in
14:45:03.294108 EDT   FIRST malformed request     <- 14 milliseconds later
  ...                 256 malformed requests over 70.4 s  (~3.6 per second)
14:46:13.700030 EDT   ends
```

Both phases used the same TCP connection (source port 63910).

The 14-millisecond transition marks the point where periodic automated check-ins
stopped and a continuous interactive stream began, consistent with a human
operator connecting to the remote-control session.

The 256 malformed requests are absent from Zeek's `http.log` — the parser
rejected them. Only Suricata's protocol-anomaly rule (sid 2221055) recorded
them. Zeek's `weird.log` logged one `bad_HTTP_request`.

## Measured beacon `[V]`

```
requests in http.log        48
gaps                        47
median gap          60.107639 s
rcv                  0.001218
```

An earlier calculation of 66.4 s was wrong: it divided the full conversation
duration, which includes the 70-second interactive burst, by the check-in gap
count. The median is unaffected by the burst and is the correct figure.

---

# 3. 2022-02-23 — SUNNYSTATION — Emotet + Formbook

Referred to throughout as **sunnystation**. Three infected hosts.

## Provenance

| Field | Value |
|---|---|
| Source | https://www.malware-traffic-analysis.net/2022/02/23/index.html |
| Type | training exercise (answers in a password-protected PDF) |
| File | `2022-02-23-traffic-analysis-exercise.pcap` |
| SHA256 | `eefc7e61b50e7846f5a3282d7645539d7b2b4b85aa08a09d0b823896c9449d1f` |
| SHA1 | `fdfa0d0edfe0cbcc0c1400fbe6ac61ff40942755` |

## File characteristics `[V]`

```
packets              30,023
size                 19 MB
duration             2,680.736661 s  =  44 m 41 s
first packet (UTC)   2022-02-23 18:22:24.405139   (13:22:24 EST)
last packet  (UTC)   2022-02-23 19:07:05.141800   (14:07:05 EST)
average packet       642.09 bytes
```

## Network

| Role | Value | Marker |
|---|---|---|
| LAN segment | `172.16.0.0/24` | `[V]` |
| Domain controller | `172.16.0.52` | `[V]` |
| Gateway | `172.16.0.1` | `[V]` |

## Infected hosts — from the answers PDF `[V]`

| MAC | IP | Hostname | User | Infection | Start (UTC) |
|---|---|---|---|---|---|
| `2c:27:d7:d2:06:f5` | `172.16.0.131` | `DESKTOP-VD151O7` | `tricia.becker` | Formbook (XLoader) | 18:29 |
| `00:12:f0:64:d1:d9` | `172.16.0.170` | `DESKTOP-W5TFTQY` | `everett.french` | Emotet | 18:25 |
| `00:1b:fc:7b:d1:c0` | `172.16.0.149` | `DESKTOP-KPQ9FDB` | `nick.montgomery` | Emotet with spambot | 18:24 |

## Emotet C2 servers — confirmed `[V]`

| Address | Contacted by | Connections | Median gap | rcv |
|---|---|---|---|---|
| `135.148.121.246:8080` | `172.16.0.149` | 28 | 44.812299 s | 0.333258 |
| `59.148.253.194:443` | `172.16.0.170` | 10 | 43.642070 s | 0.194376 |

Both are TLS. Both were contacted exclusively by hosts the answers PDF documents
as Emotet-infected. Both carry the malware JA3 fingerprint.

Neither address is listed by name in the answers PDF. The attribution comes from
the source hosts plus the fingerprint match.

## Additional Emotet C2 candidates `[U]`

Seventeen distinct destinations carried the same TLS fingerprint, all contacted
by the two confirmed-infected Emotet hosts:

```
27.254.174.84        128.199.93.156       139.196.72.155      168.197.250.14
54.37.106.167        128.199.192.135      144.217.88.125      180.250.21.2
54.38.242.185        134.209.156.68       162.144.76.184      185.184.25.78
61.7.231.226         135.148.121.246 [V]  198.199.98.78       59.148.253.194 [V]
61.7.231.229
```

Fifteen of these are marked `[U]`. They are consistent with Emotet's known use of
large hardcoded C2 lists, but JA3 fingerprints the TLS library rather than the
malware, so a collision with legitimate software cannot be ruled out from this
evidence alone.

Only 2 of the 17 reached the 10-connection minimum used by the connection-level
detector, capping that detector's recall on this capture at 12 percent.

## Formbook destinations `[V]`

Twenty domains, contacted 1-3 times each, from `172.16.0.131`:

```
3  www.seo-python.com                    1  www.riskprotek.com
3  www.jogoreviravolta.com               1  www.privilegetroissecurity.com
2  www.xn--pckwb0cye6947ajzku8opzi.com   1  www.nt-renewable.com
2  www.hydrocheats.com                   1  www.mystore.guide
2  www.db-propertygroup.com              1  www.moonshot.properties
2  www.czzhudi.com                       1  www.keysine.com
1  www.theperfecttrainer.com             1  www.katchybugonsale.com
                                         1  www.hentainftxxx.com
                                         1  www.globalsovereignbank.com
                                         1  www.elsiepupz.com
                                         1  www.chinadqwx.com
```

Benign hosts also present in `http.log`: `ctldl.windowsupdate.com` (3),
`www.msftncsi.com` (1). Total `http.log` rows for this capture: 35.

No Formbook domain reaches 10 requests. With 1-2 gaps per domain there is no
measurable interval, so interval analysis cannot score Formbook at all.

## Payload delivery `[V]`

`64.34.171.228` served a packed Windows executable over plain HTTP. Detected by
ET sids 2018959, 2014819 and 2014520.

---

# 4. 2024-07-30 — "You dirty rat!" — STRRAT

Referred to throughout as **dirtyrat**.

## Provenance

| Field | Value |
|---|---|
| Source | https://www.malware-traffic-analysis.net/2024/07/30/index.html |
| Answers | https://www.malware-traffic-analysis.net/2024/07/30/page2.html |
| File | `2024-07-30-traffic-analysis-exercise.pcap` |
| SHA256 | `c48854c24223cf7b4e9880ea72a21a877e4138e4ce36df7b7656e5c6c4043f68` |
| SHA1 | `2b2837c4ef1c08aae8fed3ce5026638bfd5aa858` |

## File characteristics `[V]`

```
packets              11,562
size                 11 MB
duration             585.662377 s  =  9 m 46 s
first packet (UTC)   2024-07-30 02:38:48.960835   (2024-07-29 22:38:48 EDT)
last packet  (UTC)   2024-07-30 02:48:34.623212   (2024-07-29 22:48:34 EDT)
average packet       980.92 bytes
```

The filename says 2024-07-30 but the local-time packets read 2024-07-29. Both
are correct — the capture was made in the evening EDT and crosses midnight UTC.

## Network — from the scenario page `[V]`

| Role | Value |
|---|---|
| LAN segment | `172.16.1.0/24` |
| Domain | `wiresharkworkshop.online` |
| Domain controller | `172.16.1.4` — `WIRESHARK-WS-DC` |
| Gateway | `172.16.1.1` |

## Infected host and malware `[V]`

| Field | Value | Evidence |
|---|---|---|
| Infected host | `172.16.1.66` | identified from Suricata alert sources |
| Malware family | STRRAT | ET sid 2030358 |
| C2 | `141.98.10.79:12132` | ET sid 2030358 |
| Additional | `141.98.10.79` is on the Spamhaus DROP list | ET sid 2400027 |

Neither the malware family nor the victim address was known before this
analysis. The answers PDF for this capture was not read; both facts were
recovered from Suricata output.

Two independent rule sources agree on `141.98.10.79`: one matching STRRAT's wire
protocol, one derived from Spamhaus's criminal-infrastructure list.

## Measured characteristics `[V]`

```
check-ins                    102
TCP connections                1   keep-alive, victim source port 49754
first check-in (EDT)   22:40:07.027145
last check-in  (EDT)   22:48:34.623093
span                     507.6 s
gaps                         101
interval                   ~5.0 s
```

A 5-second beacon, 102 times, over a single TCP connection.

An earlier estimate assumed a 60-second interval and concluded this capture held
only about 9 callbacks. That assumption was wrong by a factor of twelve.

## Why both interval detectors missed it `[V]`

```
conn.log   1 row    below the 10-event minimum
http.log   0 rows   Zeek did not parse port 12132 as HTTP
```

Zeek's `http.log` for this capture holds 2 rows total —
`www.msftconnecttest.com` and `ip-api.com`, both benign.

Suricata detected all 102 check-ins because sid 2030358 is an `alert tcp` rule
matching raw payload bytes, requiring no protocol parsing.

---

# 5. benign.pcap — self-captured clean traffic

The only capture whose contents are known with certainty, because it was
produced under controlled conditions on a machine verified beforehand.

## Provenance

| Field | Value |
|---|---|
| Captured by | this project |
| Host | `WS01` — Windows 11 Enterprise Evaluation, VirtualBox |
| Host IP | `10.0.2.5` |
| Analysis VM | `10.0.2.20` (Ubuntu 24.04) |
| Interface | `\Device\NPF_{0080C8C4-6BCF-4887-A37F-743BB19EE14D}` (Ethernet) |
| Tool | `dumpcap` (Wireshark), `-s 0` full packets, `-F pcap` |
| SHA256 | `f6c34eadb8d01069702586645fc22b67f0aff6afe24345d7ce0219ca5baf3f1d` |
| SHA1 | `d394c718a68d79e1c9fed5674684ab2536874799` |

## File characteristics `[V]`

```
packets              338,523
size                 312 MB  (306,957,839 bytes data)
duration             10,034.090647900 s  =  2 h 47 m 14 s
first packet (UTC)   2026-09-09 23:21:29.147733000
last packet  (UTC)   2026-09-10 02:08:43.238380900
data rate            30 kBps
average packet       906.76 bytes
timestamp precision  nanoseconds
strict time order    FALSE
```

`Strict time order: False`. Records must be sorted by timestamp before any gap
calculation. Failing to sort produced three fabricated gaps in an earlier
measurement, including a negative one.

This capture also crosses midnight UTC.

## Pre-capture verification `[V]`

`WS01` was used for Atomic Red Team execution during a previous project. It was
checked for surviving persistence before this capture:

```
scheduled tasks   all Microsoft (Edge, OneDrive, SoftLanding) or Npcap
HKLM Run keys     SecurityHealth, VBoxTray
HKCU Run keys     OneDrive, MicrosoftEdgeAutoLaunch
local accounts    only 'analyst' enabled
                  Administrator, Guest, DefaultAccount, WDAGUtilityAccount disabled
```

No prior-project artifacts survived.

Noted: two distinct OneDrive user SIDs are present, so OneDrive background
traffic may be heavier than on a single-profile machine.

## Deliberately generated synthetic traffic `[V]`

Two PowerShell loops ran for the duration of the capture. This traffic is benign
but automated, and exists to test whether interval analysis can distinguish
automation from malice.

**Poller 1 — 60-second target interval**

```
URL              http://www.msftconnecttest.com/connecttest.txt
attempts logged  167
Zeek http.log     28
Suricata alerts  164   (only with -k none; 0 without)
observed gaps    52 - 84 s, irregular
median gap       60.139686 s
rcv              0.000902
```

The interval is irregular because the loop is `request` then `Start-Sleep 60`.
The true cycle is 60 seconds plus the request's own latency, which varied.

**Poller 2 — 30-second target interval**

```
URL              http://detectportal.firefox.com/success.txt
attempts logged  325
Zeek http.log    318
median gap       30.184017 s
MAD              0.057 s
rcv              0.001888
max gap          118.60 s  (one stall, roughly four missed cycles)
```

Served by four Fastly edge addresses, which sum exactly to the 318 recorded
requests:

```
151.101.193.91   113
151.101.129.91    87
151.101.65.91     63
151.101.1.91      55
```

Windows caches DNS answers, so the poller contacted one address repeatedly
before re-resolving. The 30-second rhythm is preserved within each address:
grouping by IP gave clean 30-second gaps, with fewer samples per group.

Both pollers are labelled `benign-synthetic` throughout and are never presented
as naturally occurring traffic.

## Checksum offload — affects every tool `[V]`

```
packets with invalid checksums   82,711
percentage of capture             24.4%
```

Cause: the network card computes checksums in hardware, after `dumpcap` copies
the packet. Every outbound packet therefore carries an invalid checksum in the
file. Inbound packets are unaffected.

This does not occur in the four downloaded captures, which were recorded away
from the sending host. Suricata confirmed this on the anchor capture:
`No packets with invalid checksum, assuming checksum offloading is NOT used`.

**Zeek** silently discards packets that fail validation. The symptom was 356
`http.log` rows with `method`, `uri` and `host` all empty — the rows came from
responses (valid checksums), the empty fields from requests (invalid).
Fix: `zeek -C`.

**Suricata** samples the first 1,000 packets to auto-detect offload. It measured
28/1000 (2.8%) and left validation enabled, against a true rate of 24.4%. The
opening of the capture was not representative. Fix: `suricata -k none`.

Measured cost of leaving validation enabled:

```
                                validation ON   -k none
ET INFO PowerShell User-Agent         318          482
ET INFO Microsoft Connection Test       0          164
```

Poller 1 was entirely invisible without `-k none`.

`-k none` does not suppress the checksum decoder alerts themselves. Those are
separate rules (sids 2200073, 2200074, 2200075) and fired in both runs. They are
a capture artifact and are excluded from all analysis.

## Benign class produced `[V]`

```
conn.log   85 groups with >= 10 connections
http.log   356 rows; 5 destinations with >= 10 requests
```

Without the two pollers, `http.log` holds roughly 10 non-poller rows across 2
hours 47 minutes. Nearly all normal browsing is HTTPS and therefore absent from
`http.log`. The pollers are the HTTP benign class.

---

# Label definitions used in the feature tables

| Label | Meaning |
|---|---|
| `malicious` | destination appears in the `MALICIOUS` set in `build_features.py` |
| `benign-synthetic` | traffic generated deliberately by this project (the two pollers) |
| `benign` | from `benign.pcap`, a host verified clean before capture |
| `unknown` | in a downloaded capture and not on that capture's indicator list |

`unknown` is not `benign`. In a downloaded capture, "not listed as malicious"
means the capture's author did not list it. That cannot be verified from the
capture alone, so those rows are excluded from precision rather than counted as
correct. 30 of the 117 connection-level rows carry this label.

`benign-synthetic` is kept separate so that traffic generated by this project can
never be presented as a naturally occurring finding.

## The MALICIOUS set as configured

```python
MALICIOUS = {
    '45.131.214.85',      # C2 2026 NetSupport
    '38.146.28.242',      # C2 2025 NetSupport
    '79.141.165.202',     # 2025 StealC CnC
    '45.61.150.28',       # 2025 payload download
    '172.86.90.13',       # 2025 early stage
    '209.59.180.92',      # 2025 early stage
    '135.148.121.246',    # 2022 Emotet C2 (from 172.16.0.149)
    '59.148.253.194',     # 2022 Emotet C2 (from 172.16.0.170)
}
```

Known omission: `141.98.10.79` (STRRAT C2) is absent. It never entered either
feature table — one keep-alive connection in `conn.log`, zero rows in
`http.log` — so adding it would not change any measurement. It is recorded here
for completeness and should be added if the capture is reprocessed with a lower
event threshold.

---

# Cross-capture findings

## Indicator durability

```
                        2026 anchor            2025 capture
C2 address           45.131.214.85          38.146.28.242     CHANGED
C2 port                    443                   1203         CHANGED
URI                  /fakeurl.htm           /fakeurl.htm      SAME
User-Agent      NetSupport Manager/1.3  NetSupport Manager/1.3 SAME
```

Address and port are cheap for an operator to change. The URI and User-Agent are
compiled into the malware and require rebuilding and redistributing it.

Measured consequence:

```
ET sid 2035892  (matches URI + User-Agent)   264 alerts    48 alerts   BOTH
ET sid 2013926  (header fixes port 443)      264 alerts     0 alerts   BROKE
```

## Evasion mechanisms observed

| Malware | Mechanism | Effect on interval analysis |
|---|---|---|
| NetSupport (2026, 2025) | HTTP keep-alive | 1 `conn.log` row, 0 measurable gaps |
| STRRAT (2024) | HTTP keep-alive, non-HTTP port | 1 `conn.log` row, 0 `http.log` rows |
| Formbook (2022) | ~20 domains, 1-3 requests each | no domain reaches the minimum |
| Emotet (2022) | 17 C2 addresses | 2 of 17 reach the minimum |
| StealC (2025) | single burst transfer | not beaconing; rcv 0.633 |

## Beacon intervals measured

| Source | Median gap | rcv | Classification |
|---|---|---|---|
| NetSupport 2026 | 60.082894 s | 0.000160 | malicious |
| NetSupport 2025 | 60.107639 s | 0.001218 | malicious |
| STRRAT 2024 | ~5.0 s | not computed | malicious |
| Emotet `135.148.121.246` | 44.812299 s | 0.333258 | malicious |
| Emotet `59.148.253.194` | 43.642070 s | 0.194376 | malicious |
| Poller 2 (30 s target) | 30.184017 s | 0.001888 | benign-synthetic |
| Poller 1 (60 s target) | 60.139686 s | 0.000902 | benign-synthetic |
| NTP `10.2.28.2:123` | 1024.019676 s | 0.000009 | benign infrastructure |
| NetBIOS `172.16.0.1:137` | 120.013975 s | 0.000010 | benign infrastructure |

Sorted by rcv, malicious and benign entries interleave, and the most regular
traffic of all is benign protocol infrastructure. NTP is roughly seventeen times
more regular than the 2026 C2.

---

# Corrections made during analysis

Recorded because each was a silent failure. None produced an error message.

| Error | Effect if uncorrected | How it was found |
|---|---|---|
| Used `conn.log` for beacon intervals | C2 becomes 1 row, 0 gaps, undetectable | Counted connections against requests before building |
| Computed gaps without sorting first | Three fabricated gaps including one negative | A negative gap is impossible |
| Used mean and standard deviation | Benign poller ranked more regular than a real C2 | Compared both statistics on four known cases |
| `dest = key[-1]` in the feature builder | Selected the port, not the address; nothing could be labelled malicious | `dest` column printed `53`, `123`, `443` |
| `comment='#'` in the Zeek reader | Would truncate any row containing `#` in a URL | Reviewed what the flag actually does |
| Missing indicator list for sunnystation | Both Emotet C2s labelled `unknown`; detector appeared to have zero true positives | Read the answers PDF and cross-checked source hosts |
| Assumed a 60-second beacon for dirtyrat | Capture wrongly excluded from analysis; real interval is 5 s | Suricata counted 102 check-ins |
| Checksum offload unhandled | Zeek produced empty HTTP fields; Suricata missed an entire poller | `-C` and `-k none` comparison runs |
