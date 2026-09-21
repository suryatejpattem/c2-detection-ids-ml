# Findings

What the work turned up beyond the coverage table. Three kinds of thing:
tools that lose data without saying so, analysis choices that changed the
answer, and errors found before they reached the results.

Coverage results are in `../results/comparison.md`.
Per-rule results are in `../results/custom-rules.md`.

---

## 1. Tools that lose data silently

### Checksum offload hid a quarter of the benign capture

The benign capture was taken on the machine generating the traffic. A network
card computes packet checksums *after* the capture tool has already copied the
packet, so every outbound packet in the file carries a checksum that looks
wrong.

```
82,711 of 338,523 packets affected   =  24.4%
```

What each tool did about it:

```
Zeek       validates checksums and discards failures.
           http.log had 356 rows, but method, uri and host were all empty.
           Requests were outbound and discarded; server replies were inbound
           and kept. A reply creates a row, so rows existed with nothing in
           them. No error, no warning.

Suricata   samples the first 1,000 packets to decide whether offload is in
           use. It measured 28 of 1,000 - 2.8% - and left validation ON.
           The real figure across the whole file is 24.4%. The first
           thousand packets were not representative.
```

What that cost, measured by running Suricata twice:

```
                                     validation ON   -k none
ET INFO PowerShell User-Agent            318           482     +164
ET INFO Microsoft Connection Test          0           164     NEW
```

Poller 1 hit `www.msftconnecttest.com` 167 times by its own log and was
completely invisible in the first run. Every one of its packets was outbound.

Fix: `zeek -C` and `suricata -k none`.

The 164,392 checksum decoder alerts in the benign run are a capture artifact,
not a detection result. On a network tap or SPAN port they would not occur.
They are excluded from every count in this repository and the exclusion is
stated wherever a benign figure appears.

### Connection-level logging erased a 264-request beacon

```
264 HTTP requests over 4h22m   ->  http.log:  264 rows, 263 gaps
one TCP connection             ->  conn.log:    1 row,    0 gaps
```

NetSupport sends `Connection: Keep-Alive` and never reconnects. The sid
1000002 alerts show it directly - source port 51912 on all five, four hours
apart.

Grouping by connection instead of by request turns the most regular beacon in
the data into a single unscoreable row. The granularity chosen decides what is
visible before any analysis runs.

### Zeek's HTTP parser discarded the entire operator session

The NetSupport interactive session sends frames beginning `NC_DATA` with no
HTTP request line at all. Zeek's parser rejected them, so 256 requests never
reached `http.log`. Suricata saw them only as
`SURICATA HTTP request missing protocol`.

Any rule using an `http.` buffer is blind to them, because those buffers only
exist after the parser succeeds. Detection had to move to raw TCP.

### Suricata writes local time, ground truth is UTC

```
fast.log          14:55:51
ground-truth.md   19:55 UTC
```

Same event, five hours apart. Mixing the two during correlation loses an hour
of an investigation. Every timestamp in this repository is stated with its
zone.

---

## 2. Analysis choices that changed the answer

### Gaps must be sorted before differencing

Taking differences on rows in log order produced this:

```
-901.98 seconds
```

A negative gap is impossible - it means one event appeared to happen before
the one preceding it. Zeek does not guarantee rows arrive in time order.
Sorting first removed the negative value and two phantom ~900-second gaps
that were never in the traffic.

Those phantom gaps were briefly read as network outages before being traced
to the missing sort.

### Median and MAD, not mean and standard deviation

Two ways to measure steadiness:

```
cv  = standard deviation / mean           every gap counts equally
rcv = median absolute deviation / median  a few odd gaps are ignored
```

Ranked by cv, most regular first:

```
0.002853   www.msftconnecttest.com    benign 60 s poller
0.107202   45.131.214.85              NetSupport C2 2026
0.216755   detectportal.firefox.com   benign 30 s poller
0.262683   38.146.28.242              NetSupport C2 2025
```

Ranked by rcv:

```
0.000160   45.131.214.85              NetSupport C2 2026
0.000902   www.msftconnecttest.com    benign 60 s poller
0.001218   38.146.28.242              NetSupport C2 2025
0.001888   detectportal.firefox.com   benign 30 s poller
```

Under cv a benign poller outranks every C2. Under rcv the C2 comes first.

The cause is in the same row of the feature table:

```
45.131.214.85     median_gap  60.082894
                  mad_gap      0.009601
                  std_gap      6.373817     664x larger than mad_gap
                  min_gap      0.148832
```

263 gaps sit within a hundredth of a second of 60.08. A handful of
near-instant gaps at startup are the rest. Standard deviation squares every
deviation before averaging, so three outliers outweigh 260 near-perfect
intervals. The median absolute deviation asks only for the typical distance
from the middle and never sees them.

### The 10-event floor is arithmetic, not a setting

A group needs at least 10 events before any gap statistic means anything.
That floor, not any threshold choice, is why the timing detectors missed
Formbook, STRRAT and 15 of 17 Emotet C2 servers.

---

## 3. Malware behaviour measured

### Four mechanisms that defeat interval analysis

```
keep-alive         NetSupport, STRRAT
                   STRRAT: 102 check-ins -> 1 conn.log row, 0 http.log rows

domain rotation    Formbook
                   ~20 domains at 1-3 requests each, nothing reaches 10

C2 IP rotation     Emotet
                   17 servers in 45 minutes, 2 cleared the floor
                   recall ceiling 12% before any model ran

burst transfer     StealC
                   rcv 0.632745, median request 400,696 bytes
                   one large exfiltration has no rhythm to measure
```

Every one of these cost the signature approach nothing. A signature needs to
see the traffic once.

### Durability measured, not asserted

Two NetSupport captures, six months apart:

```
                           2026               2025
C2 address         45.131.214.85      38.146.28.242    CHANGED
C2 port                  443                1203       CHANGED
URI                 /fakeurl.htm       /fakeurl.htm    SAME
User-Agent    NetSupport Manager/1.3   same            SAME

ET sid 2035892  (content)     264 alerts    48 alerts   survived
ET sid 2013926  (port 443)    264 alerts     0 alerts   broke
LOCAL sid 1000001 (content)   264 alerts    48 alerts   survived
```

### The operator arrived in 14 milliseconds

```
14:45:03.280010   beacon check-in, 299 bytes, Content-Length: 103
14:45:03.294108   first NC_DATA frame
                  = 14.098 ms
```

The check-in before the handover looks ordinary. One header number is larger
than usual - 103 bytes of payload instead of the routine 36. Then the
protocol changes.

The beacon then stopped for 546 seconds. While a person is driving the
connection the malware has no reason to poll for orders.

```
beaconing      43 packets over 2,525 seconds  =  0.017 packets/second
the session  4,045 packets over   546 seconds  =  7.41  packets/second
```

A second session followed the same pattern, 148 seconds long.

---

## 4. Detection errors found by cross-checking

### 74 alerts named the wrong malware family

ET Open's JA3 rule fired 74 times on the 2022 capture saying
`Possible Dridex`. The traffic is Emotet.

```
39 alerts from 172.16.0.170    documented Emotet
35 alerts from 172.16.0.149    documented Emotet
 0 alerts from 172.16.0.131    Formbook
```

JA3 fingerprints the TLS library and its configuration, not the malware.
Emotet and Dridex share one. The detection was correct; the name was not.
The rule author knew - they wrote "Possible."

This is why sid 1000003 describes the certificate it found rather than naming
a family, and why every family name in this repository traces to a
threat-intelligence lookup rather than to a detection.

### The same mistake, caught in this project's own rule

sid 1000003 was first written with the message
`LOCAL Emotet C2 - self-signed placeholder certificate`. The rule matches
placeholder strings in a self-signed certificate and cannot establish a
family. The message was corrected to describe what is seen. The match logic
never changed.

---

## 5. Errors found in this analysis and corrected

Every one of these was caught before any number in this repository was
written. They are recorded because the correction is part of the work.

```
grouping key took the port, not the address
   Detector 2 grouped on key[-1], which is the port. The destination column
   printed 53, 123 and 443. No row could ever match the malicious address
   list, so recall would have been 0 with nothing raising an error.

comment='#' in the CSV reader
   pandas would have truncated any row containing '#' in a URL, silently
   dropping the rest of that line. Replaced with explicit line filtering.

unsorted differencing
   produced a -901.98 second gap and two phantom ~900 s gaps.

STRRAT beacon interval assumed at 60 seconds
   The real interval is 5.0 seconds with 102 check-ins. The capture was
   nearly excluded from analysis on that assumption - an error of 12x.

"connection-level analysis is blind to every C2"
   False. Emotet opens fresh connections and was visible at connection
   level. Only the keep-alive C2s were invisible.

cv chosen before rcv
   ranked a benign poller above every C2. See section 2.
```