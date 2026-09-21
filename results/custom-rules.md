# Custom Suricata Rules — Results

Four rules written from indicators measured in the five captures, then tested
against all five. Every number below came from a run recorded in this
repository. Nothing is estimated.

Engine: Suricata 8.0.6 RELEASE
Rules tested in isolation with `-S` (use ONLY this file, ignore ET Open).

---

## Reproducing these numbers

```
# the three deployable rules, all captures
suricata -r <capture>.pcap -S rules/local.rules -l <outdir>

# one rule at a time
suricata -r <capture>.pcap -S rules/individual/rule2.rules -l <outdir>

# benign.pcap only - see the checksum note at the bottom
suricata -r benign.pcap -S rules/local.rules -l <outdir> -k none

# count alerts per rule
grep -c ":1000002:" <outdir>/fast.log
```

---

## Results

`rules/local.rules` contains sids 1000002, 1000003 and 1000004.
sid 1000001 lives in `rules/individual/rule1.rules` and is **not** deployed —
it is the baseline that Rule 2 is measured against.

```
sid       anchor   c2_2025   sunnystation   dirtyrat   benign
          (2026)   (2025)    (2022)         (2024)     (own capture)
-----------------------------------------------------------------------
1000001     264       48          0             0          0     baseline
1000002       5        1          0             0          0
1000003       0        0         27             0          0
1000004       0        3          0             0          0
-----------------------------------------------------------------------
shipped       5        4         27             0          0
```

False positives on 338,523 packets of benign traffic: **0**, every rule.

---

## sid 1000001 — NetSupport check-in, content only (baseline, not deployed)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"LOCAL NetSupport RAT Check-in - content indicators only";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/fakeurl.htm"; startswith;
    http.user_agent; content:"NetSupport Manager/1.3"; fast_pattern;
    classtype:trojan-activity;
    sid:1000001; rev:1;
)
```

**Goal.** Prove that a rule built only on content survives the attacker
changing infrastructure.

**What it matches.** POST method, URI beginning `/fakeurl.htm`, User-Agent
`NetSupport Manager/1.3`. No IP address, no port. `any` on the destination
port is the entire point of the rule.

**Result.**

```
anchor 2026    264 alerts   ->  45.131.214.85:443
c2_2025        48 alerts    ->  38.146.28.242:1203
others          0 alerts
```

Between the two captures the C2 address changed **and** the port changed.
The rule was not modified between runs.

**Measured against ET Open on the same two files:**

```
                                      2026      2025
ET sid 2035892  (URI + User-Agent)     264       48     survived
ET sid 2013926  (port 443 hardcoded)   264        0     broke
LOCAL sid 1000001 (this rule)          264       48     survived
```

This is the only rule in this set whose durability is measured rather than
assumed, because it is the only one with two independent captures of the same
malware to test against.

**Why it is not deployed.** 264 alerts for one infected host across four hours
is unusable in a queue. Superseded by sid 1000002.

---

## sid 1000002 — same detection, rate limited

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"LOCAL NetSupport RAT Check-in - rate limited";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/fakeurl.htm"; startswith;
    http.user_agent; content:"NetSupport Manager/1.3"; fast_pattern;
    threshold: type limit, track by_src, count 1, seconds 3600;
    classtype:trojan-activity;
    sid:1000002; rev:1;
)
```

**Goal.** Same detection, alert volume an analyst can work with.

**The only change from sid 1000001** is the `threshold` line. The match logic
is byte-for-byte identical, so detection is unchanged — only reporting is.

```
type limit      alert on the first match in the window, then stay quiet.
                Detection continues underneath; the alerts stop.
track by_src    one window per source IP, so two infected hosts each get
                their own alert instead of sharing one.
count 1         one alert per window.
seconds 3600    the window opens at the first match, not on the clock hour.
```

**Result.**

```
              sid 1000001    sid 1000002
anchor 2026        264            5
c2_2025             48            1
```

Alert timestamps on anchor, confirming the hourly spacing:

```
14:55:51.679800    10.2.28.88:51912 -> 45.131.214.85:443
15:56:01.209424    same source port
16:56:10.603065    same source port
17:56:18.809691    same source port
18:56:26.197517    same source port
```

**Source port 51912 on all five alerts, four hours apart.** One TCP connection
held open for the entire session — the keep-alive behaviour that produces a
single `conn.log` row and defeats connection-level timing analysis.

**Trade-off, stated.** Alert count no longer tells you check-in count. An
analyst who needs the beacon frequency has to read the flow records, not the
alert queue. That is the correct trade — an alert exists to get attention once,
and the investigation reads the logs — but it is a real loss and worth saying.

---

## sid 1000003 — self-signed certificate with placeholder identity strings

```
alert tls $EXTERNAL_NET any -> $HOME_NET any (
    msg:"LOCAL Self-signed certificate with placeholder identity strings";
    tls.cert_subject; content:"O=Global Security"; content:"CN=example.com";
    tls.cert_issuer;  content:"O=Global Security"; content:"CN=example.com";
    classtype:trojan-activity;
    sid:1000003; rev:3;
)
```

**Goal.** Detect the Emotet C2 traffic in the 2022 capture, which is TLS
encrypted and which no ET Open rule named correctly.

**Why content matching was impossible.** The payload is encrypted. There is no
URI and no User-Agent to read. TLS negotiates in cleartext before encryption
begins, so three things remain readable: the SNI, the JA3 fingerprint, and the
server certificate. All three were checked against the capture before any rule
was written.

```
SNI    39 of 71 sessions on 172.16.0.170 had none
       44 of 90 sessions on 172.16.0.149 had none
       the sessions that did carry an SNI were Microsoft telemetry and Bing
       -> Emotet connects to raw IPs and never names a host. Dead end,
          and a measured fact about the malware.

JA3    ET Open already had a JA3 rule. It fired 74 times and said
       "Possible Dridex" on traffic that was Emotet. JA3 fingerprints the
       TLS library and its configuration, not the malware, and those two
       families share one. Building on JA3 would reproduce a known
       attribution error.

cert   usable - see below.
```

**What the certificate showed.**

```
subject   C=GB, ST=London, L=London, O=Global Security,
          OU=IT Department, CN=example.com
issuer    C=GB, ST=London, L=London, O=Global Security,
          OU=IT Department, CN=example.com
```

Subject and issuer identical, character for character. Nobody signed it — it
signed itself. `O=Global Security` and `OU=IT Department` are placeholders,
and `example.com` is the domain reserved by standards so documentation can
print a fake one.

Distribution in the capture:

```
172.16.0.170    18 sessions     Emotet victim
172.16.0.149     9 sessions     Emotet victim
172.16.0.131     0 sessions     Formbook victim - no TLS at all
                --
                27 sessions
```

Every other certificate in the capture traced to DigiCert or a Microsoft CA.

**Requiring both strings in BOTH buffers** is how the rule says "self-signed."
A legitimate certificate carries a real CA in the issuer field and cannot
satisfy the second half.

**Result.** 27 alerts, and they surfaced **16 distinct C2 servers**:

```
to 172.16.0.170 - 13 servers
   61.7.231.229:443      59.148.253.194:443     180.250.21.2:443
   61.7.231.226:443      168.197.250.14:80
   54.37.106.167:8080    162.144.76.184:8080    139.196.72.155:8080
   27.254.174.84:8080    128.199.93.156:8080    128.199.192.135:8080
   198.199.98.78:8080    185.184.25.78:8080

to 172.16.0.149 - 3 servers
   144.217.88.125:443    135.148.121.246:8080   134.209.156.68:443
```

Three different ports — 443 on six servers, 8080 on nine, and **80 on one**.
Port 80 is the port for plain unencrypted HTTP and there is a TLS handshake
running on it. Suricata found TLS by reading the handshake bytes, not by
trusting the port.

The two victims share no servers at all.

**Measured against the existing ruleset.** ET Open's JA3 rule on the same
capture:

```
                    alerts   unique C2 servers
ET Open JA3            74            17
LOCAL sid 1000003      27            16
```

The 16 are a subset of the 17; the missing one is `54.38.242.185:443`. No
confirmed reason for the miss — most likely that session reused an earlier TLS
session so no certificate was re-sent, but this has not been verified.

**So this rule adds an independent mechanism, not additional coverage.** The
two rules fail for different reasons: ET's reads the *client's* hello and dies
if the malware is rebuilt with a different TLS library; this one reads the
*server's* certificate and dies if the operator regenerates certificates. Two
separate changes are needed to defeat both.

**What it cannot do.** It cannot name a malware family, and the `msg` does not
claim to. Placeholder self-signed certificates are used by other families and
by careless test servers. Attribution to Emotet in this repository came from a
threat-intelligence lookup of the C2 addresses, not from the rule.

Durability is **unproven** — only one Emotet capture exists here, so there is
no second file to test an infrastructure change against.

---

## sid 1000004 — NetSupport interactive session

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"LOCAL NetSupport RAT - interactive session active, operator at keyboard";
    flow:established,to_server;
    content:"NC_DATA|0a|"; fast_pattern;
    content:"CID="; distance:0;
    threshold: type limit, track by_src, count 1, seconds 300;
    classtype:trojan-activity;
    sid:1000004; rev:1;
)
```

**Goal.** Separate "this host is beaconing" from "an operator is inside this
host right now." Rules 1 to 3 cannot — the malware, URI and User-Agent are
identical either way.

**Why no HTTP rule could work.** Three counts from the same capture:

```
total requests the victim sent           304     48 check-ins + 256 burst
ET sid 2035892  (an http rule)            48
LOCAL sid 1000001 (an http rule)          48
SURICATA HTTP request missing protocol   256
```

Buffers such as `http.uri` and `http.user_agent` only exist after Suricata's
HTTP parser has understood the request. "HTTP request missing protocol" means
the parser failed, so those buffers are empty and no `http` rule can reach the
bytes. The session traffic had to be read as raw TCP.

**What the packet timeline showed** (times relative to capture start):

```
t=776.27    218 bytes  |
t=776.43    446 bytes  |  four packets inside one second - registration
t=776.78    272 bytes  |
t=777.18    273 bytes  |

t=837.22    232 bytes  |
t=897.47    232 bytes  |  43 packets, exactly 60.2 seconds apart,
   ...      232 bytes  |  identical size every time
t=3362.68   232 bytes  |

t=3419.23   299 bytes  <-- larger, then check-ins STOP

            546 seconds, no check-ins

t=3965.51   232 bytes  |  5 more beacons
t=4206.08   232 bytes  |

t=4240.68   299 bytes  <-- larger again, then check-ins stop

            148 seconds, no check-ins

t=4388.41   232 bytes  |  5 more beacons
t=4628.74   232 bytes  |
```

Not one packet carrying `NetSupport Manager` appears inside either gap, so a
User-Agent rule is blind to the whole intrusion. The beacon stops during a
session because the malware has no reason to poll while a human is driving it.

**Inside the 546-second gap: 4,045 packets**, sizes never repeating —
434, 447, 428, 437, 145, 87, 135, 103, 136, 87, 76, 88, 79, 964, 965.

```
beaconing      43 packets over 2,525 seconds   =  0.017 packets/second
the session  4,045 packets over   546 seconds   =  7.41  packets/second
```

Four of them sit 0.3 milliseconds apart.

**Every packet in the gap begins with the same eight bytes:**

```
4e 43 5f 44 41 54 41 0a   =   N C _ D A T A \\n
```

```
BEACON (232 bytes, every 60.2 s)        SESSION (4,045 packets in 546 s)

POST http://38.146.28.242/fakeurl.htm   NC_DATA
     HTTP/1.1                           Content-Length:   403
User-Agent: NetSupport Manager/1.3
Content-Length:    36                   CID=1190
Host: 38.146.28.242                     SEQ=3
Connection: Keep-Alive                  CRC=1895889993
                                        LEN=348
CMD=ENCD ...                            DATA=<binary>
```

This explains the 256 anomaly alerts exactly. A valid HTTP request line has a
method, a target and a version. These frames have one word. Suricata looked
for the version token, found none, and said so — 256 times.

`Connection: Keep-Alive` is what makes it possible: one TCP connection carried
HTTP for 44 minutes, then a completely different protocol, without
reconnecting.

**Result.** 3 alerts on c2_2025, 0 everywhere else.

```
14:45:03.294108   10.8.20.101:63910 -> 38.146.28.242:1203
14:50:08.038940   same source port
14:58:44.724405   same source port
```

The last beacon check-in was at `14:45:03.280010`. The first session frame
arrived **14.098 milliseconds later**. The second session began the same way —
a 299-byte check-in, then session frames 47 milliseconds later. On the wire the
handover looks like nothing at all: one header number is larger than usual.

Source port 63910 on all three alerts and on the sid 1000002 alert at
14:01:00 — one connection, 77 minutes, one `conn.log` row.

4,045 packets produced 3 alerts.

**`seconds 300` rather than Rule 2's `3600`** because this is the opposite
situation. A beacon means there is time. An operator at the keyboard means
there is not, and the question is whether they are *still there*. Five minutes
gives a heartbeat that keeps arriving while the session is live and stops when
it ends. The number was chosen from the measured session lengths, 546 and 148
seconds.

**anchor scored 0**, and that is the finding:

```
anchor 2026    264 check-ins over 4h22m, 0.21 s jitter   nobody ever connected
c2_2025         48 check-ins, then a human took over     two hands-on sessions
```

Same malware family, same indicators. Both hosts are infected; only one has a
person inside it. That is a triage decision, not a detection.

**What it cannot do.** `NC_DATA` is one product's protocol keyword — a hands-on
session from any other RAT will not fire it. It fires after the operator is
already inside, so it limits damage rather than preventing entry. Everything it
matches is cleartext; if the session protocol were wrapped in TLS the rule
would score 0, which is the wall sid 1000003 ran into. And like sid 1000003,
its durability is unproven — one capture, no second file to test against.

---

## Notes on the numbers

**`-k none` on benign.pcap only.** That capture was taken on the sending
machine, where the network card fills in checksums *after* the capture point.
82,711 of 338,523 packets (24.4%) therefore carry invalid checksums and
Suricata skips them for detection by default. The four downloaded captures were
recorded elsewhere on the network and have valid checksums, so they need no
flag. Without `-k none` the false-positive test would silently cover only
three quarters of the traffic.

**sid range.** 1000000–1999999 is reserved for local rules, so none of these
can collide with an ET Open sid.

**What "0 false positives" means here.** Zero alerts from these four rules on
`benign.pcap` — 338,523 packets, 2h47m, one Windows host with synthetic
HTTP pollers running. It does not mean zero false positives on a production
network, which has far more variety than one laptop.

**Durability.** sid 1000001 and 1000002 are tested against two independent
captures of the same malware with different infrastructure. sid 1000003 and
1000004 are tested against one capture each. That difference is real and is not
smoothed over anywhere in this repository.
