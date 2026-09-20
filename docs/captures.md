# Capture Sources

Packet captures are not committed to this repository. Four are publicly

available malware traffic captures; one was produced for this project and

contains no malicious traffic.

Each file's SHA256 is recorded below. Anyone reproducing this work can verify

they have the identical bytes:

```

sha256sum <file>.pcap          # Linux

Get-FileHash <file>.pcap       # PowerShell

```

## Why they are not in the repository

- `benign.pcap` is 298 MB; GitHub rejects files over 100 MB

- The four malicious captures total roughly 104 MB

- Distributing live command-and-control traffic through a public repository is

&#x20; not appropriate regardless of size

## Downloaded captures

All four are from malware-traffic-analysis.net. Archives on that site are

password-protected; the password scheme is documented on the site's "about"

page.

### 2026-02-28 — NetSupport RAT

```

page     https://www.malware-traffic-analysis.net/2026/02/28/index.html

file     2026-02-28-traffic-analysis-exercise.pcap

sha256   3dc470f5490ec15b4024c513e87c67e0b17caeae2a2ce3d83541be24ef407e61

sha1     d4755b2b695a8c0bf53407f7978b675619ce8b55

size     6,581 kB

```

### 2025-08-20 — NetSupport RAT + StealC v2

```

page     https://www.malware-traffic-analysis.net/2025/08/20/index.html

file     2025-08-20-SmartAgeSG-Netsupport-RAT-with-StealCv2.pcap

sha256   24de7b31a2248763c4fd3e92acfc6b6fa9462b129c7b4ff8024932407ebeae4b

sha1     b263fef4225930d8ea3d0d7037a36ddda17371f5

size     68 MB

```

### 2022-02-23 — Emotet + Formbook

```

page     https://www.malware-traffic-analysis.net/2022/02/23/index.html

file     2022-02-23-traffic-analysis-exercise.pcap

sha256   eefc7e61b50e7846f5a3282d7645539d7b2b4b85aa08a09d0b823896c9449d1f

sha1     fdfa0d0edfe0cbcc0c1400fbe6ac61ff40942755

size     19 MB

```

### 2024-07-30 — STRRAT

```

page     https://www.malware-traffic-analysis.net/2024/07/30/index.html

answers  https://www.malware-traffic-analysis.net/2024/07/30/page2.html

file     2024-07-30-traffic-analysis-exercise.pcap

sha256   c48854c24223cf7b4e9880ea72a21a877e4138e4ce36df7b7656e5c6c4043f68

sha1     2b2837c4ef1c08aae8fed3ce5026638bfd5aa858

size     11 MB

```

## Benign control capture

Produced for this project. Not redistributable in the repository due to size,

but fully reproducible from the method below.

```

file     benign.pcap

sha256   f6c34eadb8d01069702586645fc22b67f0aff6afe24345d7ce0219ca5baf3f1d

sha1     d394c718a68d79e1c9fed5674684ab2536874799

size     312 MB

packets  338,523

duration 2 h 47 m 14 s

```

### How it was produced

A Windows 11 virtual machine, checked beforehand for persistence artifacts left

by earlier lab work — none survived. See `data/ground-truth.md`.

```

dumpcap -i <ethernet device> -s 0 -F pcap -w benign.pcap

```

`-s 0` captures full packets. Truncated packets would leave HTTP headers

incomplete and produce empty fields in Zeek's `http.log`.

Activity during the capture:

- roughly 45 minutes of normal browsing across 20+ sites

- a Windows Update check

- the remainder idle, so scheduled background traffic dominates

Two PowerShell loops ran throughout, generating benign traffic on fixed

intervals:

```

http://www.msftconnecttest.com/connecttest.txt   every 60 s

http://detectportal.firefox.com/success.txt      every 30 s

```

These exist to test whether interval analysis can distinguish automated benign

traffic from malware beaconing. They are labelled `benign-synthetic` throughout

and are never presented as naturally occurring.

### Capturing on the sending host

Because the capture was taken on the machine generating the traffic, every

outbound packet carries an invalid checksum — the network card computes

checksums after the capture tool copies the packet. This affects 82,711

packets, 24.4% of the capture.

Both analysis tools must be told to ignore it:

```

zeek -C -r benign.pcap

suricata -k none -r benign.pcap -l <output>

```

Without these flags, Zeek discards every outbound packet and Suricata leaves

part of the traffic uninspected. Neither reports an error. Details in

`data/ground-truth.md`.

