# Rules

`local.rules` is the deployable set: sids 1000002, 1000003 and 1000004.

`individual/` holds one rule per file so each can be tested on its own:

```
suricata -r <capture>.pcap -S rules/individual/rule3.rules -l <outdir>
```

`individual/rule1.rules` (sid 1000001) is NOT deployed. It is sid 1000002
without the threshold, kept as the baseline that the 264 -> 5 alert reduction
is measured against. Loading it alongside sid 1000002 would make every
NetSupport check-in alert twice.

`local.rules` is generated from the individual files and must be rebuilt after
any edit:

```
cat individual/rule2.rules \
    individual/rule3.rules \
    individual/rule4.rules > local.rules
```

To check the deployed file holds the right rules:

```
grep -o 'sid:[0-9]*' local.rules
```

It should print sid:1000002, sid:1000003 and sid:1000004. If sid:1000001
appears, `local.rules` was rebuilt with the wrong files.

Measured per-capture results for every rule: `../results/custom-rules.md`