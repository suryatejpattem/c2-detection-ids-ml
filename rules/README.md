# Rules

`local.rules` is the deployable set: sids 1000002, 1000003, 1000004.

`individual/` holds one rule per file so each can be tested on its own:

    suricata -r <capture>.pcap -S rules/individual/rule3.rules -l <outdir>

`individual/rule1.rules` (sid 1000001) is NOT deployed. It is sid 1000002
without the threshold, kept as the baseline that the 264 -> 5 alert
reduction is measured against. Loading it alongside 1000002 would double
every NetSupport alert.

`local.rules` is generated from the individual files and must be rebuilt
after any edit:

    cat individual/rule2.rules individual/rule3.rules individual/rule4.rules \
        > local.rules

Measured results for every rule: ../results/custom-rules.md