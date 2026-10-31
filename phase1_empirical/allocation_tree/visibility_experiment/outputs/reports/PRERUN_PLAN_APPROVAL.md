# Pre-run Plan & Approval

| Experiment | Supports claim | Essential? | Runtime | Disk | Compute/cost | External data | Decision |
|---|---|---:|---:|---:|---|---|---|
| Parse and classify the local RIPE IPv4/IPv6 PA allocation tree | RIPE contains direct and recursive PA paths in both AFIs | yes | about 5--15 min | below 500 MB derived output | CPU only; no monetary cost | none beyond the already-local dump | auto-approved (low cost) |
| Join exact root/endpoint routes and count disjoint origin sets | Quantifies visibility-related potential-conflict candidates by AFI | yes | about 10--25 min after download | about 0.6--1.0 GB including download and derived files | CPU only; no monetary cost | RIPE RIS RRC00 RIB (see dataset gate) | approved 2026-08-28 |

User approval received on 2026-08-28 for downloading and using the
2026-06-24 RIPE RIS RRC00 RIB and running the exact-route join.

Auto-approved (low cost): parsing and auditing the already-local RIPE Database
dump and testing the analysis code on synthetic fixtures.

## Post-run accounting

The approved experiment completed successfully. The conservative MRT path
took 42:57.67 and reached 303,816 KiB maximum process RSS. Its temporary
SQLite work database was observed at 1,770,348,544 bytes; together with the
411,493,623-byte RIB and the 367,373,318-byte RIPE dump, peak experiment disk
use was therefore about 2.6 GB rather than the pre-run 0.6--1.0 GB estimate.
The work database was deleted automatically after success. The independent
origin-CSV rerun took 13:16.83 and reproduced the compact and candidate tables
byte for byte. No monetary cost was incurred.
