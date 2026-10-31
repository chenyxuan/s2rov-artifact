# Dataset / License / Terms Gate

## Dataset gate: RIPE Database dump

- Source URL: <https://ftp.ripe.net/ripe/dbase/ripe.db.gz>
- Download size / disk: already local; 367,373,318 bytes compressed / no new
  raw-data disk requirement.
- License / ToU: RIPE Database Terms and Conditions and Acceptable Use Policy
  (status: clear for this noncommercial academic aggregate analysis).  The
  analysis consumes prefix/range, status, and organisation-handle fields and
  does not redistribute the raw dump.
- User confirmation required: no -- the input was already present, and the
  requested experiment explicitly places the RIPE allocation tree in scope.
- Estimated runtime: about 5--15 minutes on CPU.
- Needed for essential claims: yes -- it defines the allocation paths.
- Decision: proceed with the local parsing run.

Relevant terms:
<https://www.ripe.net/manage-ips-and-asns/db/support/documentation/terms/>
and
<https://www.ripe.net/manage-ips-and-asns/db/support/documentation/ripe-database-acceptable-use-policy/>.

## Dataset gate: RIPE RIS RRC00 `bview.20260624.0000.gz`

- Source URL:
  <https://data.ris.ripe.net/rrc00/2026.06/bview.20260624.0000.gz>
- Download size / disk: 411,493,623 bytes compressed; estimated peak below
  1.0 GB including the origin table and experiment outputs.  Parsing is
  streamed, so no full uncompressed MRT copy is created.
- License / ToU: RIPE NCC Website and Publicly Available RIPE NCC Services
  Terms of Service (status: clear for direct, noncommercial academic research
  use).  RIPE RIS and RIPE NCC will be acknowledged.  Separate commercial-use
  conditions are not applicable to this manuscript analysis.
- User confirmation required: yes -- this is a new external download and the
  experiment gate requires explicit pre-run approval.
- Estimated runtime: roughly 2--10 minutes to download and 10--25 minutes for
  streaming MRT extraction plus the exact-route join, depending on network and
  storage throughput.
- Needed for essential claims: yes -- the local 2026-06-24 RouteViews RIB is
  IPv4-only, so it cannot support the requested IPv6 row.
- Decision: proceed; explicit user approval received on 2026-08-28.

Post-run resource correction: the 411,493,623-byte download matched the
estimate, but the SQLite join database grew to an observed 1,770,348,544
bytes. Including both frozen inputs and the independently derived 30,978,869-
byte origin CSV, peak retained-plus-temporary disk use was about 2.6 GB. The
temporary database was removed after each successful run.

Dataset documentation:
<https://ris.ripe.net/docs/mrt/>.  Service and commercial-use conditions:
<https://www.ripe.net/about-us/legal/terms-of-service/> and
<https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/commercial-use/>.
