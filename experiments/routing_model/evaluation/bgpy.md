# BGPy evaluation for S2-ROV Internet-scale experiments

## Bottom line

**BGPy is a strong fit for the next S2-ROV experiment and should remain the
leading candidate for the steady-state reachability/exposure study.** It has
native CAIDA AS-relationship ingestion, explicit Gao--Rexford propagation,
exact-prefix multi-origin competition, built-in ROV, per-AS policy assignment,
fixed or randomized incremental adoption, per-AS Loc-RIB access, control/data
plane analyzers, multiprocessing, and a system-test framework.

S2-ROV should be added as a project-owned adapter outside `vendor/bgpy`; the
upstream clone need not be patched. A minimal static adapter is modest. A
faithful implementation of all four states plus the prototype's
`Explicit > Delegated > NotFound` local-preference ordering is a medium-sized
extension because BGPy's built-in ROV acceptance hook is Boolean and its stock
Gao--Rexford selector has no route-validation preference dimension.

## Identity, version, and license

There are two unrelated projects named BGPy. The BGP security simulator is
distributed as **`bgpy-pkg`** but imported as `bgpy`. The unrelated package
named `bgpy` is a background-process/socket library and must not be installed.

Authoritative evidence:

- [Official repository](https://github.com/jfuruness/bgpy_pkg)
- [PyPI distribution](https://pypi.org/project/bgpy-pkg/)
- [Official installation instructions](https://github.com/jfuruness/bgpy_pkg/wiki/Installation)
- [Official testing instructions](https://github.com/jfuruness/bgpy_pkg/wiki/Testing)
- [Official policy inventory](https://github.com/jfuruness/bgpy_pkg/wiki/Routing-Policies)

The PyPI release current at evaluation time is 13.0.10 and declares Python
`>=3.10`; the classifiers list CPython/PyPy and Python 3.10--3.14. The pinned
checkout records the same facts in `pyproject.toml:5-8,39-48`. The license is
MIT (`LICENSE.txt`).

The upstream repository has **no Git tags**. `master` was
`57ad7c5e0a3ac29355fdb9149f4e386d2e08b546` and identified itself as the
unpublished 13.0.12. For a reproducible stable baseline, the clone was detached
at `c3b1be48...`, the commit whose metadata is 13.0.10 and immediately precedes
the 17 January 2026 PyPI upload. The installed wheel's Python source matches the
pinned checkout; only test ground-truth assets are absent from the wheel.

## Paths and environment

- Clone: `experiments/routing_model/vendor/bgpy`
- Isolated test environment: `experiments/routing_model/vendor/bgpy/.venv`
- Installed package: `bgpy-pkg 13.0.10`
- Installed RPKI helper: `roa-checker 3.1.5`
- Installed ROV data helper: `rov-collector 1.1.16`

The host has PyPy 3.9.18, which is below BGPy's required Python 3.10. The
evaluation therefore used CPython 3.12.3. The official guide says a supported
PyPy is often 5--10x faster; campaign-scale timing should be piloted before
choosing CPython concurrency.

## Command and outcome log

### Repository acquisition

```console
$ /usr/bin/time -p git clone https://github.com/jfuruness/bgpy_pkg.git \
    experiments/routing_model/vendor/bgpy
Cloning into 'experiments/routing_model/vendor/bgpy'...
real 8.95
user 0.85
sys 0.55

$ git checkout --detach c3b1be48148e8c246a60b9dec6513b688a4736a5
HEAD is now at c3b1be48 Updating dependencies

$ git ls-remote --tags origin | wc -l
0
```

### Environment installation

```console
$ python3 -m venv .venv
$ /usr/bin/time -p .venv/bin/python -m pip install --upgrade pip wheel
Successfully installed packaging-26.2 pip-26.2 wheel-0.47.0
real 15.71
user 2.67
sys 0.37
```

The first documented development install, `pip install '.[test]'`, yielded
partial output at the command runner's 30-second boundary. A subsequent check
was made too early and reported the package absent, so the documented PyPI
fallback `pip install 'bgpy-pkg[test]==13.0.10'` was started. Process inspection
then showed that the first command had remained alive, causing the two installs
to overlap. Neither was killed; both completed naturally. This runner anomaly
is recorded rather than hidden. Environment integrity was checked afterward:

```console
$ vendor/bgpy/.venv/bin/python -m pip check
No broken requirements found.

$ /usr/bin/time -p vendor/bgpy/.venv/bin/python -c '<version/import probe>'
bgpy module: .../vendor/bgpy/.venv/lib/python3.12/site-packages/bgpy/__init__.py
bgpy-pkg: 13.0.10
roa-checker: 3.1.5
rov-collector: 1.1.16
real 1.35
user 3.76
sys 0.12
```

Installing the `test` extra also installed `tox` and current `chardet 7.4.3`.
Requests 2.32.5 consequently emits a `RequestsDependencyWarning`. `pip check`
does not classify this as broken. For actual campaigns, use a separate runtime
environment with `bgpy-pkg==13.0.10` without the test extra, and keep this
environment only for upstream tests.

### Official example and tests

The bundled `scripts/example.py` in 13.0.10 is not executable as shipped:

```console
$ python3 -m py_compile scripts/example.py
  File "scripts/example.py", line 101
    override_attacker_asns=frozenset({ASNs.ATTACKER.value,})
SyntaxError: invalid syntax. Perhaps you forgot a comma?
```

An initial `-k ex_000_valid_prefix_bgp_simple` selector selected zero tests
because the official suite uses IDs such as `conf0`; pytest exited 5. After
collecting the supported IDs, the exact engine test was run. Propagation and
result serialization completed, but diagram rendering failed because this host
does not have the system Graphviz `dot` executable. This is an environment
prerequisite documented by upstream, not a propagation failure. No system
package was installed during this evaluation.

The official Scenario tests, which exercise the CAIDA-backed engine without
requiring `dot`, passed:

```console
$ /usr/bin/time -p .venv/bin/python -m pytest \
    bgpy/tests/framework_tests/unit_tests/test_scenario.py -q
======================== 22 passed, 1 warning in 36.81s ========================
real 39.01
user 40.61
sys 1.78
```

The one warning is the Requests dependency warning described above.

### Public-API propagation smoke tests

The official `ex_config_004` fixture was executed directly through the public
engine/analyzer API, omitting only diagram generation:

```console
scenario: ex_004_subprefix_hijack_rov_simple
ASes: 12
announcements: [('1.2.0.0/16', 777), ('1.2.3.0/24', 666)]
ROAs: [('1.2.0.0/16', 777)]
ROV AS 9 local RIB: {'1.2.0.0/16': (9, 4, 777)}
CTRL outcomes: {'ATTACKER_SUCCESS': 8, 'VICTIM_SUCCESS': 4}
DATA outcomes: {'ATTACKER_SUCCESS': 8, 'VICTIM_SUCCESS': 4}
real 1.49
```

This confirms that the ROV node filtered the invalid more-specific route while
retaining the valid aggregate.

The official exact-prefix hijack fixture demonstrates two simultaneous origins
competing for one prefix:

```console
sources: [(666, '1.2.0.0/16'), (777, '1.2.0.0/16')]
selected origins: {666: 5, 777: 7}
data-plane outcomes: {'ATTACKER_SUCCESS': 5, 'VICTIM_SUCCESS': 7}
real 1.45
```

Running the fixed ROV fixture twice with `PYTHONHASHSEED=0` produced exact
equality for all per-AS RIB snapshots and both outcome maps:

```console
exact_match: True
AS_ribs_compared: 12
real 1.45
```

### CAIDA Internet graph

The official tests downloaded their default monthly CAIDA serial-2 graph to
BGPy's platform cache, which is outside `routing_model`:

```text
<home>/.cache/bgpy/2026-08-04/
  CAIDAASGraphCollector_2026.07.25.txt
```

This side effect is caused by the upstream test fixture's default constructor.
Future routing-model code must pass an explicit `cache_dir` under
`experiments/routing_model/data/cache` and an explicit `dl_time`.

Downloaded file evidence:

```text
size:    13,998,401 bytes
lines:   752,004
sha256:  aabd0b2154d9dec5b4c0b63d1d9f88cbfbf381bbc4d2246fe0471dd4aacf2181
source header begins: # source:topology|BGP|20260701|routeviews|eqix
```

Graph construction itself succeeded and reported:

```text
ASes:                         80,144
customer-provider edges:     165,811
peer edges:                  586,011
propagation ranks:                  90
input-clique ASes:                  19
```

The probe then exited 1 on a nonessential display lookup because the requested
group key was misspelled (`stubs_or_multihomed` rather than the package enum's
actual value). The graph and the preceding counts had already been constructed.
Elapsed time was 29.16 s with customer/provider cone storage disabled.

## Capability assessment

| Requirement | Assessment | Evidence and caveat |
|---|---|---|
| CAIDA AS graph | **Native / strong** | Serial-2 collector, deterministic relationship parser, input clique and AS groups; 80,144-AS current graph constructed. Pin and hash the monthly source rather than use the rolling default. |
| Gao--Rexford | **Native / strong** | Engine propagates customer routes upward, then peers, then customers; selection is relationship local preference, AS-path length, then lowest-neighbor-ASN tie break (`gao_rexford.py`). |
| Multi-source competition | **Native / verified** | Two exact-prefix origins were seeded and selected across the same 12-AS graph. Multiple prefixes and subprefix/aggregate fallback are also native. |
| Conventional ROV | **Native / verified** | Built-in `ROV` rejects `roa-checker` Invalid and accepts Valid/Unknown; official subprefix fixture verified filtering. |
| Custom policy | **Strong extension point** | Policies are swappable classes. Overriding `_valid_ann` is sufficient for static admission; overriding route comparison is needed for DA-state local-preference ordering. |
| Per-AS incremental deployment | **Native / strong** | `override_adopting_asns`, `hardcoded_asn_cls_dict`, and `hardcoded_base_asn_cls_dict` permit exact AS sets. A DA subset can override a fixed measured-ROV baseline. |
| Deployment strategies | **Native with project code** | Built-in random percentage adoption is stratified across AS categories. For random/degree/customer-cone deployment among the 589 measured ROV ASes, precompute exact sets and pass `override_adopting_asns`; do not use the global percentage sampler. |
| Reproducibility | **Good when explicitly pinned** | Supports `python_hash_seed`, fixed overrides, YAML fixtures, ground-truth tests, and deterministic tie breaking. Defaults are not sufficient: topology date is rolling, multiprocessing seeds depend on chunk/CPU count, and random AS sampling must be fixed. |
| Output granularity | **Strong engine, coarse default export** | Every AS exposes a per-prefix Loc-RIB and analyzer output is per-AS control/data-plane outcome. The default simulation CSV stores only aggregated means and `yerr`; raw trial/AS observations require a custom analyzer/writer. |
| Aggregate fallback / data plane | **Native / useful** | Analyzer chooses the most-specific locally available route and traces `next_hop_asn`, so delegated-/24 delivery can be separated from mere aggregate reachability. |
| Parallel execution | **Native** | Trials are split across processes and each process constructs its own engine. Fix `parse_cpus`, seed, topology, and scenario ordering for repeatability. |
| Dynamics | **Limited for this study** | `BGPFull` models RIBs-in/out and withdrawals, but BGPy is primarily a round-based steady-state simulator, not a packet-level or wall-clock BGP convergence emulator. This is acceptable for the proposed reachability/exposure experiment. |

## Mapping S2-ROV onto BGPy

### Recommended policy layout

Use three policy classes in one graph:

1. `BGP` for ASes without ROV;
2. stock `ROV` for measured ROV ASes that have not upgraded; and
3. project-owned `S2ROV` for the selected S2-ROV-aware subset.

`ScenarioConfig.hardcoded_base_asn_cls_dict` can map all 589 measured ROV ASes
to stock `ROV`. `override_adopting_asns` then names the subset upgraded to
`S2ROV`; the scenario's lookup order gives adopters precedence over the base
mapping. This directly represents incremental deployment without modifying the
CAIDA graph or upstream code.

The stock Scenario automatically treats victims as adopters and attackers as
non-adopters. For a deployment experiment, subclass Scenario and override these
endpoint defaults so capability is controlled only by the explicit deployment
set; otherwise endpoints can silently acquire the DA policy.

### Four-state implementation cost

A static reachability/exposure experiment needs:

- an immutable DA policy index backed by the existing S2-ROV-encoding reference
  validator;
- `S2ROV._valid_ann`, accepting `Explicit`, `Delegated`, and `NotFound` under
  the chosen enforcement profile and rejecting `Invalid`;
- paired legitimate-delegate and eligible-unlisted-origin scenarios;
- a custom analyzer/writer that records per trial, per AS, selected prefix,
  selected origin, path, DA state, and deployment membership; and
- small-topology ground-truth tests for all four states, exact-prefix
  competition, aggregate fallback, closed override, and partial deployment.

Estimated project-owned code: **200--350 lines plus tests**, roughly **1--2
engineering days** before a small pilot.

Faithfully implementing the prototype's state preference
`Explicit (LP 300) > Delegated (LP 200) > NotFound (LP 100)` requires more than
the Boolean admission hook. BGPy's stock selector first compares relationship,
then AS-path length. The adapter must either extend the announcement with a
state/preference field or override `_get_best_ann_by_gao_rexford` to compare the
DA action before the stock path rules. If withdrawals/BGPFull and upstream-style
system tests are also required, estimate **400--700 lines and 3--5 engineering
days**.

For the first paper experiment, the full dynamic implementation is unnecessary:
the primary paired legitimate/unauthorized routes are both `Delegated`, so
stock Gao--Rexford can break their competition after DA admission. Nevertheless,
the four-state classifier must still be exported per AS, and an Exact-ROA
baseline must use stock ROV so the attacker is actually filtered.

### Output schema for the campaign

Do not rely solely on BGPy's aggregate CSV. Persist one row per scenario-AS pair
with at least:

```text
trial_id, scenario_pair_id, topology_sha256, deployment_strategy,
deployment_fraction, da_aware_asn, observer_asn, role,
selected_prefix, selected_origin, selected_path, validation_state,
control_reachable, data_plane_outcome
```

Aggregate later into legitimate delegated-/24 propagation, aggregate-only
fallback, attacker infection, and paired deltas. Keeping raw rows makes error
bars and reviewer audits reproducible.

## Risks requiring controls

1. **Rolling topology default.** BGPy chooses a date relative to the current
   day. Pin `dl_time`, copy the source under routing-model, and record SHA-256.
2. **CPU-count-dependent random streams.** The simulation seeds per chunk;
   changing `parse_cpus` changes trial assignment. Fix both seed and CPU count,
   or precompute all attacker/victim/deployment sets and use overrides.
3. **Global ROA checker.** `Policy.roa_checker` is class-global. Process-based
   trials are safe if each scenario resets it as designed; do not introduce
   threaded concurrent scenarios.
4. **Default endpoints affect adoption.** Victim and attacker policy defaults
   must be overridden for a clean staged-deployment study.
5. **Default output loses raw trials.** Write project-owned raw results before
   aggregation.
6. **Default error bar appears twice the usual half-width.** BGPy computes
   `yerr = 2 * 1.645 * s / sqrt(n)` and passes it directly to Matplotlib's
   `errorbar`, whose `yerr` is a distance above and below the center. Do not use
   this field for paper figures; compute and document our own CI or percentile
   interval from raw trials.
7. **Examples/documentation lag.** The bundled 13.0.10 example has a syntax
   error, and the wiki includes older API snippets. Treat source tests and
   pinned code as authoritative.
8. **Graphviz is optional for simulation but required by engine-test diagrams.**
   Run headless project tests without diagrams or add a declared system
   dependency in the routing-model environment recipe.
9. **Performance.** CPython graph construction without cone materialization was
   about 29 s. Run a 10-pair x 3-deployment pilot before launching thousands of
   full-graph scenarios; measure wall time and peak RSS, then choose process
   count conservatively.

## Recommendation for the parent comparison

Independently of the InternetSim result, BGPy meets the scientific requirements
for the planned steady-state experiment and offers a defensible, peer-reviewed,
extensible basis that is materially better than the previous hand-written
simulator. Select it unless InternetSim demonstrates both (a) equally direct
per-AS policy heterogeneity and four-state extension points and (b) clearly
better tested output/reproducibility. The BGPy implementation should live in a
new project-owned source tree under `routing_model`, with the pinned vendor
clone treated as read-only.
