# InternetSim evaluation for S2-ROV Internet-scale experiments

## Material Passport

- **Origin skill:** `academic-research-suite`, experiment `run` / compatibility audit
- **Evaluation date:** 2026-08-04
- **Verification status:** **ANALYZED; build conditionally verified; official example failed**
- **Evaluated source:** official paper metadata, authors' publication page, official GitHub repository, and the checked-out source
- **Official repository:** <https://github.com/internetsys/InternetSim>
- **Pinned commit:** `a96b15716f579658b9d745c8abe1805dd869e375`
- **Paper:** Jiahong Lai, Jessie Hui Wang, Yunhao Liu, and Jilong Wang, “InternetSim: A Fast and Memory-Efficient Internet-Scale Inter-Domain Routing Simulator,” ACM IMC 2025, pp. 204–212, DOI [10.1145/3730567.3732924](https://doi.org/10.1145/3730567.3732924)
- **Host:** Ubuntu 24.04.3 LTS, aarch64, CPython 3.12.3, GCC 13.3.0, CMake 3.28.3, 32 logical CPUs, 62 GiB RAM
- **Upstream code modified:** no tracked file was edited

## Bottom line

**Do not use InternetSim as the primary routing-model platform. Use BGPy.**

InternetSim has attractive architecture for full-Internet routing and incremental
policy updates, but the current public artifact is not runnable as documented on
this host. Its Cython modules can be compiled after supplying several undocumented
dependencies and compatibility settings, but the bundled official example still
fails. The failures are source/build portability problems, not a long-running
experiment or insufficient hardware.

The final blocker is especially important: after working around the ARM signed-
`char` issue without changing source, the simulator loads all 76,802 ASes and
495,579 links, then crashes at the first propagation batch because
`ThreadPoolExecutor` cannot invoke the Cython `cdef` callback. Continuing would
require patching upstream code. In contrast, the separately verified
[BGPy evaluation](./bgpy.md) passed 22 official scenario tests and verified CAIDA
graph construction, multi-origin propagation, ROV, and deterministic replay.

## Project identity and ambiguity resolution

Several unrelated projects use the name “InternetSim.” The evaluated project is
`internetsys/InternetSim`, because:

1. its sole contributor is `jiahonglai`, matching the paper's first author;
2. it implements a C++/Cython, multi-threaded, AS-level BGP simulator with
   incremental policy changes and MongoDB offloading, matching the IMC paper; and
3. the repository organization and publication metadata are both associated with
   the Tsinghua Internet-systems group.

Repository state observed through the GitHub repository API on 2026-08-04:

- created 2025-04-27; last source push 2025-07-06;
- one commit on `master`, no tags, no releases, no CI, and no tests;
- 4 stars, 2 forks, no open issues, not archived;
- MIT license (`LICENSE`, copyright 2025 jiahonglai).

There is therefore no semantic release to pin. The commit hash above is the only
public source version.

## Local layout

- Upstream clone: `experiments/routing_model/vendor/internetsim`
- Python environment: `experiments/routing_model/.venv-internetsim`
- Local native dependencies: `experiments/routing_model/.deps-internetsim`
- This report: `experiments/routing_model/evaluation/internetsim.md`

The native dependency prefix contains MongoDB C++ Driver 4.4.1 and its
auto-selected MongoDB C Driver 2.3.3. It was installed locally, not system-wide.
The Python environment currently contains Cython 0.29.37, setuptools 83.0.0,
PyMongo 4.17.0, and dnspython 2.8.0. Cython 3.2.9 was also tested before the
compatibility check; both Cython branches exhibited the same negative-`char`
runtime failure.

## Build and run record

### Clone

```console
$ git clone https://github.com/internetsys/InternetSim.git \
    experiments/routing_model/vendor/internetsim
ELAPSED=1.87 s  MAXRSS=16,128 KiB  EXIT=0

$ git -C experiments/routing_model/vendor/internetsim rev-parse HEAD
a96b15716f579658b9d745c8abe1805dd869e375
```

### Documented prerequisites are incomplete

The README lists only a C++17 compiler, MongoDB, MongoDB C++ Driver, and Cython.
The source additionally requires:

- `pymongo`, imported unconditionally by `cython/Scheduler.pyx`;
- `setuptools` on Python 3.12 because `setup.py` imports removed stdlib
  `distutils`;
- compatible MongoDB C/C++ headers and unversioned library names; and
- architecture/compiler behavior in which ordinary C `char` can represent `-1`,
  or the external compile option `-fsigned-char`.

No requirements file, lockfile, supported Python matrix, compiler matrix,
container, or driver version is supplied.

### Native dependency build

MongoDB C++ Driver 4.4.1 was built into the local prefix. Its first configuration
failed because the auto-downloaded C driver enabled MONGODB-AWS without finding a
crypto library. Reconfiguration with unused AWS authentication disabled succeeded.

```text
MongoDB C++ configure: 2.24 s, exit 0
MongoDB C/C++ build:   81.98 s, peak 663,404 KiB, exit 0
MongoDB install:        5.78 s, exit 0
Installed prefix size: 12 MiB
```

Current Driver 4.4.1 installs `libmongocxx1`/`libbsoncxx1`, whereas InternetSim's
`setup.py` links `-lmongocxx -lbsoncxx`. Local compatibility symlinks were needed;
the upstream build file was not edited.

### InternetSim compilation

The exact README command initially failed immediately on Python 3.12:

```console
$ python3 setup.py build_ext --inplace
ModuleNotFoundError: No module named 'distutils'
```

After adding the missing Python packages and local include/library paths, all eight
Cython extensions compiled:

```text
Cython 3.2.9 build: 158.93 s, peak 798,892 KiB, exit 0
Cython 0.29.37 build: 157.38 s, peak 787,096 KiB, exit 0
```

Both builds warned that a `case -1` label lies outside the range of C `char` on
this aarch64 compiler. Thus the correct status is **conditional build success**,
not an out-of-the-box successful installation.

### Official example: failed

The default `config.ini` selects `description/description_1.txt`, which announces
eight prefixes, runs a simulation, displays two routes, changes one import policy,
and repeats the route queries.

With an otherwise successful Cython build, it fails on the first relationship in
the bundled CAIDA-derived topology:

```text
RuntimeError: Error parsing ASRelFile at line 1: 174|222222|-1
(can't convert negative value to char)
```

This happens because `Topology.addAS(..., char relationship)` receives CAIDA's
`-1` provider/customer marker and aarch64 GCC uses unsigned ordinary `char` by
default. Cython 3.2.9 and 0.29.37 both fail identically. An amd64 Docker validation
was attempted, but this host has no amd64 emulation (`exec format error`).

To isolate the next failure without editing source, a clean temporary checkout was
compiled with `CFLAGS=CXXFLAGS=-fsigned-char`:

```text
signed-char compile: 89.30 s, peak 495,232 KiB, exit 0
Loaded 76802 ASes, 495579 links
Simulation start
TypeError: wrap() takes exactly one argument (0 given)
signed-char run: 6.56 s, peak 143,516 KiB, exit 1
```

The second crash originates at `executor.submit(processor.process)` in
`Scheduler.pyx`; `Processor.process` is declared as a Cython `cdef` method and is
not a valid zero-argument Python callback in this build. Fixing it requires a
source change such as exposing a Python-callable wrapper or redesigning the worker
dispatch. No official example or test completed successfully.

## Capability assessment

| S2-ROV requirement | InternetSim assessment | Evidence and limitation |
|---|---|---|
| Internet-scale AS topology | **Strong design, load verified** | Bundles a 2024-05-01 relationship snapshot; 76,802 ASes and 495,579 links loaded after the signed-char compatibility build. README gives no CAIDA provenance URL, license note, or checksum. |
| Gao--Rexford routing | **Native** | Default local preferences are customer 100, peer 80, provider 60; export suppresses peer/provider-learned routes toward peers/providers; selection then uses shortest AS path, origin type, and lower first-hop ASN. |
| Multi-origin / dual-source attack | **Representable** | Multiple ASes may announce the same prefix. Bundled `description_2.txt` originates one prefix at AS52866 and then AS8309. There is no attacker/victim scenario abstraction or outcome analyzer. |
| Conventional ROV | **Present but semantically weak** | A per-AS ROV set filters an exact `(origin ASN, prefix)` pair found in an externally supplied `Invalid-Set`. It does not compute RFC-style Valid/Invalid/NotFound from ROAs, prefix coverage, or `maxLength`. |
| Partial deployment | **Representable** | ROV ASes can be loaded from a set and enabled incrementally. There is no deployment sampler, strategy implementation, repeated-trial harness, or confidence-interval output. |
| Custom routing policy | **Rich DSL** | Per-neighbor import/export filters can match exact/covered prefix, AS path, AS-SET, and community, with accept/deny/local-pref/community/prepend actions. Runtime policy changes trigger incremental refresh. |
| S2-ROV custom state | **Requires invasive extension** | `Extension.ROV` returns only Boolean acceptance. Implementing Explicit/Delegated/NotFound/Invalid and state-aware route ranking requires edits to Cython/C++ announcement and selection code, plus rebuilds of multiple extensions. |
| Aggregate/subprefix behavior | **Routing data structure supports prefixes** | The trie stores CIDR prefixes, but the public artifact has no built-in S2-ROV aggregate-fallback or four-state analyzer. These would need project code and ground-truth tests. |
| Structured metrics | **Weak** | Primary interface prints selected routes. No standard per-AS CSV/JSON campaign output, reachability metric, exposure metric, or uncertainty calculation is supplied. |
| Reproducibility | **Poor public artifact** | One commit, no release/tag, no tests/CI, no dependency pins, no supported platform declaration, no example oracle, and two independent runtime portability failures. Multithread scheduling is not covered by determinism tests. |
| Maintenance | **Low confidence** | Last source push was about 13 months before this evaluation; no later commits or release maintenance are visible. |

## Relative decision: InternetSim versus BGPy

| Criterion | InternetSim | BGPy 13.0.10 |
|---|---|---|
| Installation on this host | Conditional compile; runtime fails | Installed; official scenario tests pass |
| Security simulation model | Boolean exact-pair invalid filter | Native ROV/ROA semantics and security scenarios |
| Partial deployment | Manual ROV set only | Explicit per-AS policy classes and adopting-AS sets |
| Multi-origin experiments | DSL can express them; no analyzer | Verified exact-prefix and subprefix scenarios plus analyzers |
| S2-ROV extension surface | Cython/C++ changes across core types | Project-owned Python policy/analyzer outside vendor tree |
| Global graph | Bundled snapshot | Native CAIDA collector; graph construction verified |
| Incremental routing updates | Architectural strength | Primarily steady-state/round-based |
| Artifact maturity | One untested commit | PyPI release, documentation, tests, scenario framework |

InternetSim's potential advantages are high-throughput full-table simulation,
multi-threading, disk offload, and rapid incremental recomputation after policy
changes. Those strengths may matter for future convergence or very large
full-table studies, but they do not compensate for the current artifact's runtime
failures and the effort needed to add S2-ROV semantics and measurements.

For the paper's immediate paired reachability/exposure study, **BGPy is the lower-
risk and more scientifically defensible choice**. Keep InternetSim vendored only as
a documented secondary candidate; do not base paper claims on it unless upstream
fixes are obtained or a separately reviewed fork is created and validated against
ground-truth topologies.

## Experiment result summary

- **Type:** simulator acquisition and official-example reproduction
- **Status:** build completed with compatibility environment; official example crashed
- **Successful outputs:** pinned clone, isolated environment, eight compiled modules, full topology load under external `-fsigned-char`
- **Failed output:** no completed route-propagation result from an official example
- **Timeouts:** none; failures occurred in under seven seconds after startup
- **Primary anomalies:** missing dependency declarations, current-driver link-name mismatch, ARM signed-`char` overflow, non-callable Cython thread callback
