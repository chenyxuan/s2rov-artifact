# Phase 6: DA-ROV System Prototype

**Date:** 2026-07-29
**Status:** Conventional Krill–Routinator–RTR–FRR baseline and DA-aware
local-API enforcement complete
**Dependency:** Phases 1-5 (completed)

---

## 1. Overview

This phase contains an RPKI testbed that previously reproduced the RFC 6811
semantic conflict through Krill publication and Routinator validation. Unlike
the analytical evaluation in Phase 5, it targets operational feasibility.
The deterministic experiment in `e2e/` now demonstrates stock RTR-to-FRR
validation and DA-aware enforcement against live FRR BGP routes.

### 1.1 Architecture

```
┌──────────────────────────────────────────────────┐
│  testbed container (Krill CA)                    │
│  → Sign and publish ROA objects                  │
│  → krillc roas update for ROA lifecycle mgmt     │
├──────────────────────────────────────────────────┤
│  routinator container (RPKI Validator)            │
│  → Fetch TALs, sync ROAs from repository         │
│  → Serve VRPs via RPKI-RTR                       │
├──────────────────────────────────────────────────┤
│  FRR 10.6.1 collector + seven BGP speakers       │
│  → stock RFC 6811 RTR validation                 │
│  → DA-aware local API and route-map enforcement  │
└──────────────────────────────────────────────────┘
```

### 1.2 Components

| Component | File | Description |
|-----------|------|-------------|
| Launch script | `launch.md` | Docker setup for Krill testbed + Routinator |
| ROA management | `krillc-roas-update-guide.md` | Complete reference for `krillc roas update` — how to add/remove ROAs via CLI or delta files |
| Routinator deployment | `dockerfiles/stripe-roa-system.zip` | Routinator package with TALs, config, and docs |
| Reproducible E2E testbed | `e2e/` | Krill, Routinator, RTR, FRR, DA evaluation, assertions, and raw results |

---

## 2. Files

```
phase6_system/
├── SYSTEM.md                      ← This file
├── launch.md                      ← Docker launch instructions
├── krillc-roas-update-guide.md    ← krillc ROA management manual
└── dockerfiles/
    └── stripe-roa-system.zip      ← Routinator deployment package
```

---

## 3. Tasks

| Task | Description | Status |
|------|-------------|:------:|
| **T1** | Testbed deployment: Krill + Routinator in Docker | ✅ |
| **T2** | ROA issuance: generate and publish ROA via krillc | ✅ |
| **T3** | RPKI validation: Routinator fetches ROA, validates routes | ✅ |
| **T4** | Semantic conflict reproduction: customer delegation → Invalid | ✅ |
| **T5** | Stock RTR/router integration: connect Routinator to FRR | ✅ |
| **T6** | DA-aware local-API enforcement on live FRR routes | ✅ |

### 3.1 Current audit

The audit of the old, long-running containers found stale manifests and no FRR.
The new `e2e/` experiment avoids that state by creating a fresh Krill data
volume, waiting for a valid RRDP publication, and recording machine-readable
evidence at every stage. It does not modify or depend on the old containers.

The passing 2026-07-29 run is under `e2e/outputs/latest/`.

---

## 4. Relationship to Research Phases

```
Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4 ──→ Phase 5
  │           │           │           │           │
  Empirical   Formal      DA-ROV      DA-ROA      Evaluation
  evidence    proof       semantics   encoding    (synthetic)
                                                     │
Phase 6 ←─────────────────────────────────────────────┘
  System prototype: real RPKI conflict reproduction
```

---

## 5. End-to-End Validation Results (2026-07-06)

### 5.1 Environment

| Component | Version | Notes |
|-----------|---------|-------|
| Krill | 0.14.4 (custom build) | ARM64, Krill CA + TA |
| Routinator | 0.13.2 (custom build) | ARM64, RRDP-only |
| Base images | rust:bookworm, rust:1.88-bullseye | via DaoCloud mirror |
| krillc | 0.14.4 | CLI for ROA management |

### 5.2 Validation Results

| Route | Result | Meaning |
|-------|:------:|---------|
| `10.0.0.0/16 → AS64501` | **valid** | Legitimate route from ROA holder |
| `10.0.0.0/16 → AS64502` | **invalid** | Hijack detected |
| `192.168.0.0/24 → AS64501` | **not-found** | Prefix not covered by any ROA |
| `10.0.1.0/24 → AS64502` | **invalid** | ⚠️ **Semantic conflict**: legitimate customer delegation marked Invalid under RFC 6811 |

### 5.3 Semantic Conflict Reproduced

The last test case (`10.0.1.0/24 → AS64502`) reproduces the exact scenario DA-ROV is designed to fix:

1. AS64501 holds `10.0.0.0/16` and issues ROA `{10.0.0.0/16, AS64501}`
2. AS64502 is a legitimate customer delegated `10.0.1.0/24`
3. Under RFC 6811 ROV: origin mismatch → **Invalid**
4. Both parties performed non-offensive operations — the conflict is purely semantic

### 5.4 Build & Configuration Notes

Key fixes applied to the source-derived Docker images:

| Fix | Description |
|-----|-------------|
| `rrdp-root-certs` | Created `/etc/pki/CA/root.pem` from `root.crt` |
| `extra-tals-dir` | Enabled in `/root/.routinator.conf` |
| Server cert SAN | Generated server cert with `DNS:testbed` + `IP:172.17.0.2` |
| rsync cert path | Copied TA cert to `<home>/data/rsync_cer/ta.cer` |
| nginx HTTPS:443 | Proxy to Krill HTTPS:3000 with self-signed SAN cert |
| Routinator `--no-ui` | Skipped `routinator-ui` optional dependency to avoid GitHub fetch |

### 5.5 VRP Propagation

```
ROA in Krill:  krillc roas update --add "10.0.0.0/16 => 64501"
       ↓ RRDP (notification.xml → snapshot.xml)
VRP in Routinator:  AS64501, 10.0.0.0/16, 16, 16, ta
       ↓ RPKI-RTR (port 3323)
BGP Router → ROV decision
```

---

## 6. krillc Quick Reference

```bash
# View current ROAs
krillc roas list -c my_ca

# Add a self-protective ROA
krillc roas update -c my_ca --add "10.0.0.0/16 => 64501"

# Add customer authorization
krillc roas update -c my_ca --add "10.0.1.0/24 => 64502"

# Add with maxLength (allows sub-prefixes up to /24)
krillc roas update -c my_ca --add "10.0.0.0/16-24 => 64501"

# Dry-run (preview impact)
krillc roas update -c my_ca --add "10.0.0.0/16 => 64501" --dryrun

# Batch update via delta file
krillc roas update -c my_ca --delta /path/to/delta.txt
```
