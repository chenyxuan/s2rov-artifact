# Secondary Analysis Plan: NDSS 2026 Invalid-Route Corpus

**Status:** re-audited
**Purpose:** descriptive context and pipeline validation

## 1. Scope and Attribution

The input CSVs and cause-evidence columns are from the artifact accompanying
Li, Wan, and Chung (NDSS 2026).  This phase does not relabel their collection
as a new S2-ROV dataset.  It summarizes the supplied occurrence rows and tests
how much of the corpus carries relationship-oriented evidence.

Allowed claims:

- counts and shares under a documented deterministic rule;
- temporal stability of those **corpus labels**;
- overlap among label columns.

Disallowed claims without additional evidence:

- every labeled route is legitimate;
- a label is a signed origin authorization;
- a labeled Invalid route is necessarily a false positive;
- the source paper's empirical contribution is ours; or
- the corpus represents all global Invalid routes.

## 2. Input Contract

Required columns:

`prefix, bgp_origin, roa_origin, org, customer, maxlength, org_transit,
direct_leasing, hidden_transit, broker_leasing`

The date is parsed from each `YYYYMMDD.csv` filename.  Source evidence columns
may contain counts, so preprocessing converts numeric values with `value > 0`
to label-present.  Missing columns or nonnumeric evidence values are errors;
files are not skipped silently.

## 3. Descriptive Reporting

Rows can carry multiple labels.  Report both:

1. non-exclusive prevalence for each source column; and
2. one mutually exclusive composition using priority
   `transit > leasing > customer > MaxLength-only > other`.

The priority is only a double-counting convention.  All narrative and figure
labels must say “relationship-labeled,” “transit-labeled,” and so on, rather
than “legitimate,” “genuine hijack,” “semantic false positive,” or
“uncorrectable.”

## 4. Tasks

1. Validate the file count, date range, schema, row count, missingness, and
   observed values.
2. Normalize evidence columns and save a processed table.
3. Produce non-exclusive label prevalence.
4. Produce mutually exclusive occurrence composition.
5. Plot monthly occurrence composition and relationship-labeled share.
6. Report unique prefixes and origin ASNs only as corpus descriptors.

## 5. Outputs

- `outputs/tables/data_processed.parquet` or `data_processed.csv.gz`
- `outputs/tables/classification_summary.csv`
- `outputs/tables/flag_prevalence.csv`
- figures under `outputs/figures/`
- `RESULTS.md` with explicit provenance and claim boundaries

## 6. Relationship to the Paper

This phase supports related-work context.  The paper's independent empirical
evidence comes from the allocation-tree counterfactual, which does not import
these source labels.  No figure or percentage from this phase should be added
to the manuscript unless its secondary provenance and non-authorization
interpretation are explicit.
