# Experiment Table Necessity Audit

Date: 2026-08-30

| Candidate table | Decision | Reason |
|---|---|---|
| RIPE allocation paths and origin divergence | Keep | A table is the most compact representation of the IPv4/IPv6 depth subsets |
| Semantic correctness counts | Omit from main text | The checks are a prerequisite and fit in one setup paragraph |
| Partial-policy deployment | Use Fig. 2 | Six OpenScope placement levels directly show how remaining candidate conflicts change across matching-ROA issuance rates |
| Handoff latency | Keep in Section V-B prose | The rounded workflow means and paired contrast fit in one compact paragraph |
| Selected-policy replay | Use Fig. 3 | Two grouped-bar panels make the IPv4/IPv6 loading and classification comparison visible across the three policy sizes |
| Deployment outcomes | Use Fig. 4 | Deployment response and uncertainty bands are the key relationships |
| Live scale and outage controls | Keep in prose | The controls support a bounded robustness statement and do not need another table |

The resulting Evaluation uses three figures and no result table. Table I
remains the compact motivation table in Section II. The manuscript does not
duplicate the same numeric comparison in both a table and a figure.
