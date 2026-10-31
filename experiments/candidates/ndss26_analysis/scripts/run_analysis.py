"""candidate-selection: Full Analysis — Descriptive stats, classification, temporal, impact.
Self-contained script — runs all tasks and produces figures + tables."""
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[4]
HERE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = HERE_DIR / "outputs"
TABLE_DIR = OUTPUT_DIR / "tables"
FIG_DIR = OUTPUT_DIR / "figures"
for d in [TABLE_DIR, FIG_DIR]:
    d.mkdir(parents=True, exist_ok=True)

plt.style.use("seaborn-v0_8-whitegrid")
plt.rcParams.update({"font.size": 10.5})
C = ["#2166ac", "#d6604d", "#f4a582", "#92c5de", "#4393c3"]

REL_COLS = ["customer", "maxlength", "org_transit", "direct_leasing", "hidden_transit", "broker_leasing"]
FLAG_COLS = ["org", *REL_COLS]

# ─── Load ───
print("Loading...")
parquet_path = TABLE_DIR / "data_processed.parquet"
csv_path = TABLE_DIR / "data_processed.csv.gz"
if csv_path.exists():
    # The loader always emits this format, including in environments without
    # an optional Parquet engine.  Prefer it so an older Parquet cache cannot
    # silently shadow a freshly normalized corpus.
    data = pd.read_csv(csv_path, parse_dates=["date"])
elif parquet_path.exists():
    try:
        data = pd.read_parquet(parquet_path)
    except ImportError as exc:
        raise RuntimeError(
            "Only a Parquet cache is available, but no Parquet engine is installed; "
            "rerun 01_data_loader.py to create data_processed.csv.gz"
        ) from exc
else:
    raw_dir = ROOT / "data/roa-misconfiguration-data/datas"
    frames = []
    for f in sorted(raw_dir.glob("*.csv")):
        df = pd.read_csv(f)
        df["date"] = pd.to_datetime(f.stem, format="%Y%m%d")
        frames.append(df)
    if not frames:
        raise FileNotFoundError(f"No processed data or raw CSV files found under {raw_dir}")
    data = pd.concat(frames, ignore_index=True)

# Normalize evidence/count columns consistently whether the processed table or
# raw CSV fallback was used.  Positive counts mean the source label is present.
for col in FLAG_COLS:
    numeric = pd.to_numeric(data[col], errors="coerce")
    invalid = numeric.isna() & data[col].notna()
    if invalid.any():
        raise ValueError(f"{col}: non-numeric evidence values")
    data[col] = numeric.fillna(0).gt(0)
data["ym"] = data["date"].dt.to_period("M")

# ─── Task 1: Descriptive ───
print("\n=== T1: Descriptive ===")
daily = data.groupby("date").size()
monthly = data.groupby("ym").size()
print(f"Total rows: {len(data):,}  |  Unique prefixes: {data['prefix'].nunique():,}")
print(f"Unique bgp_origin: {data['bgp_origin'].nunique():,}  |  Unique roa_origin: {data['roa_origin'].nunique():,}")
print(f"Date range: {data['date'].min().date()} → {data['date'].max().date()}")

# Multi-relationship
data["n_rel"] = data[REL_COLS].sum(axis=1)
print("\nMulti-rel distribution:")
for k, v in data["n_rel"].value_counts().sort_index().items():
    print(f"  {k}: {v:,} ({v/len(data)*100:.1f}%)")

# Figure 1
fig, ax = plt.subplots(figsize=(10, 3.5))
ax.plot(daily.index, daily.values, color=C[0], lw=0.4, alpha=0.7)
ax.set_title("Figure 1: Daily RPKI-Invalid Route Count"); ax.set_ylabel("Count")
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
fig.tight_layout(); fig.savefig(FIG_DIR / "f1_daily_invalid.png", dpi=150); plt.close()

# Figure 2: Flag prevalence
prev = {c: data[c].mean()*100 for c in REL_COLS}
prev_sorted = sorted(prev.items(), key=lambda x: x[1], reverse=True)
pd.DataFrame(prev_sorted, columns=["flag", "prevalence_pct"]).to_csv(
    TABLE_DIR / "flag_prevalence.csv", index=False
)
fig, ax = plt.subplots(figsize=(8, 3.5))
ax.barh([p[0] for p in prev_sorted], [p[1] for p in prev_sorted], color=C[0])
ax.set_title("Figure 2: Relationship Flag Prevalence"); ax.set_xlabel("%")
ax.invert_yaxis()
for i, (_, v) in enumerate(prev_sorted):
    ax.text(v+0.3, i, f"{v:.1f}%", va="center", fontsize=9)
fig.tight_layout(); fig.savefig(FIG_DIR / "f2_flag_prev.png", dpi=150); plt.close()

# ─── Task 2-3: Classification ───
print("\n=== T2-3: Classification ===")

def classify(row):
    c = row["customer"]; l = row["direct_leasing"] or row["broker_leasing"]
    t = row["org_transit"] or row["hidden_transit"]; m = row["maxlength"]
    # Mutually exclusive reporting priority for overlapping source labels.
    if t:                       return "Transit-labeled"
    if l:                       return "IP-leasing-labeled"
    if c:                       return "Customer-labeled"
    if m:                       return "MaxLength-only"
    return "Other/unlabeled"

data["cls"] = data.apply(classify, axis=1)
cls = data["cls"].value_counts()
cls_df = cls.reset_index(); cls_df.columns = ["class", "count"]
cls_df["pct"] = (cls_df["count"] / cls_df["count"].sum() * 100).round(1)
print(cls_df.to_string(index=False))
cls_df.to_csv(TABLE_DIR / "classification_summary.csv", index=False)

# Figure 3: Bar chart
fig, ax = plt.subplots(figsize=(9, 4))
bars = ax.bar(range(len(cls_df)), cls_df["count"], color=[C[0], C[0], C[0], C[0], C[3], C[1]])
ax.set_xticks(range(len(cls_df)))
ax.set_xticklabels(cls_df["class"], fontsize=8)
ax.set_title("Figure 3: Mutually Exclusive Source-Label Classification")
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
for bar, pct in zip(bars, cls_df["pct"]):
    ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+10000, f"{pct}%", ha="center", fontweight="bold")
fig.tight_layout(); fig.savefig(FIG_DIR / "f3_classification.png", dpi=150); plt.close()

# Figure 4: Source-label composition.  These labels do not prove legitimacy,
# operator intent, or whether a route is operationally "correctable".
relationship_cls = {"Customer-labeled", "IP-leasing-labeled", "Transit-labeled"}
n_relationship = data[data["cls"].isin(relationship_cls)].shape[0]
n_ml = (data["cls"] == "MaxLength-only").sum()
n_other = (data["cls"] == "Other/unlabeled").sum()
composition = [
    ("Relationship-labeled", n_relationship, C[0]),
    ("MaxLength-only", n_ml, C[3]),
]
fig, ax = plt.subplots(figsize=(8.5, 2.8))
left = 0.0
for label, count, color in composition:
    share = count / len(data) * 100
    ax.barh([0], [share], left=left, color=color, height=0.48, label=label)
    ax.text(
        left + share / 2,
        0,
        f"{label}\n{count:,} ({share:.1f}%)",
        ha="center",
        va="center",
        color="white" if color == C[0] else "#222222",
        fontsize=10,
        fontweight="bold",
    )
    left += share
ax.set_xlim(0, 100)
ax.set_yticks([])
ax.set_xlabel("Share of source-corpus occurrences (%)")
ax.set_title("Figure 4: Source-Corpus Label Composition")
ax.text(
    1,
    -0.55,
    f"Other/unlabeled: {n_other:,} ({n_other/len(data)*100:.1f}%)",
    transform=ax.transAxes,
    ha="right",
    va="top",
    fontsize=9,
)
fig.tight_layout()
fig.savefig(FIG_DIR / "f4_label_composition.png", dpi=150, bbox_inches="tight")
plt.close()

# ─── Task 4: Temporal ───
print("\n=== T4: Temporal ===")
monthly_cls = data.groupby(["ym", "cls"]).size().unstack(fill_value=0)
monthly_cls.index = monthly_cls.index.astype(str)
labels = monthly_cls.index.tolist()

# Figure 5: Stacked area
fig, ax = plt.subplots(figsize=(11, 4.5))
plot_order = ["Customer-labeled", "IP-leasing-labeled", "Transit-labeled", "MaxLength-only", "Other/unlabeled"]
available = [c for c in plot_order if c in monthly_cls.columns]
df_plot = pd.DataFrame({c: monthly_cls[c] for c in available})
colors_stack = [C[0], C[1], C[2], C[3], C[4]][:len(available)]
df_plot.plot.area(ax=ax, color=colors_stack, alpha=0.85, lw=0)
ax.set_title("Figure 5: Monthly RPKI-Invalid Occurrences by Source Label")
ax.set_ylabel("Count")
n = len(labels); step = max(1, n//10)
ax.set_xticks(range(0, n, step))
ax.set_xticklabels([labels[i] for i in range(0, n, step)], rotation=45, ha="right", fontsize=7)
ax.legend(loc="upper left", fontsize=7, ncol=2)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
fig.tight_layout(); fig.savefig(FIG_DIR / "f5_monthly_stack.png", dpi=150); plt.close()

# Figure 6: Relationship-labeled share
monthly_relationship = monthly_cls[[c for c in relationship_cls if c in monthly_cls]].sum(axis=1)
monthly_total = monthly_cls.sum(axis=1)
monthly_relationship_pct = (monthly_relationship / monthly_total * 100)
fig, ax = plt.subplots(figsize=(10, 3.5))
ax.plot(range(len(monthly_relationship_pct)), monthly_relationship_pct.values, color=C[0], lw=2, marker="o", ms=3)
ax.axhline(monthly_relationship_pct.mean(), color="red", ls="--", label=f"Mean: {monthly_relationship_pct.mean():.1f}%")
ax.set_title("Figure 6: Relationship-Labeled Occurrence Share")
ax.set_ylabel("%"); ax.legend(); ax.set_ylim(0, 100)
n_l = len(labels); s = max(1, n_l//10)
ax.set_xticks(range(0, n_l, s)); ax.set_xticklabels([labels[i] for i in range(0, n_l, s)], rotation=45, ha="right", fontsize=7)
fig.tight_layout(); fig.savefig(FIG_DIR / "f6_relationship_trend.png", dpi=150); plt.close()
print(f"Relationship-labeled share: mean={monthly_relationship_pct.mean():.1f}%, range [{monthly_relationship_pct.min():.1f}%–{monthly_relationship_pct.max():.1f}%]")

# ─── Task 5: Impact ───
print("\n=== T5: Impact ===")
relationship_data = data[data["cls"].isin(relationship_cls)]
u_prefixes = relationship_data["prefix"].drop_duplicates()
print(f"Relationship-labeled: {len(relationship_data):,} occurrences")
print(f"  Unique prefixes: {u_prefixes.nunique():,}")
print(f"  Unique bgp_origins: {relationship_data['bgp_origin'].nunique():,}")
print(f"  Unique roa_origins: {relationship_data['roa_origin'].nunique():,}")

# Top ASes
top = relationship_data["bgp_origin"].value_counts().head(10)
print("\nTop 10 affected ASes (bgp_origin):")
for asn, cnt in top.items():
    print(f"  AS{asn}: {cnt:,}")

# Prefix length
relationship_u = relationship_data.drop_duplicates(["prefix", "bgp_origin"]).copy()
relationship_u["plen"] = relationship_u["prefix"].str.split("/").str[1].astype(int)
fig, ax = plt.subplots(figsize=(8, 3.5))
ax.hist(relationship_u["plen"], bins=range(8, 33), color=C[0], edgecolor="white")
ax.set_title("Figure 7: Prefix Length Distribution (Relationship-Labeled)"); ax.set_xlabel("/N")
fig.tight_layout(); fig.savefig(FIG_DIR / "f7_prefix_len.png", dpi=150); plt.close()

# ─── Task 6: MaxLength ───
print("\n=== T6: MaxLength ===")
relationship_ml = relationship_data["maxlength"].sum()
print(f"Relationship-labeled + maxLength: {relationship_ml:,} ({relationship_ml/len(relationship_data)*100:.1f}%)")
ml_cats = {
    "Customer+ML": len(data[data["customer"] & data["maxlength"]]),
    "Leasing+ML": len(data[(data["direct_leasing"]|data["broker_leasing"]) & data["maxlength"]]),
    "Transit+ML": len(data[(data["org_transit"]|data["hidden_transit"]) & data["maxlength"]]),
    "Pure ML": (data["cls"]=="MaxLength-only").sum(),
}
fig, ax = plt.subplots(figsize=(6, 5))
ax.pie(list(ml_cats.values()), labels=[f"{k}\n({v:,})" for k,v in ml_cats.items()],
       colors=[C[0], C[1], C[2], C[3]], startangle=90, textprops={"fontsize":9})
ax.set_title("Figure 8: MaxLength Overlap")
fig.tight_layout(); fig.savefig(FIG_DIR / "f8_ml_overlap.png", dpi=150); plt.close()

# ─── FINAL ───
print("\n" + "="*50)
print("candidate-selection COMPLETE")
print(f"Relationship-labeled: {n_relationship:,} ({n_relationship/len(data)*100:.1f}%)")
print(f"MaxLength-only: {n_ml:,} ({n_ml/len(data)*100:.1f}%)")
print(f"Other:          {n_other:,} ({n_other/len(data)*100:.1f}%)")
print(f"Outputs → {OUTPUT_DIR}")
