"""candidate-selection: Data Loader — Load and preprocess ROA misconfiguration data."""
import pandas as pd
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data/roa-misconfiguration-data/datas"
OUTPUT_DIR = HERE_DIR / "outputs/tables"

COLUMNS = [
    "prefix", "bgp_origin", "roa_origin", "org", "customer",
    "maxlength", "org_transit", "direct_leasing",
    "hidden_transit", "broker_leasing"
]

RELATIONSHIP_FLAGS = [
    "org", "customer", "maxlength", "org_transit",
    "direct_leasing", "hidden_transit", "broker_leasing"
]


def load_all_data(data_dir: Path = DATA_DIR) -> pd.DataFrame:
    """Load all daily CSV files and concatenate into a single DataFrame.

    Returns:
        DataFrame with all data + a 'date' column parsed from filename.
    """
    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    frames = []
    for f in csv_files:
        date_str = f.stem  # e.g., "20230101"
        date = pd.to_datetime(date_str, format="%Y%m%d")
        df = pd.read_csv(f)
        missing = set(COLUMNS) - set(df.columns)
        if missing:
            raise ValueError(f"{f.name}: missing required columns {sorted(missing)}")
        df = df[COLUMNS].copy()
        df["date"] = date
        frames.append(df)

    data = pd.concat(frames, ignore_index=True)
    print(f"Loaded {len(data):,} rows from {len(frames)} files "
          f"({data['date'].min().date()} to {data['date'].max().date()})")
    return data


def preprocess(data: pd.DataFrame) -> pd.DataFrame:
    """Clean and preprocess the data."""
    missing = set(COLUMNS + ["date"]) - set(data.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    # Several corpus columns contain positive integer evidence counts rather
    # than only {0,1}.  Treat strictly positive values as a present label.
    for col in RELATIONSHIP_FLAGS:
        numeric = pd.to_numeric(data[col], errors="coerce")
        invalid = numeric.isna() & data[col].notna()
        if invalid.any():
            examples = data.loc[invalid, col].astype(str).head(5).tolist()
            raise ValueError(f"{col}: non-numeric values {examples}")
        data[col] = numeric.fillna(0).gt(0)

    # Add derived columns
    data["year_month"] = data["date"].dt.to_period("M")

    # Count how many relationship flags are set per row
    data["n_relationships"] = data[RELATIONSHIP_FLAGS].sum(axis=1)

    # No relationship at all → potential hijack
    data["no_relationship"] = data["n_relationships"] == 0

    # Presence of a relationship/cause label is descriptive evidence from the
    # source corpus.  It is not authorization or legitimacy ground truth.
    data["has_relationship_label"] = (
        data[["customer", "direct_leasing", "org_transit",
               "hidden_transit", "broker_leasing"]].any(axis=1)
    )

    # Classification
    conditions = [
        # Relationship-labeled, different organization
        data["has_relationship_label"] & ~data["org"],
        # Same-org coordination failure
        data["org"] & ~data["has_relationship_label"],
        # MaxLength only
        data["maxlength"] & ~data["has_relationship_label"] & ~data["org"],
        # Everything else
        data["no_relationship"]
    ]
    choices = [
        "relationship_labeled",
        "same_org",
        "maxlength_only",
        "unknown"
    ]
    data["classification"] = "unknown"
    for cond, choice in zip(conditions, choices):
        data.loc[cond, "classification"] = choice

    return data


def classification_summary(data: pd.DataFrame) -> pd.DataFrame:
    """Generate summary statistics of the classification."""
    return data["classification"].value_counts().to_frame("count").assign(
        pct=lambda df: (df["count"] / df["count"].sum() * 100).round(2)
    )


if __name__ == "__main__":
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading data...")
    data = load_all_data()

    print("Preprocessing...")
    data = preprocess(data)

    # Save preprocessed data. Prefer parquet, but keep a CSV fallback so the
    # pipeline remains reproducible when pyarrow/fastparquet is unavailable.
    parquet_path = OUTPUT_DIR / "data_processed.parquet"
    csv_path = OUTPUT_DIR / "data_processed.csv.gz"
    try:
        data.to_parquet(parquet_path, index=False)
        print(f"Saved {len(data):,} rows to {parquet_path}")
    except ImportError as e:
        print(f"Parquet unavailable ({e}); writing CSV fallback", file=sys.stderr)
        data.to_csv(csv_path, index=False)
        print(f"Saved {len(data):,} rows to {csv_path}")

    # Print classification summary
    print("\n=== Classification Summary ===")
    print(classification_summary(data).to_string())

    # Print relationship breakdown
    print("\n=== Relationship Flag Prevalence ===")
    for col in RELATIONSHIP_FLAGS:
        pct = data[col].mean() * 100
        print(f"  {col:20s}: {pct:6.2f}%")
