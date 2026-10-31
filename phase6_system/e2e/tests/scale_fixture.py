import csv
import json
from pathlib import Path


LEVELS = (0, 64, 256, 1024)
TRANSITIONS = ("remove", "restore")


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def build_scale_run(
    root: Path,
    *,
    address_family: str,
    route_checks_per_transition: int = 1,
) -> tuple[Path, str]:
    if address_family == "ipv4":
        target_prefix = "10.0.10.0/24"
    elif address_family == "ipv6":
        target_prefix = "2001:db8:10::/48"
    else:
        raise ValueError(f"unsupported address family: {address_family}")

    run_dir = root / f"scale-{address_family}-synthetic"
    run_dir.mkdir(parents=True)
    samples_path = run_dir / "policy-scale-samples.csv"
    with samples_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            (
                "background_stripes",
                "total_validated_entries",
                "trial",
                "transition",
                "milliseconds",
            )
        )
        for level in LEVELS:
            for trial in range(1, 11):
                for transition in TRANSITIONS:
                    transition_offset = 100 if transition == "restore" else 0
                    duration = 1000 + level + 10 * trial + transition_offset
                    writer.writerow((level, level + 2, trial, transition, duration))
                    enforcement = [
                        {
                            "name": f"target-{check}",
                            "prefix": target_prefix,
                            "pass": True,
                        }
                        for check in range(1, route_checks_per_transition + 1)
                    ]
                    write_json(
                        run_dir
                        / f"background-{level}"
                        / f"trial-{trial:02d}"
                        / transition
                        / "enforcement.json",
                        enforcement,
                    )

    with (run_dir / "policy-scale-payloads.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(
            (
                "background_stripes",
                "total_validated_entries",
                "json_bytes",
                "setup_ms",
            )
        )
        for level in LEVELS:
            writer.writerow((level, level + 2, 1000 + level, 25.0 + level))
    return run_dir, target_prefix


def corrupt_sample_matrix(samples_path: Path) -> None:
    with samples_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
        fieldnames = list(rows[0])

    omitted = next(
        row
        for row in rows
        if row["background_stripes"] == "0"
        and row["transition"] == "remove"
        and row["trial"] == "10"
    )
    rows.remove(omitted)
    duplicate = next(
        row
        for row in rows
        if row["background_stripes"] == "0"
        and row["transition"] == "restore"
        and row["trial"] == "1"
    )
    rows.append(dict(duplicate))

    with samples_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
