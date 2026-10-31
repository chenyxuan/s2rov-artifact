from __future__ import annotations

import importlib.util
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "build_fig_deployment_outcomes.py"
if str(SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("build_fig_deployment_outcomes", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
FIGURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIGURE)


def _order_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for panel, estimand, announcement, attacker in (
        ("a", "Delta_R", "intended_only", "none"),
        (
            "b",
            "Delta_E_rov",
            "competition_uniform_unlisted_origin",
            "uniform",
        ),
    ):
        for order_index, order in enumerate(FIGURE.RANDOM_ORDERS):
            for percent in FIGURE.DEPLOYMENT_PERCENTS:
                rows.append(
                    {
                        "panel": panel,
                        "announcement_set": announcement,
                        "estimand": estimand,
                        "metric_level": "destination",
                        "population": "all_AS_destinations",
                        "attacker_class": attacker,
                        "deployment_order": order,
                        "deployment_percent": percent,
                        "deployment_as_count": FIGURE.DEPLOYMENT_COUNTS[percent],
                        "estimate_pp": (
                            percent / 10
                            if percent in {0, 100}
                            else percent / 10 + order_index / 100
                        ),
                        "n_selected_units": 200,
                        "independent_unit": "holder/root-origin unit",
                        "point_estimate_source": "test",
                    }
                )
    return rows


def test_regular_grid_and_floor_counts_are_fixed() -> None:
    assert FIGURE.DEPLOYMENT_PERCENTS == list(range(0, 101, 10))
    assert FIGURE.DEPLOYMENT_COUNTS == {
        percent: int(589 * percent / 100)
        for percent in FIGURE.DEPLOYMENT_PERCENTS
    }
    assert len(FIGURE.RANDOM_ORDERS) == 5


def test_pending_extension_hash_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(FIGURE, "REPO", tmp_path)
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"complete")
    with pytest.raises(ValueError, match="expected SHA-256 is not populated"):
        FIGURE.verify_hashes(
            {artifact: FIGURE._PENDING_EXTENSION_HASH}, input_group="test extension"
        )


def test_tidy_order_csv_requires_exact_110_cells(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    order_csv = tmp_path / "orders.csv"
    monkeypatch.setattr(FIGURE, "ORDER_SOURCE_CSV", order_csv)
    rows = _order_rows()
    FIGURE.write_csv(order_csv, rows, fields=FIGURE.ORDER_SOURCE_FIELDS)
    panels = FIGURE.load_and_validate_order_source_csv()
    assert len(panels["a"]) == 55
    assert len(panels["b"]) == 55

    FIGURE.write_csv(order_csv, rows[:-1], fields=FIGURE.ORDER_SOURCE_FIELDS)
    with pytest.raises(ValueError, match="exactly 110"):
        FIGURE.load_and_validate_order_source_csv()


def test_tidy_order_csv_requires_shared_path_endpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    order_csv = tmp_path / "orders.csv"
    monkeypatch.setattr(FIGURE, "ORDER_SOURCE_CSV", order_csv)
    rows = _order_rows()
    endpoint = next(
        row
        for row in rows
        if row["panel"] == "b"
        and row["deployment_order"] == "random_05"
        and row["deployment_percent"] == 100
    )
    endpoint["estimate_pp"] = float(endpoint["estimate_pp"]) + 0.01
    FIGURE.write_csv(order_csv, rows, fields=FIGURE.ORDER_SOURCE_FIELDS)
    with pytest.raises(ValueError, match="shared 100% endpoint differs"):
        FIGURE.load_and_validate_order_source_csv()


def test_active_panels_omit_redundant_overlays() -> None:
    forbidden = (
        "Five fixed-order paths",
        "Five-order mean",
        "baseline",
        "95% interval",
        "Mean",
        "change (%)",
        "17.1%",
        "8.9%",
        "[4.5, 13.4]",
        "OpenScope",
        "Exact ROA",
        "Exact ROV",
        "Upgraded share within fixed 589-AS set",
        "589-AS",
    )
    for panel in ("a", "b"):
        svg = FIGURE.OUTPUTS[f"{panel}_svg"].read_text(encoding="utf-8")
        assert all(label not in svg for label in forbidden)
        assert "S²-ROV" in svg
        assert "S²-ROV upgraded share (%)" in svg
        assert "Aggregate-only ROV" in svg
        assert "Exact-match ROV" in svg


def test_active_panel_tick_labels_are_integer_text() -> None:
    expected = {
        "a": {"0", "20", "40", "60", "80", "85", "90", "95", "100"},
        "b": {"0", "10", "20", "30", "40", "50", "60", "80", "100"},
    }
    for panel in ("a", "b"):
        root = ET.parse(FIGURE.OUTPUTS[f"{panel}_svg"]).getroot()
        text_nodes = [
            "".join(element.itertext())
            for element in root.iter()
            if element.tag.endswith("text")
        ]
        numeric_labels = {
            label for label in text_nodes if re.fullmatch(r"-?\d+(?:\.\d+)?%?", label)
        }
        assert numeric_labels == expected[panel]
        assert all(re.fullmatch(r"-?\d+", label) for label in numeric_labels)


def test_absolute_outcome_anchors() -> None:
    _, panels = FIGURE.load_and_validate_source_csv()
    a50 = next(row for row in panels["a"] if int(row["deployment_percent"]) == 50)
    b50 = next(row for row in panels["b"] if int(row["deployment_percent"]) == 50)
    assert float(a50["reference_delivery_pct"]) == pytest.approx(82.1382036395829)
    assert float(a50["treatment_delivery_pct"]) == pytest.approx(93.54209086260795)
    assert float(panels["reference_a"]["treatment_delivery_pct"]) == pytest.approx(
        99.23127330189004
    )
    assert float(b50["reference_delivery_pct"]) == pytest.approx(32.35482713550432)
    assert float(b50["treatment_delivery_pct"]) == pytest.approx(40.34973596370132)
    assert float(panels["reference_b"]["treatment_delivery_pct"]) == pytest.approx(
        11.656181128842953
    )


def test_competition_exact_reference_uses_announcement_matched_contrast() -> None:
    _, panels = FIGURE.load_and_validate_source_csv()
    reference = panels["reference_b"]
    assert float(reference["treatment_delivery_pct"]) == pytest.approx(
        11.656181128842953
    )
    assert float(reference["reference_delivery_pct"]) == pytest.approx(
        32.35482713550432
    )
    assert float(reference["estimate_pp"]) == pytest.approx(-20.69864600666137)
    assert float(reference["interval95_low_pp"]) == pytest.approx(
        -23.60618713873701
    )
    assert float(reference["interval95_high_pp"]) == pytest.approx(
        -17.924187617173543
    )
