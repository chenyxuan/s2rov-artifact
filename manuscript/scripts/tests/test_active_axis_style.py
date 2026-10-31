from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path
import re
import sys
import unittest

import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib import font_manager


SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load_module(stem: str):
    path = SCRIPTS / f"{stem}.py"
    name = f"axis_style_{stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PARTIAL_POLICY = _load_module("run_partial_policy_replay")
PROCESSING_COST = _load_module("build_processing_cost_figure")
DEPLOYMENT_OUTCOMES = _load_module("build_fig_deployment_outcomes")

ACTIVE_MODULES = (
    PARTIAL_POLICY,
    PROCESSING_COST,
    DEPLOYMENT_OUTCOMES,
)
ACTIVE_PLOTTERS = (
    (
        PARTIAL_POLICY,
        (
            "draw_family_figure",
            "draw_strategy_figure",
            "draw_deployment_conflict_panel",
            "draw_openscope_placement",
        ),
    ),
    (PROCESSING_COST, ("make_update_latency_figure", "draw_panel")),
    (DEPLOYMENT_OUTCOMES, ("draw_figure",)),
)


class ActiveAxisStyleTests(unittest.TestCase):
    def tearDown(self) -> None:
        plt.close("all")

    def test_configure_style_uses_bottom_left_ticks_and_closed_axes(self) -> None:
        for module in ACTIVE_MODULES:
            with self.subTest(module=module.__name__), mpl.rc_context():
                mpl.rcdefaults()
                module.configure_style()

                self.assertEqual(mpl.rcParams["font.family"], ["serif"])
                self.assertEqual(
                    mpl.rcParams["font.serif"], [module.BODY_FONT_FAMILY]
                )
                resolved = font_manager.findfont(
                    module.BODY_FONT_FAMILY,
                    fallback_to_default=False,
                )
                self.assertIn("NimbusRoman-", Path(resolved).name)

                self.assertEqual(mpl.rcParams["xtick.direction"], "in")
                self.assertEqual(mpl.rcParams["ytick.direction"], "in")
                self.assertFalse(mpl.rcParams["xtick.top"])
                self.assertFalse(mpl.rcParams["ytick.right"])

                figure, axis = plt.subplots()
                axis.minorticks_on()
                figure.canvas.draw()
                self.assertTrue(
                    all(
                        axis.spines[side].get_visible()
                        for side in ("left", "right", "bottom", "top")
                    )
                )
                for tick in (
                    axis.xaxis.get_major_ticks()
                    + axis.xaxis.get_minor_ticks()
                ):
                    self.assertTrue(tick.tick1line.get_visible())
                    self.assertFalse(tick.tick2line.get_visible())
                for tick in (
                    axis.yaxis.get_major_ticks()
                    + axis.yaxis.get_minor_ticks()
                ):
                    self.assertTrue(tick.tick1line.get_visible())
                    self.assertFalse(tick.tick2line.get_visible())
                plt.close(figure)

    def test_active_coordinate_panels_share_geometry_and_type_scale(self) -> None:
        expected_size = (3.50, 1.75)
        expected_margins = {
            "left": 0.145,
            "right": 0.94,
            "bottom": 0.27,
            "top": 0.89,
        }
        for module in ACTIVE_MODULES:
            with self.subTest(module=module.__name__), mpl.rc_context():
                self.assertEqual(module.ACTIVE_PANEL_FIGSIZE, expected_size)
                self.assertEqual(module.ACTIVE_PANEL_MARGINS, expected_margins)
                self.assertEqual(module.ACTIVE_BASE_FONTSIZE, 8.4)
                self.assertEqual(module.ACTIVE_TICK_LABELSIZE, 7.56)
                self.assertEqual(module.ACTIVE_AXIS_LABELSIZE, 8.4)
                self.assertEqual(module.ACTIVE_LEGEND_FONTSIZE, 6.96)

                mpl.rcdefaults()
                module.configure_style()
                self.assertEqual(mpl.rcParams["font.size"], 8.4)
                self.assertEqual(mpl.rcParams["xtick.labelsize"], 7.56)
                self.assertEqual(mpl.rcParams["ytick.labelsize"], 7.56)
                self.assertEqual(mpl.rcParams["axes.labelsize"], 8.4)
                self.assertEqual(mpl.rcParams["legend.fontsize"], 6.96)

    def test_active_coordinate_plotters_use_shared_geometry(self) -> None:
        for function in (
            PARTIAL_POLICY.draw_deployment_conflict_panel,
            PARTIAL_POLICY.draw_openscope_placement,
            PROCESSING_COST.new_cost_panel,
            DEPLOYMENT_OUTCOMES.draw_figure,
        ):
            source = inspect.getsource(function)
            with self.subTest(function=function.__name__):
                self.assertIn("figsize=ACTIVE_PANEL_FIGSIZE", source)
                self.assertIn(
                    "subplots_adjust(**ACTIVE_PANEL_MARGINS)", source
                )

    def test_active_plotters_preserve_axis_style_contract(self) -> None:
        for module, function_names in ACTIVE_PLOTTERS:
            for function_name in function_names:
                with self.subTest(
                    module=module.__name__, function=function_name
                ):
                    source = inspect.getsource(getattr(module, function_name))
                    self.assertRegex(source, r"\bconfigure_style\s*\(\s*\)")
                    self.assertIsNone(
                        re.search(
                            r"\bdirection\s*=\s*['\"]out['\"]",
                            source,
                        )
                    )
                    self.assertIsNone(
                        re.search(
                            r"\.set_visible\s*\(\s*False\s*\)",
                            source,
                        )
                    )
                    self.assertIsNone(
                        re.search(r"\b(?:top|right)\s*=\s*True", source)
                    )

    def test_deployment_conflict_panels_omit_range_glyphs(self) -> None:
        for function in (
            PARTIAL_POLICY.draw_deployment_conflict_panel,
            PARTIAL_POLICY.draw_openscope_placement,
        ):
            source = inspect.getsource(function)
            for forbidden in (".errorbar(", ".fill_between(", "_p05", "_p95"):
                with self.subTest(function=function.__name__, forbidden=forbidden):
                    self.assertNotIn(forbidden, source)

    def test_percentage_panels_use_exact_zero_to_hundred_x_range(self) -> None:
        for function in (
            PARTIAL_POLICY.draw_deployment_conflict_panel,
            PARTIAL_POLICY.draw_openscope_placement,
            DEPLOYMENT_OUTCOMES.draw_figure,
        ):
            source = inspect.getsource(function)
            with self.subTest(function=function.__name__):
                self.assertRegex(
                    source,
                    r"\.set_xlim\(\s*0(?:\.0)?\s*,\s*100(?:\.0)?\s*\)",
                )

    def test_deployment_outcome_endpoint_markers_are_not_clipped(self) -> None:
        source = inspect.getsource(DEPLOYMENT_OUTCOMES.draw_figure)
        self.assertEqual(source.count("clip_on=False"), 2)


if __name__ == "__main__":
    unittest.main()
