PYTHON ?= python3
SOURCE_DATE_EPOCH ?= 1787875200
FORCE_SOURCE_DATE ?= 1
export SOURCE_DATE_EPOCH FORCE_SOURCE_DATE

LOCKED_TITLE := Protect the Parent, Spare the Child: Protecting Prefixes in RPKI before All Origins Are Known
LOCKED_INTRO_P1_SHA256 := 6ebf6cf9dcf60cdb9eefc14a49d4f632fbdd3a536533848bb9ab69ac5e901162
LOCKED_INTRO_P2_SHA256 := 72506e5a071693450c8b48e2744e39fc46a9c6e513e26b48419960788b7f7bea

SECTIONS := $(wildcard sections/*.tex)
FIGURES := \
	figures/fig_motivation_overview.pdf \
	figures/fig_partial_policy_legend.pdf \
	figures/fig_partial_policy_potential.pdf \
	figures/fig_partial_policy_observed.pdf \
	figures/fig_openscope_placement.pdf \
	figures/fig_processing_cost_classify.pdf \
	figures/fig_processing_cost_update.pdf \
	figures/fig_deployment_outcomes_a.pdf \
	figures/fig_deployment_outcomes_b.pdf
FIGURE_INPUTS := \
	../phase1_empirical/allocation_tree/visibility_experiment/outputs/visibility_candidates.csv \
	figures/source_data/openscope_placement_as_scores.json \
	../phase4_encoding/scripts/utils/daroa.py \
	../phase4_encoding/scripts/utils/as_set.py \
	../phase5_evaluation/processing_benchmark/outputs/controlled-processing-20260830T-marker-final-v1/summary.json \
	../phase5_evaluation/processing_benchmark/outputs/controlled-processing-20260830T-marker-final-v1/independent_audit.json \
	../phase5_evaluation/processing_benchmark/outputs/policy-update-20260830T-marker-final-v1/summary.json \
	../phase5_evaluation/processing_benchmark/outputs/policy-update-20260830T-marker-final-v1/independent_audit.json \
	../phase5_evaluation/processing_benchmark/outputs/policy-update-20260830T-marker-final-v1/input_manifest.json \
	../phase5_evaluation/processing_benchmark/outputs/policy-update-20260830T-marker-final-v1/run_config.json \
	../phase5_evaluation/processing_benchmark/outputs/policy-update-20260830T-marker-final-v1/artifact_manifest.json \
	../phase7_simulation/results/paper_campaign/analysis/raw_cell_summary.csv \
	../phase7_simulation/results/paper_campaign/analysis/analysis_manifest.json \
	../phase9_selected_unit_reanalysis/results/competition_cells.csv \
	../phase7_simulation/results/deployment_grid_extension/manifest.json \
	../phase7_simulation/results/deployment_grid_extension/raw_scenarios.jsonl \
	../phase7_simulation/results/deployment_grid_extension/independent_audit.json \
	../phase7_simulation/results/deployment_grid_extension/analysis/analysis_manifest.json \
	../phase7_simulation/results/deployment_grid_extension/analysis/order_level_unit_contrasts.jsonl \
	../phase7_simulation/results/deployment_grid_extension/analysis/unit_contrasts.jsonl \
	../phase7_simulation/results/deployment_grid_extension/analysis/cell_summary.json \
	../phase7_simulation/results/deployment_grid_extension/analysis/cell_summary.csv \
	../phase7_simulation/results/deployment_grid_extension/analysis/order_trajectories.json \
	../phase7_simulation/results/deployment_grid_extension/analysis/order_trajectories.csv

.PHONY: all figures refresh check clean

all: refresh check

figures: scripts/build_motivation_figure.py scripts/run_partial_policy_replay.py scripts/build_processing_cost_table.py scripts/build_processing_cost_figure.py scripts/build_fig_deployment_outcomes.py scripts/figure_typography.py scripts/check_figure_fonts.py $(FIGURE_INPUTS)
	$(PYTHON) scripts/build_motivation_figure.py
	$(PYTHON) scripts/run_partial_policy_replay.py
	$(PYTHON) scripts/build_processing_cost_table.py
	$(PYTHON) scripts/build_processing_cost_figure.py
	$(PYTHON) scripts/build_fig_deployment_outcomes.py
	$(PYTHON) scripts/check_figure_fonts.py

refresh: template.json blueprint.json main.tex.tmpl refs.bib $(SECTIONS) $(FIGURES)
	$(PYTHON) scripts/assemble_paper.py .

check: main.pdf
	@$(PYTHON) scripts/check_classifier_boundaries.py
	@$(PYTHON) scripts/check_figure_fonts.py --main-pdf
	@test "$$(grep -c '\\begin{abstract}' main.tex)" -eq 1
	@test "$$(grep -c '\\end{abstract}' main.tex)" -eq 1
	@test "$$(grep -c '\\begin{IEEEkeywords}' main.tex)" -eq 1
	@test "$$(grep -c '\\end{IEEEkeywords}' main.tex)" -eq 1
	@$(PYTHON) -m unittest discover -s scripts/tests -p 'test_active_axis_style.py'
	@$(PYTHON) -m unittest discover -s scripts/tests -p 'test_build_processing_cost_figure.py'
	@$(PYTHON) -m unittest discover -s scripts/tests -p 'test_partial_policy_replay.py'
	@test "$$($(PYTHON) -c 'import json; print(json.load(open("blueprint.json", encoding="utf-8"))["paper_title"])')" = "$(LOCKED_TITLE)"
	@test "$$(sed -n '3p' sections/introduction.tex | sha256sum | awk '{print $$1}')" = "$(LOCKED_INTRO_P1_SHA256)"
	@test "$$(sed -n '5p' sections/introduction.tex | sha256sum | awk '{print $$1}')" = "$(LOCKED_INTRO_P2_SHA256)"
	@test "$$(pdfinfo main.pdf | sed -n 's/^Title:[[:space:]]*//p')" = "$(LOCKED_TITLE)"
	@echo "PDF pages (informational): $$(pdfinfo main.pdf | awk '/^Pages:/{print $$2}')"
	@pdfinfo main.pdf | grep -q '612 x 792 pts'
	@! pdffonts main.pdf 2>/dev/null | grep -q 'Type 3'
	@if test -f main.log; then \
		! grep -E '(^!|Undefined control sequence|LaTeX Error|Citation .* undefined|Reference .* undefined)' main.log; \
	fi

clean:
	latexmk -C main.tex
	$(RM) -r build
