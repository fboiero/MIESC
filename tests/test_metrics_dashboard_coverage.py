"""Behavioural coverage tests for ``miesc.utils.metrics_dashboard``.

These tests lay down realistic Slither/Foundry/Echidna result files under
``tmp_path`` and assert the metrics the :class:`XauditDashboard` collects, the
JSON it round-trips, the HTML it renders and the behaviour of ``main``.

Chart generation (``generate_charts`` / ``_chart_*``) renders with matplotlib.
matplotlib is intentionally NOT a runtime dependency of this module (it guards
the import and sets ``plt = None`` when it is missing). In that configuration
``generate_charts`` is a no-op, which is the degradation path asserted here;
the chart-drawing internals require matplotlib and are left uncovered on
purpose rather than exercised through a mock that would assert nothing real.
"""

import json
import logging
import sys

import pytest

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _write_slither(results_dir, detectors_per_file):
    """Create ``results_dir/slither`` with one JSON file per detector list."""
    slither_dir = results_dir / "slither"
    slither_dir.mkdir(parents=True, exist_ok=True)
    for idx, detectors in enumerate(detectors_per_file):
        payload = {"results": {"detectors": detectors}}
        (slither_dir / f"report_{idx}.json").write_text(json.dumps(payload))
    return slither_dir


def _write_foundry(results_dir, content):
    foundry_dir = results_dir / "foundry"
    foundry_dir.mkdir(parents=True, exist_ok=True)
    (foundry_dir / "test_results.txt").write_text(content)
    return foundry_dir


def _write_echidna(results_dir, files):
    echidna_dir = results_dir / "echidna"
    echidna_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (echidna_dir / name).write_text(content)
    return echidna_dir


# ---------------------------------------------------------------------------
# Slither collection
# ---------------------------------------------------------------------------


def test_slither_counts_group_by_severity_and_ignore_unknown_impact(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    long_desc = "x" * 250
    _write_slither(
        tmp_path,
        [
            [
                {
                    "impact": "High",
                    "check": "reentrancy-eth",
                    "description": long_desc,
                    "confidence": "High",
                },
                {
                    "impact": "MEDIUM",
                    "check": "unchecked-lowlevel",
                    "description": "d",
                    "confidence": "Medium",
                },
            ],
            [
                {
                    "impact": "low",
                    "check": "naming-convention",
                    "description": "d",
                    "confidence": "High",
                },
                {"impact": "Info", "check": "pragma", "description": "d", "confidence": "High"},
                # Impact outside the tracked buckets is silently ignored.
                {
                    "impact": "Optimization",
                    "check": "costly-loop",
                    "description": "d",
                    "confidence": "High",
                },
            ],
        ],
    )

    metrics = XauditDashboard(tmp_path).metrics
    slither = metrics["slither"]

    assert slither["high"]["count"] == 1
    assert slither["medium"]["count"] == 1
    assert slither["low"]["count"] == 1
    assert slither["info"]["count"] == 1
    # "Optimization" was dropped, so only four issues are tracked in total.
    assert sum(b["count"] for b in slither.values()) == 4

    # Issue payload is preserved and the description is truncated to 100 chars.
    high_issue = slither["high"]["issues"][0]
    assert high_issue["check"] == "reentrancy-eth"
    assert high_issue["confidence"] == "High"
    assert len(high_issue["description"]) == 100


def test_slither_missing_dir_returns_empty_and_zero_summary(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    metrics = XauditDashboard(tmp_path).metrics

    assert metrics["slither"] == {}
    summary = metrics["summary"]
    assert summary["total_issues"] == 0
    assert summary["critical"] == 0
    assert summary["high"] == 0
    assert summary["medium"] == 0


def test_slither_malformed_json_is_skipped_and_logged(tmp_path, caplog):
    from miesc.utils.metrics_dashboard import XauditDashboard

    slither_dir = _write_slither(
        tmp_path,
        [[{"impact": "high", "check": "ok", "description": "d", "confidence": "High"}]],
    )
    # A file missing the "results" key contributes zero issues (no crash).
    (slither_dir / "empty.json").write_text(json.dumps({}))
    # A truly malformed file must be skipped with a warning.
    (slither_dir / "broken.json").write_text("{not valid json")

    with caplog.at_level(logging.WARNING, logger="miesc.utils.metrics_dashboard"):
        metrics = XauditDashboard(tmp_path).metrics

    # The good detector still counts despite the broken neighbour.
    assert metrics["slither"]["high"]["count"] == 1
    assert "broken.json" in caplog.text


# ---------------------------------------------------------------------------
# Foundry collection
# ---------------------------------------------------------------------------


def test_foundry_counts_pass_and_fail_markers(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    _write_foundry(tmp_path, "[PASS] a\n[PASS] b\n[FAIL] c\n[PASS] d\n")

    foundry = XauditDashboard(tmp_path).metrics["foundry"]
    assert foundry["passed"] == 3
    assert foundry["failed"] == 1
    assert foundry["total"] == 4


def test_foundry_missing_dir_returns_zeros_without_total(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    foundry = XauditDashboard(tmp_path).metrics["foundry"]
    # Missing data returns the minimal shape (no "total" key) by contract.
    assert foundry == {"passed": 0, "failed": 0}
    assert "total" not in foundry


def test_foundry_missing_results_file_returns_zeros(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    (tmp_path / "foundry").mkdir()  # dir exists but no test_results.txt

    foundry = XauditDashboard(tmp_path).metrics["foundry"]
    assert foundry == {"passed": 0, "failed": 0}


def test_foundry_unreadable_results_file_degrades_to_zeros(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    foundry_dir = tmp_path / "foundry"
    foundry_dir.mkdir()
    # Make "test_results.txt" a directory so read_text() raises and is caught.
    (foundry_dir / "test_results.txt").mkdir()

    foundry = XauditDashboard(tmp_path).metrics["foundry"]
    assert foundry == {"passed": 0, "failed": 0}


# ---------------------------------------------------------------------------
# Echidna collection
# ---------------------------------------------------------------------------


def test_echidna_counts_violated_and_passed_across_files(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    _write_echidna(
        tmp_path,
        {
            "prop_a.txt": "invariant failed!\nother passed!\n",
            "prop_b.txt": "passed!\n",
        },
    )

    echidna = XauditDashboard(tmp_path).metrics["echidna"]
    assert echidna["violated"] == 1
    assert echidna["passed"] == 2
    assert echidna["total"] == 3


def test_echidna_missing_dir_returns_zeros(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    echidna = XauditDashboard(tmp_path).metrics["echidna"]
    assert echidna == {"violated": 0, "passed": 0}


def test_echidna_unreadable_file_is_skipped(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    echidna_dir = tmp_path / "echidna"
    echidna_dir.mkdir()
    (echidna_dir / "good.txt").write_text("failed!\npassed!\n")
    # A directory matching *.txt makes read_text() raise; it must be skipped.
    (echidna_dir / "bad.txt").mkdir()

    echidna = XauditDashboard(tmp_path).metrics["echidna"]
    assert echidna["violated"] == 1
    assert echidna["passed"] == 1


# ---------------------------------------------------------------------------
# Summary mapping
# ---------------------------------------------------------------------------


def test_summary_maps_severity_buckets_and_test_results(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    _write_slither(
        tmp_path,
        [
            [
                {"impact": "high", "check": "h1", "description": "d", "confidence": "High"},
                {"impact": "high", "check": "h2", "description": "d", "confidence": "High"},
                {"impact": "medium", "check": "m1", "description": "d", "confidence": "High"},
                {"impact": "low", "check": "l1", "description": "d", "confidence": "High"},
                {"impact": "low", "check": "l2", "description": "d", "confidence": "High"},
                {"impact": "low", "check": "l3", "description": "d", "confidence": "High"},
            ]
        ],
    )
    _write_foundry(tmp_path, "[PASS] a\n[PASS] b\n[FAIL] c\n")
    _write_echidna(tmp_path, {"p.txt": "failed!\nfailed!\npassed!\n"})

    summary = XauditDashboard(tmp_path).metrics["summary"]

    # This pins the module's CURRENT mapping (the test does not endorse it):
    # summary["critical"] <- slither high, summary["high"] <- slither medium,
    # summary["medium"] <- slither low.
    assert summary["total_issues"] == 6
    assert summary["critical"] == 2  # slither "high" bucket
    assert summary["high"] == 1  # slither "medium" bucket
    assert summary["medium"] == 3  # slither "low" bucket
    assert summary["tests_passed"] == 2
    assert summary["tests_failed"] == 1
    assert summary["properties_violated"] == 2


# ---------------------------------------------------------------------------
# JSON / HTML output
# ---------------------------------------------------------------------------


def test_save_metrics_json_round_trips_and_creates_parents(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    _write_foundry(tmp_path, "[PASS] a\n[FAIL] b\n")
    dashboard = XauditDashboard(tmp_path)

    out = tmp_path / "nested" / "out" / "metrics.json"
    dashboard.save_metrics_json(out)

    assert out.exists()
    loaded = json.loads(out.read_text())
    assert loaded["summary"] == dashboard.metrics["summary"]
    assert loaded["foundry"] == {"passed": 1, "failed": 1, "total": 2}
    assert "timestamp" in loaded


def test_generate_html_report_embeds_summary_numbers(tmp_path):
    from miesc.utils.metrics_dashboard import XauditDashboard

    _write_slither(
        tmp_path,
        [
            [
                {"impact": "high", "check": "h", "description": "d", "confidence": "High"},
                {"impact": "medium", "check": "m", "description": "d", "confidence": "High"},
                {"impact": "medium", "check": "m2", "description": "d", "confidence": "High"},
            ]
        ],
    )
    _write_foundry(tmp_path, "[PASS] a\n[PASS] b\n[PASS] c\n[FAIL] d\n")
    dashboard = XauditDashboard(tmp_path)

    out = tmp_path / "report" / "index.html"
    dashboard.generate_html_report(out)

    assert out.exists()
    html = out.read_text()
    assert "Xaudit Analysis Dashboard" in html
    # Critical label shows slither "high" (1), High shows slither "medium" (2).
    assert '<div class="value">1</div>' in html
    assert '<div class="value">2</div>' in html
    # Tests passed (3) and failed (1) are rendered.
    assert '<div class="value">3</div>' in html
    assert '<div class="value">4</div>' not in html  # total is not shown as a tile


# ---------------------------------------------------------------------------
# Charts (degradation path — matplotlib absent)
# ---------------------------------------------------------------------------


def test_generate_charts_is_noop_without_matplotlib(tmp_path, monkeypatch):
    from miesc.utils import metrics_dashboard
    from miesc.utils.metrics_dashboard import XauditDashboard

    dashboard = XauditDashboard(tmp_path)
    # Force the matplotlib-missing configuration deterministically.
    monkeypatch.setattr(metrics_dashboard, "plt", None)

    out_dir = tmp_path / "charts"
    assert dashboard.generate_charts(out_dir) is None
    # The early return precedes mkdir, so nothing is created.
    assert not out_dir.exists()


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def test_main_exits_when_results_dir_missing(tmp_path, monkeypatch, capsys):
    from miesc.utils.metrics_dashboard import main

    missing = tmp_path / "does_not_exist"
    monkeypatch.setattr(sys, "argv", ["metrics_dashboard", "--results", str(missing)])

    with pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 1
    assert "not found" in capsys.readouterr().out


def test_main_generates_html_and_json_outputs(tmp_path, monkeypatch, capsys):
    from miesc.utils.metrics_dashboard import XauditDashboard, main

    results_dir = tmp_path / "results"
    results_dir.mkdir()
    _write_slither(
        results_dir,
        [[{"impact": "high", "check": "h", "description": "d", "confidence": "High"}]],
    )
    _write_foundry(results_dir, "[PASS] a\n[FAIL] b\n")
    output_dir = tmp_path / "dashboard"

    monkeypatch.setattr(
        sys,
        "argv",
        ["metrics_dashboard", "--results", str(results_dir), "--output", str(output_dir)],
    )
    main()

    out = capsys.readouterr().out
    assert "Dashboard generated successfully" in out

    index = output_dir / "index.html"
    metrics_file = output_dir / "metrics.json"
    assert index.exists()
    assert metrics_file.exists()
    # No PNGs: matplotlib is absent so chart generation is skipped.
    assert not list(output_dir.glob("*.png"))

    # The persisted summary matches a freshly collected one for the same inputs.
    expected = XauditDashboard(results_dir).metrics["summary"]
    assert json.loads(metrics_file.read_text())["summary"] == expected
