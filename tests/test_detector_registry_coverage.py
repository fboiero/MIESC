"""Coverage for the detector base class and registry (miesc.detectors)."""

import pytest

import miesc.detectors as det
from miesc.detectors import (
    BaseDetector,
    Finding,
    Severity,
    get_all_detectors,
    get_detector,
    list_detectors,
    register_detector,
    run_all_detectors,
    run_detector,
    unregister_detector,
)


@pytest.fixture(autouse=True)
def isolate_registry():
    """Snapshot and restore the global registry so tests don't leak detectors."""
    saved = dict(det._detector_registry)
    try:
        yield
    finally:
        det._detector_registry.clear()
        det._detector_registry.update(saved)


class Dummy(BaseDetector):
    name = "dummy-cov"
    description = "dummy detector for coverage"
    category = "testcat"
    severity_default = Severity.HIGH

    def analyze(self, source_code, file_path=None):
        if "BOOM" in source_code:
            return [
                self.create_finding(
                    title="Boom",
                    description="found boom",
                    line=1,
                    file_path=file_path or "",
                )
            ]
        return []


class Other(BaseDetector):
    name = "other-cov"
    category = "othercat"

    def analyze(self, source_code, file_path=None):
        return []


# --------------------------------------------------------------------------
# BaseDetector + Finding
# --------------------------------------------------------------------------
class TestBaseDetector:
    def test_enable_disable(self):
        d = Dummy()
        assert d.is_enabled() is True
        d.disable()
        assert d.is_enabled() is False
        d.enable()
        assert d.is_enabled() is True

    def test_metadata(self):
        md = Dummy().get_metadata()
        assert md["name"] == "dummy-cov"
        assert md["category"] == "testcat"
        assert md["severity"] == Severity.HIGH.value

    def test_create_finding_and_to_dict(self):
        f = Dummy().create_finding(
            title="T", description="D", line=7, file_path="C.sol", function="foo"
        )
        assert isinstance(f, Finding)
        assert f.location.line == 7
        d = f.to_dict()
        assert d["title"] == "T"
        assert d["severity"] == Severity.HIGH.value
        assert d["detector"] == "dummy-cov"


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------
class TestRegistry:
    def test_register_get_unregister(self):
        register_detector(Dummy)
        assert get_detector("dummy-cov") is Dummy
        assert "dummy-cov" in get_all_detectors()
        assert unregister_detector("dummy-cov") is True
        assert get_detector("dummy-cov") is None

    def test_unregister_missing_returns_false(self):
        assert unregister_detector("does-not-exist") is False

    def test_register_overwrite_warns(self, caplog):
        register_detector(Dummy)
        with caplog.at_level("WARNING"):
            register_detector(Dummy)  # same name -> overwrite warning
        assert any("already registered" in r.message for r in caplog.records)

    def test_register_non_subclass_raises(self):
        with pytest.raises(TypeError):
            register_detector(str)  # not a BaseDetector

    def test_list_detectors_returns_metadata(self):
        register_detector(Dummy)
        names = {m["name"] for m in list_detectors()}
        assert "dummy-cov" in names


# --------------------------------------------------------------------------
# run_detector / run_all_detectors
# --------------------------------------------------------------------------
class TestRun:
    def test_run_detector_found(self):
        register_detector(Dummy)
        findings = run_detector("dummy-cov", "contract C { BOOM }")
        assert len(findings) == 1
        assert findings[0].title == "Boom"

    def test_run_detector_not_found_raises(self):
        with pytest.raises(ValueError):
            run_detector("nope", "x")

    def test_run_detector_disabled_returns_empty(self, monkeypatch):
        register_detector(Dummy)
        # Force the freshly constructed detector to report disabled.
        monkeypatch.setattr(Dummy, "is_enabled", lambda self: False)
        assert run_detector("dummy-cov", "contract C { BOOM }") == []

    def test_run_all_detectors_and_category_filter(self):
        det._detector_registry.clear()
        register_detector(Dummy)
        register_detector(Other)
        # No filter: Dummy fires on BOOM, Other never fires.
        all_f = run_all_detectors("contract C { BOOM }")
        assert len(all_f) == 1
        # Category filter excludes Dummy.
        only_other = run_all_detectors("contract C { BOOM }", categories=["othercat"])
        assert only_other == []

    def test_run_all_detectors_skips_disabled(self, monkeypatch):
        det._detector_registry.clear()
        register_detector(Dummy)
        monkeypatch.setattr(Dummy, "is_enabled", lambda self: False)
        assert run_all_detectors("contract C { BOOM }") == []

    def test_run_all_detectors_swallows_detector_errors(self):
        det._detector_registry.clear()

        class Boom(BaseDetector):
            name = "boom-cov"

            def analyze(self, source_code, file_path=None):
                raise RuntimeError("detector blew up")

        register_detector(Boom)
        # An exploding detector is logged and skipped, not propagated.
        assert run_all_detectors("x") == []


# --------------------------------------------------------------------------
# Loaders
# --------------------------------------------------------------------------
class TestLoaders:
    def test_load_from_bad_package_returns_zero(self):
        assert det.load_detectors_from_package("miesc._no_such_package_xyz") == 0

    def test_load_from_real_examples_package(self):
        det._detector_registry.clear()
        n = det.load_detectors_from_package("miesc.detectors")
        # The examples module registers many detectors.
        assert n >= 1

    def test_load_local_plugins_handles_missing(self, monkeypatch):
        # If the plugin manager raises, the loader degrades to 0, never crashes.
        import miesc.plugins as plugins

        class BadManager:
            def __init__(self, *a, **k):
                raise RuntimeError("no plugins dir")

        monkeypatch.setattr(plugins, "PluginManager", BadManager, raising=False)
        assert det.load_local_plugins() == 0
