"""
Tests for the foundational tool contract (src/core/tool_protocol.py).

Every adapter in the project implements ToolAdapter / returns ToolMetadata; this
module was at 0% covered (omitted). It is a hybrid: pure dataclasses/enums + a
ToolRegistry + concrete ToolAdapter helper methods (finding/result builders,
severity normalization, JSON parsing) + three subprocess helpers (mocked here).
"""

import json
import subprocess

import pytest

import src.core.tool_protocol as mod
from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolRegistry,
    ToolStatus,
    get_tool_registry,
)


class FakeAdapter(ToolAdapter):
    """Minimal concrete adapter to exercise the base-class helpers."""

    def __init__(self, name="fake", category=ToolCategory.STATIC_ANALYSIS,
                 status=ToolStatus.AVAILABLE):
        self._name = name
        self._category = category
        self._status = status

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self._name, version="1.0.0", category=self._category,
            author="t", license="MIT", homepage="h", repository="r",
            documentation="d", installation_cmd="pip install x",
            capabilities=[ToolCapability(name="c", description="d",
                                         supported_languages=["solidity"],
                                         detection_types=["x"])],
            cost=0.0, requires_api_key=False, is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        return self._status

    def analyze(self, contract_path, **kwargs):
        return self.create_result(findings=[])

    def normalize_findings(self, raw_output):
        return []


class _Proc:
    def __init__(self, returncode=0, stdout="v1.0", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --------------------------------------------------------------------------- #
# dataclasses / enums
# --------------------------------------------------------------------------- #
def test_enums_and_dataclasses():
    assert ToolStatus.AVAILABLE.value != ToolStatus.NOT_INSTALLED.value
    assert isinstance(ToolCategory.STATIC_ANALYSIS.value, str)
    cap = ToolCapability(name="n", description="d", supported_languages=["solidity"],
                         detection_types=["reentrancy"])
    assert cap.supported_languages == ["solidity"]
    md = FakeAdapter().get_metadata()
    assert md.name == "fake" and md.is_optional is True


# --------------------------------------------------------------------------- #
# optional/default base methods
# --------------------------------------------------------------------------- #
def test_optional_defaults():
    a = FakeAdapter()
    assert a.can_analyze("x.sol") is True
    assert a.can_analyze("x.txt") is False
    assert a.get_default_config() == {}
    assert a.validate_config({"any": 1}) is True
    instr = a.get_installation_instructions()
    assert "pip install x" in instr and "fake" in instr


# --------------------------------------------------------------------------- #
# normalize_severity
# --------------------------------------------------------------------------- #
def test_normalize_severity():
    a = FakeAdapter()
    assert a.normalize_severity("HIGH") == "High"
    assert a.normalize_severity("informational") == "Info"
    assert a.normalize_severity("warning") == "Medium"
    assert a.normalize_severity("totally-unknown") == "Info"  # default fallback
    # custom map overrides
    assert a.normalize_severity("blocker", {"blocker": "Critical"}) == "Critical"


# --------------------------------------------------------------------------- #
# create_finding / create_result
# --------------------------------------------------------------------------- #
def test_create_finding_normalizes_and_clamps():
    a = FakeAdapter()
    f = a.create_finding("ID1", "reentrancy", "high", "msg", file_path="C.sol",
                         line=5, confidence=2.0)
    assert f["severity"] == "High"
    assert f["confidence"] == 1.0  # clamped to [0,1]
    assert f["location"]["line"] == 5
    assert f["description"] == "msg"  # falls back to message


def test_create_result_structure():
    a = FakeAdapter()
    r = a.create_result(status="error", error="boom")
    assert r["tool"] == "fake"
    assert r["status"] == "error"
    assert r["error"] == "boom"
    assert r["findings"] == []


# --------------------------------------------------------------------------- #
# parse_json_safely
# --------------------------------------------------------------------------- #
def test_parse_json_safely():
    a = FakeAdapter()
    data, err = a.parse_json_safely('{"a": 1}')
    assert data == {"a": 1} and err is None
    # empty
    assert a.parse_json_safely("")[0] is None
    # embedded JSON with ANSI codes and surrounding text
    data, err = a.parse_json_safely('\x1b[31mLOG\x1b[0m result: [1, 2, 3] done')
    assert data == [1, 2, 3] and err is None
    # invalid
    data, err = a.parse_json_safely("{not json")
    assert data is None and "parse error" in err


# --------------------------------------------------------------------------- #
# check_binary_available (subprocess mocked)
# --------------------------------------------------------------------------- #
def test_check_binary_available_all_paths(monkeypatch):
    a = FakeAdapter()
    monkeypatch.setattr(mod.subprocess, "run", lambda *x, **k: _Proc(returncode=0))
    assert a.check_binary_available("slither") == ToolStatus.AVAILABLE

    monkeypatch.setattr(mod.subprocess, "run", lambda *x, **k: _Proc(returncode=1))
    assert a.check_binary_available("slither") == ToolStatus.CONFIGURATION_ERROR

    def _notfound(*x, **k):
        raise FileNotFoundError()
    monkeypatch.setattr(mod.subprocess, "run", _notfound)
    assert a.check_binary_available("slither") == ToolStatus.NOT_INSTALLED

    def _timeout(*x, **k):
        raise subprocess.TimeoutExpired(cmd="slither", timeout=10)
    monkeypatch.setattr(mod.subprocess, "run", _timeout)
    assert a.check_binary_available("slither") == ToolStatus.CONFIGURATION_ERROR

    def _boom(*x, **k):
        raise OSError("weird")
    monkeypatch.setattr(mod.subprocess, "run", _boom)
    assert a.check_binary_available("slither") == ToolStatus.CONFIGURATION_ERROR


def test_run_subprocess(monkeypatch):
    a = FakeAdapter()
    monkeypatch.setattr(mod.subprocess, "run",
                        lambda *x, **k: _Proc(returncode=0, stdout="out", stderr="err"))
    rc, out, err = a.run_subprocess(["echo", "hi"])
    assert (rc, out, err) == (0, "out", "err")


# --------------------------------------------------------------------------- #
# find_binary (subprocess mocked + real executable temp file)
# --------------------------------------------------------------------------- #
def test_find_binary_priority_path(monkeypatch, tmp_path):
    a = FakeAdapter()
    binp = tmp_path / "slither"
    binp.write_text("#!/bin/sh\n")
    binp.chmod(0o755)
    monkeypatch.setattr(mod.subprocess, "run", lambda *x, **k: _Proc(returncode=0))
    assert a.find_binary("slither", priority_paths=[str(binp)]) == str(binp)


def test_find_binary_priority_path_subprocess_fails(monkeypatch, tmp_path):
    a = FakeAdapter()
    binp = tmp_path / "slither"
    binp.write_text("#!/bin/sh\n")
    binp.chmod(0o755)

    def _boom(*x, **k):
        raise OSError("cannot exec")

    monkeypatch.setattr(mod.subprocess, "run", _boom)  # priority path verify raises
    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/slither")
    # priority path fails -> except/continue -> falls back to which
    assert a.find_binary("slither", priority_paths=[str(binp)]) == "/usr/bin/slither"


def test_find_binary_which_fallback(monkeypatch):
    a = FakeAdapter()
    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/slither")
    assert a.find_binary("slither") == "/usr/bin/slither"


def test_find_binary_default(monkeypatch):
    a = FakeAdapter()
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    assert a.find_binary("nope") == "nope"


# --------------------------------------------------------------------------- #
# ToolRegistry
# --------------------------------------------------------------------------- #
def test_tool_registry():
    reg = ToolRegistry()
    a1 = FakeAdapter(name="t1", category=ToolCategory.STATIC_ANALYSIS,
                     status=ToolStatus.AVAILABLE)
    a2 = FakeAdapter(name="t2", category=ToolCategory.STATIC_ANALYSIS,
                     status=ToolStatus.NOT_INSTALLED)
    reg.register(a1)
    reg.register(a2)
    assert reg.get_tool("t1") is a1
    assert len(reg.get_all_tools()) == 2
    assert reg.get_tools_by_category(ToolCategory.STATIC_ANALYSIS) == [a1, a2]
    assert reg.get_available_tools() == [a1]  # only AVAILABLE

    a3 = FakeAdapter(name="t3", status=ToolStatus.CONFIGURATION_ERROR)
    reg.register(a3)
    report = reg.get_tool_status_report()
    assert report["total_tools"] == 3
    assert report["available"] == 1
    assert report["not_installed"] == 1
    assert report["configuration_error"] == 1


def test_tool_registry_overwrite_warns():
    reg = ToolRegistry()
    reg.register(FakeAdapter(name="dup"))
    reg.register(FakeAdapter(name="dup"))  # overwrite path
    assert len(reg.get_all_tools()) == 1


def test_get_tool_registry_singleton():
    assert get_tool_registry() is get_tool_registry()
