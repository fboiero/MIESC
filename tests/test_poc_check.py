"""Tests for the optional forge compile-check of PoC scaffolds (phase 5).

The check must be strictly best-effort: skip everything when forge is absent
(so CI is never affected), never raise, and report compiled/failed per scaffold
when forge and the scaffolded project are available. The forge/Foundry
collaborators are mocked so these run without forge installed.
"""

import unittest
from unittest import mock

from miesc.formal.poc_check import check_scaffolds_compile, forge_available

_SCAFFOLDS = [("A_halmos_cx1.t.sol", "contract A {}"), ("B_halmos_cx2.t.sol", "contract B {}")]


class TestForgeAvailability(unittest.TestCase):
    def test_forge_available_reflects_path(self):
        with mock.patch("shutil.which", return_value="/usr/bin/forge"):
            self.assertTrue(forge_available())
        with mock.patch("shutil.which", return_value=None):
            self.assertFalse(forge_available())


class TestSkipPaths(unittest.TestCase):
    def test_empty_scaffolds(self):
        self.assertEqual(check_scaffolds_compile([], "/repo", "/c.sol"), [])

    def test_all_skipped_when_forge_absent(self):
        with mock.patch("miesc.formal.poc_check.forge_available", return_value=False):
            out = check_scaffolds_compile(_SCAFFOLDS, "/repo", "/c.sol")
        self.assertEqual([r["status"] for r in out], ["skipped", "skipped"])
        self.assertEqual([r["filename"] for r in out], [s[0] for s in _SCAFFOLDS])

    def test_all_skipped_when_project_scaffold_fails(self):
        with (
            mock.patch("miesc.formal.poc_check.forge_available", return_value=True),
            mock.patch("miesc.poc.foundry_scaffold.scaffold_foundry_project", return_value=None),
        ):
            out = check_scaffolds_compile(_SCAFFOLDS, "/repo", "/c.sol")
        self.assertTrue(all(r["status"] == "skipped" for r in out))


class TestCompilePath(unittest.TestCase):
    def test_reports_compiled_and_failed(self):
        import tempfile

        with tempfile.TemporaryDirectory() as project:
            runner = mock.Mock()
            # baseline build (True), then scaffold 1 compiles (True), scaffold 2 fails (False)
            runner.compile.side_effect = [True, True, False]
            with (
                mock.patch("miesc.formal.poc_check.forge_available", return_value=True),
                mock.patch(
                    "miesc.poc.foundry_scaffold.scaffold_foundry_project", return_value=project
                ),
                mock.patch(
                    "miesc.poc.validators.foundry_runner.FoundryRunner", return_value=runner
                ),
            ):
                out = check_scaffolds_compile(_SCAFFOLDS, "/repo", "/c.sol")
        self.assertEqual([r["status"] for r in out], ["compiled", "failed"])

    def test_compile_exception_is_skipped_not_raised(self):
        import tempfile

        with tempfile.TemporaryDirectory() as project:
            runner = mock.Mock()
            runner.compile.side_effect = RuntimeError("forge blew up")
            with (
                mock.patch("miesc.formal.poc_check.forge_available", return_value=True),
                mock.patch(
                    "miesc.poc.foundry_scaffold.scaffold_foundry_project", return_value=project
                ),
                mock.patch(
                    "miesc.poc.validators.foundry_runner.FoundryRunner", return_value=runner
                ),
            ):
                out = check_scaffolds_compile([_SCAFFOLDS[0]], "/repo", "/c.sol")
        self.assertEqual(out[0]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
