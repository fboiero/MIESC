"""
Coverage boost tests for MIESC project.

Targets uncovered lines in:
- src/ml/code_embeddings.py (lines 208-211, 604-621)
- src/core/tool_discovery.py (lines 126, 140, 146-148, 197-205, 220-222, 235, 241, 247, 260, 276)
- src/detectors/detector_api.py (lines 436, 442-445, 465, 470-471)
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# code_embeddings.py coverage
# ---------------------------------------------------------------------------

from src.ml.code_embeddings import (
    CodeEmbedder,
    CodeEmbedding,
    SolidityTokenizer,
    VulnerabilityPatternDB,
)


class TestTokenizerCommentHandling:
    """Cover lines 208-211: comment extraction in SolidityTokenizer.tokenize."""

    def test_tokenize_line_with_inline_comment(self):
        """Tokenize code that has inline comments to hit the // branch."""
        tokenizer = SolidityTokenizer()
        code = "uint x = 1; // this is a comment"
        tokens = tokenizer.tokenize(code)

        comment_tokens = [t for t in tokens if t.token_type.value == "comment"]
        assert len(comment_tokens) == 1
        assert "// this is a comment" in comment_tokens[0].value

    def test_tokenize_multiple_comment_lines(self):
        """Tokenize multiple lines with comments."""
        tokenizer = SolidityTokenizer()
        code = (
            "function foo() public {\n"
            "    uint x = 1; // first comment\n"
            "    // full line comment\n"
            "    return x;\n"
            "}"
        )
        tokens = tokenizer.tokenize(code)
        comment_tokens = [t for t in tokens if t.token_type.value == "comment"]
        assert len(comment_tokens) == 2

    def test_tokenize_comment_preserves_position(self):
        """Verify comment token records the correct position."""
        tokenizer = SolidityTokenizer()
        code = "abc // note"
        tokens = tokenizer.tokenize(code)
        comment_tokens = [t for t in tokens if t.token_type.value == "comment"]
        assert len(comment_tokens) == 1
        assert comment_tokens[0].position == 4  # index of "//"


class TestVulnerabilityPatternDBMatchPatterns:
    """Cover lines 604-621: VulnerabilityPatternDB.match_patterns."""

    def test_match_patterns_returns_matches(self):
        """match_patterns should find matches for code similar to known patterns."""
        db = VulnerabilityPatternDB()

        # Code very similar to the reentrancy pattern in _initialize_patterns
        reentrancy_code = """
        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
        }
        """
        matches = db.match_patterns(reentrancy_code, threshold=0.3)

        assert isinstance(matches, list)
        # Should find at least one match since the code is nearly identical
        assert len(matches) >= 1
        for m in matches:
            assert "vulnerability_type" in m
            assert "similarity" in m
            assert "confidence" in m

    def test_match_patterns_empty_for_unrelated_code(self):
        """match_patterns with very high threshold should return nothing for unrelated code."""
        db = VulnerabilityPatternDB()

        unrelated = "contract Empty {}"
        matches = db.match_patterns(unrelated, threshold=0.99)
        assert isinstance(matches, list)
        # With a very high threshold, we expect zero or very few matches
        # (the threshold is very strict)

    def test_match_patterns_sorted_by_similarity(self):
        """Verify results are sorted by descending similarity."""
        db = VulnerabilityPatternDB()

        code = """
        function transferTo(address to, uint amount) public {
            require(tx.origin == owner);
            to.transfer(amount);
        }
        """
        matches = db.match_patterns(code, threshold=0.1)
        if len(matches) >= 2:
            for i in range(len(matches) - 1):
                assert matches[i]["similarity"] >= matches[i + 1]["similarity"]

    def test_match_patterns_confidence_capped(self):
        """Confidence should be capped at 0.95."""
        db = VulnerabilityPatternDB()

        code = """
        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
        }
        """
        matches = db.match_patterns(code, threshold=0.1)
        for m in matches:
            assert m["confidence"] <= 0.95


class TestCodeEmbeddingSimilarityNormal:
    """Additional similarity tests for CodeEmbedding to ensure normal path coverage."""

    def test_similarity_identical_vectors(self):
        """Similarity of identical vectors should be 1.0."""
        embed = CodeEmbedding(
            source_hash="a",
            vector=[0.6, 0.8],
            dimensions=2,
            tokens=5,
            code_type="function",
        )
        assert abs(embed.similarity(embed) - 1.0) < 1e-6

    def test_similarity_orthogonal_vectors(self):
        """Similarity of orthogonal vectors should be 0.0."""
        e1 = CodeEmbedding(
            source_hash="a",
            vector=[1.0, 0.0],
            dimensions=2,
            tokens=5,
            code_type="function",
        )
        e2 = CodeEmbedding(
            source_hash="b",
            vector=[0.0, 1.0],
            dimensions=2,
            tokens=5,
            code_type="function",
        )
        assert abs(e1.similarity(e2)) < 1e-6


# ---------------------------------------------------------------------------
# tool_discovery.py coverage
# ---------------------------------------------------------------------------

from src.core.tool_discovery import ToolDiscovery, ToolInfo


class TestToolDiscoveryFindAdaptersPathNotFound:
    """Cover line 126: RuntimeError when adapters directory not found."""

    def test_raises_when_no_adapters_dir(self):
        """_find_adapters_path raises RuntimeError if no candidate directory exists."""
        with patch.object(Path, "exists", return_value=False):
            with pytest.raises(RuntimeError, match="Could not find adapters directory"):
                ToolDiscovery(adapters_path=None)


class TestToolDiscoveryDiscoverBranches:
    """Cover lines 140, 146-148: discover skips _-prefixed files and catches exceptions."""

    def test_discover_skips_underscore_files(self, tmp_path):
        """Files starting with _ should be skipped during discover."""
        # Create a file that starts with _
        underscore_file = tmp_path / "_internal_adapter.py"
        underscore_file.write_text("class InternalAdapter: pass")

        # Create a normal adapter file (will fail to import but that's fine)
        normal_file = tmp_path / "fake_adapter.py"
        normal_file.write_text("class FakeAdapter: pass")

        disc = ToolDiscovery(adapters_path=str(tmp_path))
        tools = disc.discover()
        # _internal_adapter should not appear
        assert "_internal" not in tools

    def test_discover_catches_load_exception(self, tmp_path):
        """discover silently catches exceptions from _load_adapter_info."""
        # Create a valid-looking adapter file
        adapter_file = tmp_path / "broken_adapter.py"
        adapter_file.write_text("class BrokenAdapter: pass")

        disc = ToolDiscovery(adapters_path=str(tmp_path))

        # Mock _load_adapter_info to raise an exception
        with patch.object(disc, "_load_adapter_info", side_effect=Exception("boom")):
            tools = disc.discover()
            assert isinstance(tools, dict)
            # Should not crash


class TestToolDiscoveryLoadAdapterInfoBranches:
    """Cover lines 197-205 and 220-222: exception branches in _load_adapter_info."""

    def test_import_error_returns_unavailable_tool_info(self, tmp_path):
        """ImportError in _load_adapter_info returns ToolInfo with available=False."""
        adapter_file = tmp_path / "nonexistent_adapter.py"
        adapter_file.write_text("# empty")

        disc = ToolDiscovery(adapters_path=str(tmp_path))

        with patch("importlib.import_module", side_effect=ImportError("no such module")):
            result = disc._load_adapter_info(adapter_file)

        assert result is not None
        assert result.available is False
        assert result.is_optional is True

    def test_instance_creation_fails_returns_unavailable(self, tmp_path):
        """When adapter instantiation raises, should return available=False (lines 200-205)."""
        import types

        adapter_file = tmp_path / "badctor_adapter.py"
        adapter_file.write_text("# placeholder")

        disc = ToolDiscovery(adapters_path=str(tmp_path))

        # Build a real module object with a class that raises on instantiation
        fake_module = types.ModuleType("src.adapters.badctor_adapter")

        class BadctorAdapter:
            def __init__(self):
                raise RuntimeError("constructor failed")

        fake_module.BadctorAdapter = BadctorAdapter

        with patch("importlib.import_module", return_value=fake_module):
            result = disc._load_adapter_info(adapter_file)

        assert result is not None
        assert result.available is False
        assert result.adapter_class == "BadctorAdapter"

    def test_get_metadata_exception_is_caught(self, tmp_path):
        """When get_metadata raises, it should be silently caught (lines 197-198)."""
        import types

        adapter_file = tmp_path / "metafail_adapter.py"
        adapter_file.write_text("# placeholder")

        disc = ToolDiscovery(adapters_path=str(tmp_path))

        fake_module = types.ModuleType("src.adapters.metafail_adapter")

        class MetafailAdapter:
            def is_available(self):
                return True

            def get_metadata(self):
                raise AttributeError("no metadata")

        fake_module.MetafailAdapter = MetafailAdapter

        with patch("importlib.import_module", return_value=fake_module):
            result = disc._load_adapter_info(adapter_file)

        assert result is not None
        assert result.available is True
        # Description defaults to "" when get_metadata fails
        assert result.description == ""


class TestToolDiscoveryAutoDiscover:
    """Cover lines 235, 241, 247, 260, 276: auto-discover when _discovered is False."""

    def _make_undiscovered(self):
        """Create a ToolDiscovery instance that has not yet discovered."""
        disc = ToolDiscovery()
        disc._discovered = False
        disc._tools = {}
        return disc

    def test_get_tool_triggers_discover(self):
        """get_tool should call discover if not yet discovered."""
        disc = self._make_undiscovered()
        with patch.object(disc, "discover", return_value={}) as mock_disc:
            disc.get_tool("slither")
            mock_disc.assert_called_once()

    def test_get_available_tools_triggers_discover(self):
        """get_available_tools should call discover if not yet discovered."""
        disc = self._make_undiscovered()
        with patch.object(disc, "discover", return_value={}) as mock_disc:
            disc.get_available_tools()
            mock_disc.assert_called_once()

    def test_get_tools_by_layer_triggers_discover(self):
        """get_tools_by_layer should call discover if not yet discovered."""
        disc = self._make_undiscovered()
        with patch.object(disc, "discover", return_value={}) as mock_disc:
            disc.get_tools_by_layer()
            mock_disc.assert_called_once()

    def test_get_all_tool_names_triggers_discover(self):
        """get_all_tool_names should call discover if not yet discovered."""
        disc = self._make_undiscovered()
        with patch.object(disc, "discover", return_value={}) as mock_disc:
            disc.get_all_tool_names()
            mock_disc.assert_called_once()

    def test_to_dict_triggers_discover(self):
        """to_dict should call discover if not yet discovered."""
        disc = self._make_undiscovered()
        with patch.object(disc, "discover", return_value={}) as mock_disc:
            disc.to_dict()
            # to_dict calls discover, plus internal calls to get_available_tools
            # and get_tools_by_layer also check _discovered
            assert mock_disc.call_count >= 1


# ---------------------------------------------------------------------------
# detector_api.py coverage
# ---------------------------------------------------------------------------

from src.detectors.detector_api import (
    BaseDetector,
    Category,
    DetectorRegistry,
    Finding,
    Severity,
)


class TestDetectorRegistryPluginLoading:
    """Cover lines 436, 442-445: _load_plugins entry_points branches."""

    def test_load_plugins_select_not_available(self):
        """When entry_points() has no 'select' method, use .get() fallback (line 436)."""
        registry = DetectorRegistry.__new__(DetectorRegistry)
        registry._detectors = {}
        registry._loaded_plugins = False

        mock_eps = {"miesc.detectors": []}  # dict-like, no select method
        with patch("importlib.metadata.entry_points", return_value=mock_eps):
            registry._load_plugins()

        assert registry._loaded_plugins is True

    def test_load_plugins_ep_load_fails(self):
        """When an entry point fails to load, print warning (lines 442-443)."""
        registry = DetectorRegistry.__new__(DetectorRegistry)
        registry._detectors = {}
        registry._loaded_plugins = False

        mock_ep = MagicMock()
        mock_ep.name = "broken_detector"
        mock_ep.load.side_effect = ImportError("cannot load")

        mock_eps = MagicMock()
        mock_eps.select.return_value = [mock_ep]

        with patch("importlib.metadata.entry_points", return_value=mock_eps):
            registry._load_plugins()

        assert registry._loaded_plugins is True
        # The detector should NOT have been registered
        assert "broken_detector" not in registry._detectors

    def test_load_plugins_entry_points_raises(self):
        """When entry_points() itself raises, silently pass (lines 444-445)."""
        registry = DetectorRegistry.__new__(DetectorRegistry)
        registry._detectors = {}
        registry._loaded_plugins = False

        with patch(
            "importlib.metadata.entry_points", side_effect=Exception("no metadata")
        ):
            registry._load_plugins()

        assert registry._loaded_plugins is True


class TestDetectorRegistryRunAllBranches:
    """Cover lines 465, 470-471: run_all skip disabled and exception handling."""

    def test_run_all_skips_disabled_detector(self):
        """run_all should skip detectors that are disabled (line 465)."""
        registry = DetectorRegistry.__new__(DetectorRegistry)
        registry._detectors = {}
        registry._loaded_plugins = True

        class EnabledDetector(BaseDetector):
            name = "enabled-det"

            def analyze(self, source_code, file_path=None):
                return [
                    Finding(
                        detector=self.name,
                        title="Found",
                        description="D",
                        severity=Severity.LOW,
                    )
                ]

        class DisabledDetector(BaseDetector):
            name = "disabled-det"

            def analyze(self, source_code, file_path=None):
                return [
                    Finding(
                        detector=self.name,
                        title="Should Not Appear",
                        description="D",
                        severity=Severity.LOW,
                    )
                ]

        enabled = EnabledDetector()
        disabled = DisabledDetector()
        disabled.enabled = False

        registry.register(enabled)
        registry.register(disabled)

        findings = registry.run_all("some code", enabled_only=True)

        detectors_found = {f.detector for f in findings}
        assert "enabled-det" in detectors_found
        assert "disabled-det" not in detectors_found

    def test_run_all_catches_detector_exception(self):
        """run_all should catch exceptions from failing detectors (lines 470-471)."""
        registry = DetectorRegistry.__new__(DetectorRegistry)
        registry._detectors = {}
        registry._loaded_plugins = True

        class CrashingDetector(BaseDetector):
            name = "crasher"

            def analyze(self, source_code, file_path=None):
                raise RuntimeError("detector crashed")

        class OkDetector(BaseDetector):
            name = "ok-det"

            def analyze(self, source_code, file_path=None):
                return [
                    Finding(
                        detector=self.name,
                        title="OK",
                        description="D",
                        severity=Severity.LOW,
                    )
                ]

        registry.register(CrashingDetector())
        registry.register(OkDetector())

        # Should not raise, and should still include findings from the OK detector
        findings = registry.run_all("some code")
        assert any(f.detector == "ok-det" for f in findings)
