"""Tests for the MIESC Plugin Marketplace.

Tests cover:
- MarketplacePlugin dataclass (serialization, compatibility)
- MarketplaceIndex parsing
- MarketplaceClient (search, browse, cache, fetch, submissions)
"""

import json
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.plugins.marketplace import (
    DEFAULT_CACHE_TTL_SECONDS,
    VALID_PLUGIN_TYPES,
    MarketplaceClient,
    MarketplaceIndex,
    MarketplacePlugin,
    MarketplaceSearchResult,
    MarketplaceUnavailableError,
    VerificationStatus,
    _compute_relevance,
    _parse_version,
    _slugify,
    _version_in_range,
)


# --- Sample data ---

SAMPLE_PLUGIN_DICT = {
    "name": "DeFi Flash Loan Detector",
    "slug": "defi-flash-loan",
    "pypi_package": "miesc-defi-flash-loan",
    "version": "1.2.0",
    "plugin_type": "detector",
    "description": "Detects flash loan attack vulnerabilities in DeFi contracts",
    "author": "Security Researcher",
    "author_email": "dev@example.com",
    "homepage": "https://github.com/user/miesc-defi-flash-loan",
    "repository": "https://github.com/user/miesc-defi-flash-loan",
    "license": "MIT",
    "tags": ["defi", "flash-loan", "security", "lending"],
    "min_miesc_version": "4.5.0",
    "max_miesc_version": None,
    "verification_status": "community",
    "added_at": "2026-01-15T10:00:00Z",
    "updated_at": "2026-02-01T12:00:00Z",
}

SAMPLE_PLUGIN_DICT_2 = {
    "name": "Reentrancy Guard Checker",
    "slug": "reentrancy-guard",
    "pypi_package": "miesc-reentrancy-guard",
    "version": "2.0.0",
    "plugin_type": "detector",
    "description": "Verifies reentrancy guard patterns in contracts",
    "author": "Audit Team",
    "tags": ["security", "reentrancy"],
    "min_miesc_version": "5.0.0",
    "verification_status": "verified",
}

SAMPLE_PLUGIN_DICT_3 = {
    "name": "Custom PDF Reporter",
    "slug": "pdf-reporter",
    "pypi_package": "miesc-pdf-reporter",
    "version": "0.5.0",
    "plugin_type": "reporter",
    "description": "Generate PDF audit reports with custom branding",
    "author": "Report Builder",
    "tags": ["report", "pdf", "branding"],
    "min_miesc_version": "4.0.0",
    "max_miesc_version": "5.9.9",
    "verification_status": "experimental",
}

SAMPLE_INDEX_DICT = {
    "version": "1.0",
    "updated_at": "2026-02-02T00:00:00Z",
    "plugins": [SAMPLE_PLUGIN_DICT, SAMPLE_PLUGIN_DICT_2, SAMPLE_PLUGIN_DICT_3],
}


# --- Fixtures ---


@pytest.fixture
def sample_plugin():
    return MarketplacePlugin.from_dict(SAMPLE_PLUGIN_DICT)


@pytest.fixture
def sample_index():
    return MarketplaceIndex.from_dict(SAMPLE_INDEX_DICT)


@pytest.fixture
def cache_path(tmp_path):
    return tmp_path / "marketplace_cache.json"


@pytest.fixture
def client(cache_path):
    return MarketplaceClient(
        index_url="https://example.com/index.json",
        cache_path=cache_path,
        cache_ttl_seconds=3600,
        miesc_version="5.0.3",
    )


@pytest.fixture
def client_with_index(client, sample_index):
    """Client with a pre-loaded index (no network needed)."""
    client._index = sample_index
    return client


# =====================
# MarketplacePlugin
# =====================


class TestMarketplacePlugin:
    def test_from_dict(self, sample_plugin):
        assert sample_plugin.name == "DeFi Flash Loan Detector"
        assert sample_plugin.slug == "defi-flash-loan"
        assert sample_plugin.pypi_package == "miesc-defi-flash-loan"
        assert sample_plugin.version == "1.2.0"
        assert sample_plugin.plugin_type == "detector"
        assert sample_plugin.author == "Security Researcher"
        assert sample_plugin.verification_status == VerificationStatus.COMMUNITY
        assert "defi" in sample_plugin.tags
        assert sample_plugin.min_miesc_version == "4.5.0"
        assert sample_plugin.max_miesc_version is None

    def test_from_dict_defaults(self):
        minimal = {"name": "Test", "slug": "test", "pypi_package": "miesc-test",
                    "version": "1.0.0", "plugin_type": "detector",
                    "description": "A test", "author": "Dev"}
        plugin = MarketplacePlugin.from_dict(minimal)
        assert plugin.author_email == ""
        assert plugin.homepage == ""
        assert plugin.tags == []
        assert plugin.min_miesc_version == "4.0.0"
        assert plugin.verification_status == VerificationStatus.COMMUNITY

    def test_from_dict_invalid_verification_status(self):
        data = {**SAMPLE_PLUGIN_DICT, "verification_status": "invalid"}
        plugin = MarketplacePlugin.from_dict(data)
        assert plugin.verification_status == VerificationStatus.COMMUNITY

    def test_to_dict(self, sample_plugin):
        d = sample_plugin.to_dict()
        assert d["name"] == "DeFi Flash Loan Detector"
        assert d["slug"] == "defi-flash-loan"
        assert d["verification_status"] == "community"
        assert d["author_email"] == "dev@example.com"
        assert d["homepage"] == "https://github.com/user/miesc-defi-flash-loan"

    def test_to_dict_omits_empty_optional(self):
        plugin = MarketplacePlugin(
            name="Test", slug="test", pypi_package="miesc-test",
            version="1.0.0", plugin_type="detector",
            description="A test", author="Dev",
        )
        d = plugin.to_dict()
        assert "author_email" not in d
        assert "homepage" not in d
        assert "repository" not in d
        assert "max_miesc_version" not in d

    def test_roundtrip(self, sample_plugin):
        d = sample_plugin.to_dict()
        restored = MarketplacePlugin.from_dict(d)
        assert restored.name == sample_plugin.name
        assert restored.slug == sample_plugin.slug
        assert restored.version == sample_plugin.version

    def test_is_compatible_within_range(self, sample_plugin):
        assert sample_plugin.is_compatible("5.0.0") is True
        assert sample_plugin.is_compatible("4.5.0") is True
        assert sample_plugin.is_compatible("6.0.0") is True

    def test_is_compatible_below_min(self, sample_plugin):
        assert sample_plugin.is_compatible("4.4.0") is False
        assert sample_plugin.is_compatible("3.0.0") is False

    def test_is_compatible_with_max(self):
        plugin = MarketplacePlugin.from_dict(SAMPLE_PLUGIN_DICT_3)
        assert plugin.is_compatible("5.0.0") is True
        assert plugin.is_compatible("5.9.9") is True
        assert plugin.is_compatible("6.0.0") is False
        assert plugin.is_compatible("3.0.0") is False


# =====================
# MarketplaceIndex
# =====================


class TestMarketplaceIndex:
    def test_parse_index(self, sample_index):
        assert sample_index.version == "1.0"
        assert len(sample_index.plugins) == 3
        assert sample_index.plugins[0].slug == "defi-flash-loan"
        assert sample_index.plugins[1].slug == "reentrancy-guard"

    def test_empty_index(self):
        idx = MarketplaceIndex.from_dict({"version": "1.0", "updated_at": "", "plugins": []})
        assert idx.plugins == []
        assert idx.version == "1.0"

    def test_missing_plugins_key(self):
        idx = MarketplaceIndex.from_dict({"version": "1.0"})
        assert idx.plugins == []

    def test_to_dict(self, sample_index):
        d = sample_index.to_dict()
        assert d["version"] == "1.0"
        assert len(d["plugins"]) == 3
        assert d["plugins"][0]["slug"] == "defi-flash-loan"

    def test_roundtrip(self, sample_index):
        d = sample_index.to_dict()
        restored = MarketplaceIndex.from_dict(d)
        assert len(restored.plugins) == len(sample_index.plugins)
        assert restored.version == sample_index.version


# =====================
# Helper functions
# =====================


class TestHelpers:
    def test_parse_version(self):
        assert _parse_version("5.0.3") == (5, 0, 3)
        assert _parse_version("4.10.0") == (4, 10, 0)
        assert _parse_version("invalid") == (0, 0, 0)
        assert _parse_version("") == (0, 0, 0)

    def test_version_in_range(self):
        assert _version_in_range("5.0.0", "4.0.0", None) is True
        assert _version_in_range("3.0.0", "4.0.0", None) is False
        assert _version_in_range("5.0.0", "4.0.0", "6.0.0") is True
        assert _version_in_range("7.0.0", "4.0.0", "6.0.0") is False
        assert _version_in_range("5.0.0", None, None) is True

    def test_slugify(self):
        assert _slugify("Flash Loan Detector") == "flash-loan-detector"
        assert _slugify("My-Plugin_v2") == "my-plugin-v2"
        assert _slugify("  spaces  ") == "spaces"

    def test_compute_relevance_exact_match(self):
        plugin = MarketplacePlugin.from_dict(SAMPLE_PLUGIN_DICT)
        score = _compute_relevance(plugin, "defi-flash-loan", ["defi-flash-loan"])
        assert score > 0

    def test_compute_relevance_tag_match(self):
        plugin = MarketplacePlugin.from_dict(SAMPLE_PLUGIN_DICT)
        score = _compute_relevance(plugin, "lending", ["lending"])
        assert score > 0

    def test_compute_relevance_no_match(self):
        plugin = MarketplacePlugin.from_dict(SAMPLE_PLUGIN_DICT)
        score = _compute_relevance(plugin, "zzzzzzz", ["zzzzzzz"])
        assert score == 0

    def test_compute_relevance_verified_boost(self):
        verified = MarketplacePlugin.from_dict(SAMPLE_PLUGIN_DICT_2)
        community = MarketplacePlugin.from_dict({
            **SAMPLE_PLUGIN_DICT_2,
            "verification_status": "community",
        })
        # Same plugin, only verification status differs
        score_v = _compute_relevance(verified, "security", ["security"])
        score_c = _compute_relevance(community, "security", ["security"])
        # Verified gets 1.2x boost
        assert score_v > score_c
        assert score_v == pytest.approx(score_c * 1.2)


# =====================
# MarketplaceClient - Search
# =====================


class TestMarketplaceSearch:
    def test_search_by_name(self, client_with_index):
        results = client_with_index.search("flash loan")
        assert len(results) >= 1
        assert results[0].plugin.slug == "defi-flash-loan"

    def test_search_by_tag(self, client_with_index):
        results = client_with_index.search("reentrancy")
        slugs = [r.plugin.slug for r in results]
        assert "reentrancy-guard" in slugs

    def test_search_by_description(self, client_with_index):
        results = client_with_index.search("PDF audit")
        slugs = [r.plugin.slug for r in results]
        assert "pdf-reporter" in slugs

    def test_search_filter_by_type(self, client_with_index):
        results = client_with_index.search("security", plugin_type="reporter")
        # Only reporters should match
        for r in results:
            assert r.plugin.plugin_type == "reporter"

    def test_search_filter_by_tags(self, client_with_index):
        results = client_with_index.search("", tags=["defi"])
        assert all("defi" in r.plugin.tags for r in results)

    def test_search_filter_by_verification(self, client_with_index):
        results = client_with_index.search(
            "", verification_status=VerificationStatus.VERIFIED
        )
        assert all(
            r.plugin.verification_status == VerificationStatus.VERIFIED
            for r in results
        )

    def test_search_compatible_only(self, client_with_index):
        # Client is v5.0.3, plugin_dict_2 requires 5.0.0+ -> compatible
        results = client_with_index.search("reentrancy", compatible_only=True)
        slugs = [r.plugin.slug for r in results]
        assert "reentrancy-guard" in slugs

    def test_search_incompatible_excluded(self):
        client = MarketplaceClient(
            cache_path=Path("/dev/null"),
            miesc_version="3.0.0",  # Too old for all plugins
        )
        index = MarketplaceIndex.from_dict(SAMPLE_INDEX_DICT)
        client._index = index
        results = client.search("security", compatible_only=True)
        assert len(results) == 0

    def test_search_no_results(self, client_with_index):
        results = client_with_index.search("nonexistent_xyz_plugin")
        assert len(results) == 0

    def test_search_sorted_by_relevance(self, client_with_index):
        results = client_with_index.search("security")
        if len(results) > 1:
            for i in range(len(results) - 1):
                assert results[i].relevance_score >= results[i + 1].relevance_score


# =====================
# MarketplaceClient - Browse
# =====================


class TestMarketplaceBrowse:
    def test_browse_all(self, client_with_index):
        plugins = client_with_index.browse()
        assert len(plugins) == 3

    def test_browse_filter_by_type(self, client_with_index):
        plugins = client_with_index.browse(plugin_type="detector")
        assert len(plugins) == 2
        assert all(p.plugin_type == "detector" for p in plugins)

    def test_browse_filter_by_verification(self, client_with_index):
        plugins = client_with_index.browse(
            verification_status=VerificationStatus.VERIFIED
        )
        assert len(plugins) == 1
        assert plugins[0].slug == "reentrancy-guard"

    def test_browse_pagination(self, client_with_index):
        page1 = client_with_index.browse(per_page=2, page=1)
        page2 = client_with_index.browse(per_page=2, page=2)
        assert len(page1) == 2
        assert len(page2) == 1

    def test_browse_pagination_empty_page(self, client_with_index):
        page = client_with_index.browse(per_page=20, page=99)
        assert len(page) == 0


# =====================
# MarketplaceClient - Get
# =====================


class TestMarketplaceGet:
    def test_get_plugin_by_slug(self, client_with_index):
        plugin = client_with_index.get_plugin("defi-flash-loan")
        assert plugin is not None
        assert plugin.name == "DeFi Flash Loan Detector"

    def test_get_plugin_not_found(self, client_with_index):
        plugin = client_with_index.get_plugin("nonexistent")
        assert plugin is None

    def test_get_plugin_by_package(self, client_with_index):
        plugin = client_with_index.get_plugin_by_package("miesc-defi-flash-loan")
        assert plugin is not None
        assert plugin.slug == "defi-flash-loan"

    def test_get_plugin_by_package_not_found(self, client_with_index):
        plugin = client_with_index.get_plugin_by_package("nonexistent")
        assert plugin is None


# =====================
# MarketplaceClient - Compatibility
# =====================


class TestMarketplaceCompatibility:
    def test_check_compatible(self, client_with_index):
        plugin = client_with_index.get_plugin("defi-flash-loan")
        result = client_with_index.check_compatibility(plugin)
        assert result["compatible"] is True
        assert "Compatible" in result["message"]

    def test_check_incompatible(self):
        client = MarketplaceClient(
            cache_path=Path("/dev/null"),
            miesc_version="3.0.0",
        )
        plugin = MarketplacePlugin.from_dict(SAMPLE_PLUGIN_DICT)
        result = client.check_compatibility(plugin)
        assert result["compatible"] is False
        assert "Requires" in result["message"]

    def test_get_install_command(self, client_with_index):
        plugin = client_with_index.get_plugin("defi-flash-loan")
        cmd = client_with_index.get_install_command(plugin)
        assert cmd == "pip install miesc-defi-flash-loan"


# =====================
# MarketplaceClient - Cache
# =====================


class TestMarketplaceCache:
    def test_cache_save_load(self, client, sample_index):
        client._save_cache(sample_index)
        loaded = client._load_cache()
        assert loaded is not None
        assert len(loaded.plugins) == 3
        assert loaded.plugins[0].slug == "defi-flash-loan"

    def test_cache_validity(self, client, sample_index):
        client._save_cache(sample_index)
        assert client._is_cache_valid() is True

    def test_cache_expired(self, client, sample_index):
        client._save_cache(sample_index)
        # Modify cache to be old
        cache_data = json.loads(client.cache_path.read_text())
        old_time = datetime.now(timezone.utc) - timedelta(seconds=7200)
        cache_data["cached_at"] = old_time.isoformat()
        client.cache_path.write_text(json.dumps(cache_data))
        assert client._is_cache_valid() is False

    def test_cache_missing(self, client):
        assert client._is_cache_valid() is False

    def test_load_cache_missing_file(self, client):
        assert client._load_cache() is None

    def test_load_cache_corrupt_json(self, client):
        client.cache_path.parent.mkdir(parents=True, exist_ok=True)
        client.cache_path.write_text("not json")
        assert client._load_cache() is None

    def test_cache_directory_created(self, tmp_path):
        deep_path = tmp_path / "a" / "b" / "cache.json"
        client = MarketplaceClient(cache_path=deep_path, miesc_version="5.0.3")
        index = MarketplaceIndex.from_dict(SAMPLE_INDEX_DICT)
        client._save_cache(index)
        assert deep_path.exists()


# =====================
# MarketplaceClient - Fetch
# =====================


class TestMarketplaceFetch:
    def test_fetch_uses_cache_when_valid(self, client, sample_index):
        client._save_cache(sample_index)
        # Should not make network call
        index = client.fetch_index()
        assert len(index.plugins) == 3

    def test_fetch_returns_memory_index(self, client_with_index):
        # Already loaded in memory, no cache or network needed
        index = client_with_index.fetch_index()
        assert len(index.plugins) == 3

    @patch("src.plugins.marketplace.urllib.request.urlopen")
    def test_fetch_remote_success(self, mock_urlopen, client):
        response_data = json.dumps(SAMPLE_INDEX_DICT).encode()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = response_data
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        index = client.fetch_index(force_refresh=True)
        assert len(index.plugins) == 3
        mock_urlopen.assert_called_once()

    @patch("src.plugins.marketplace.urllib.request.urlopen")
    def test_fetch_remote_failure_with_cache_fallback(self, mock_urlopen, client, sample_index):
        # Save cache first
        client._save_cache(sample_index)
        # Network fails
        mock_urlopen.side_effect = urllib.error.URLError("Network error")

        index = client.fetch_index(force_refresh=True)
        assert len(index.plugins) == 3  # Falls back to cache

    @patch("src.plugins.marketplace.urllib.request.urlopen")
    def test_fetch_remote_failure_no_cache(self, mock_urlopen, client):
        mock_urlopen.side_effect = urllib.error.URLError("Network error")
        with pytest.raises(MarketplaceUnavailableError):
            client.fetch_index(force_refresh=True)

    @patch("src.plugins.marketplace.urllib.request.urlopen")
    def test_fetch_remote_timeout(self, mock_urlopen, client):
        mock_urlopen.side_effect = TimeoutError("Timeout")
        with pytest.raises(MarketplaceUnavailableError):
            client.fetch_index(force_refresh=True)

    @patch("src.plugins.marketplace.urllib.request.urlopen")
    def test_fetch_remote_bad_json(self, mock_urlopen, client):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"not json"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        with pytest.raises(Exception):
            client.fetch_index(force_refresh=True)


# =====================
# Submission
# =====================


class TestMarketplaceSubmission:
    def test_generate_submission(self, client_with_index):
        entry = client_with_index.generate_submission(
            name="My Detector",
            pypi_package="miesc-my-detector",
            version="1.0.0",
            plugin_type="detector",
            description="Detects things",
            author="Dev",
            tags=["security"],
        )
        assert entry["name"] == "My Detector"
        assert entry["slug"] == "my-detector"
        assert entry["pypi_package"] == "miesc-my-detector"
        assert entry["verification_status"] == "community"
        assert entry["added_at"] != ""

    def test_validate_submission_valid(self, client_with_index):
        entry = client_with_index.generate_submission(
            name="New Plugin",
            pypi_package="miesc-new-plugin",
            version="1.0.0",
            plugin_type="detector",
            description="A new plugin",
            author="Author",
        )
        errors = client_with_index.validate_submission(entry)
        assert errors == []

    def test_validate_submission_missing_fields(self, client_with_index):
        entry = {"name": "Test"}
        errors = client_with_index.validate_submission(entry)
        assert any("slug" in e for e in errors)
        assert any("pypi_package" in e for e in errors)

    def test_validate_submission_bad_slug(self, client_with_index):
        entry = client_with_index.generate_submission(
            name="T", pypi_package="miesc-t", version="1.0.0",
            plugin_type="detector", description="Test", author="Dev",
        )
        # Single char slug won't match the regex requiring at least 2 chars
        errors = client_with_index.validate_submission(entry)
        assert any("slug" in e.lower() for e in errors)

    def test_validate_submission_bad_version(self, client_with_index):
        entry = {
            "name": "Test", "slug": "test-plugin", "pypi_package": "miesc-test",
            "version": "bad", "plugin_type": "detector",
            "description": "Test desc", "author": "Dev",
        }
        errors = client_with_index.validate_submission(entry)
        assert any("version" in e.lower() for e in errors)

    def test_validate_submission_bad_type(self, client_with_index):
        entry = {
            "name": "Test", "slug": "test-plugin", "pypi_package": "miesc-test",
            "version": "1.0.0", "plugin_type": "invalid_type",
            "description": "Test desc", "author": "Dev",
        }
        errors = client_with_index.validate_submission(entry)
        assert any("plugin_type" in e for e in errors)

    def test_validate_submission_no_miesc_prefix(self, client_with_index):
        entry = {
            "name": "Test", "slug": "test-plugin", "pypi_package": "not-miesc",
            "version": "1.0.0", "plugin_type": "detector",
            "description": "Test desc", "author": "Dev",
        }
        errors = client_with_index.validate_submission(entry)
        assert any("miesc-" in e for e in errors)

    def test_validate_submission_duplicate_slug(self, client_with_index):
        entry = {
            "name": "Test", "slug": "defi-flash-loan",
            "pypi_package": "miesc-duplicate", "version": "1.0.0",
            "plugin_type": "detector", "description": "Duplicate slug",
            "author": "Dev",
        }
        errors = client_with_index.validate_submission(entry)
        assert any("already exists" in e for e in errors)


# =====================
# Integration
# =====================


class TestMarketplaceIntegration:
    @patch("src.plugins.marketplace.urllib.request.urlopen")
    def test_full_search_workflow(self, mock_urlopen, cache_path):
        """Test complete workflow: fetch -> search -> get details."""
        response_data = json.dumps(SAMPLE_INDEX_DICT).encode()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = response_data
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = MarketplaceClient(
            cache_path=cache_path, miesc_version="5.0.3"
        )

        # Search
        results = client.search("flash loan")
        assert len(results) >= 1
        assert results[0].plugin.slug == "defi-flash-loan"

        # Get details
        plugin = client.get_plugin("defi-flash-loan")
        assert plugin is not None
        assert plugin.version == "1.2.0"

        # Check compatibility
        compat = client.check_compatibility(plugin)
        assert compat["compatible"] is True

        # Get install command
        cmd = client.get_install_command(plugin)
        assert "miesc-defi-flash-loan" in cmd

        # Cache should exist
        assert cache_path.exists()

    def test_client_default_init(self, cache_path):
        """Test client initializes with defaults."""
        client = MarketplaceClient(cache_path=cache_path)
        assert client.cache_ttl_seconds == DEFAULT_CACHE_TTL_SECONDS
        assert "github" in client.index_url
