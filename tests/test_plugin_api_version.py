"""
Tests for the versioned Plugin API contract (miesc/plugins/version.py).

Covers the semantic-versioning compatibility matrix used to decide whether a
community plugin built against one Plugin API version can be loaded by the
current host.
"""

from __future__ import annotations

import pytest

from miesc.plugins.version import (
    PLUGIN_API_VERSION,
    ApiCompatStatus,
    check_api_compatibility,
    parse_api_version,
)


class TestParseApiVersion:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("1.0.0", (1, 0, 0)),
            ("2.3.4", (2, 3, 4)),
            ("1.10.99", (1, 10, 99)),
            ("1.0.0-rc1", (1, 0, 0)),  # pre-release tail ignored
            ("1.2.3+build", (1, 2, 3)),
        ],
    )
    def test_valid_semver(self, raw, expected):
        assert parse_api_version(raw) == expected

    @pytest.mark.parametrize("raw", ["", "abc", "1", "1.2", "v1.0.0", None, 1.0])
    def test_invalid_semver(self, raw):
        assert parse_api_version(raw) is None


class TestApiCompatibilityMatrix:
    """Table-driven compatibility matrix: (plugin, host) -> status."""

    @pytest.mark.parametrize(
        "plugin,host,status",
        [
            # Same major, same minor -> compatible
            ("1.0.0", "1.0.0", ApiCompatStatus.COMPATIBLE),
            # Same major, patch differences ignored -> compatible
            ("1.0.5", "1.0.0", ApiCompatStatus.COMPATIBLE),
            ("1.0.0", "1.0.9", ApiCompatStatus.COMPATIBLE),
            # Same major, plugin older minor -> host is backward compatible
            ("1.2.0", "1.5.0", ApiCompatStatus.COMPATIBLE),
            # Same major, plugin NEWER minor -> host lacks features -> reject
            ("1.5.0", "1.2.0", ApiCompatStatus.INCOMPATIBLE_MINOR),
            ("1.1.0", "1.0.0", ApiCompatStatus.INCOMPATIBLE_MINOR),
            # Newer major (plugin ahead) -> reject
            ("2.0.0", "1.0.0", ApiCompatStatus.INCOMPATIBLE_MAJOR),
            # Older major (plugin behind) -> reject
            ("1.0.0", "2.0.0", ApiCompatStatus.INCOMPATIBLE_MAJOR),
            # Invalid declared version -> invalid
            ("bogus", "1.0.0", ApiCompatStatus.INVALID),
            ("", "1.0.0", ApiCompatStatus.INVALID),
        ],
    )
    def test_matrix(self, plugin, host, status):
        result = check_api_compatibility(plugin, host)
        assert result.status is status
        assert result.compatible == (status == ApiCompatStatus.COMPATIBLE)

    def test_default_host_is_current_api(self):
        result = check_api_compatibility(PLUGIN_API_VERSION)
        assert result.compatible
        assert result.host_api_version == PLUGIN_API_VERSION

    def test_major_message_upgrade_hint_when_plugin_ahead(self):
        result = check_api_compatibility("2.0.0", "1.0.0")
        assert "Upgrade MIESC" in result.message

    def test_major_message_update_plugin_hint_when_plugin_behind(self):
        result = check_api_compatibility("1.0.0", "2.0.0")
        assert "Update the plugin" in result.message

    def test_minor_message_names_required_version(self):
        result = check_api_compatibility("1.5.0", "1.2.0")
        assert "1.5" in result.message
        assert result.status is ApiCompatStatus.INCOMPATIBLE_MINOR

    def test_invalid_message_mentions_semver(self):
        result = check_api_compatibility("not-a-version")
        assert "invalid" in result.message.lower()

    def test_result_to_dict_roundtrip(self):
        result = check_api_compatibility("1.0.0", "1.0.0")
        data = result.to_dict()
        assert data["compatible"] is True
        assert data["status"] == "compatible"
        assert data["plugin_api_version"] == "1.0.0"
        assert data["host_api_version"] == "1.0.0"
