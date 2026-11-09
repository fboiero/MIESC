"""Coverage for the pure version/compatibility logic in miesc.plugins.manager."""

from miesc.plugins.manager import (
    CompatibilityInfo,
    CompatibilityStatus,
    PluginManager,
    VersionConstraint,
    compare_versions,
)


class TestCompareVersions:
    def test_ordering(self):
        assert compare_versions("4.0.0", "5.0.0") == -1
        assert compare_versions("5.0.0", "4.0.0") == 1
        assert compare_versions("4.2.0", "4.2.0") == 0

    def test_padding_and_alpha_suffix(self):
        assert compare_versions("4.2", "4.2.0") == 0  # padded
        assert compare_versions("4.3.3a1", "4.3.3") == 0  # alpha stripped to numeric


class TestVersionConstraint:
    def test_from_string_operators(self):
        assert VersionConstraint.from_string(">=4.0.0").min_version == "4.0.0"
        assert VersionConstraint.from_string(">4.0.0").min_inclusive is False
        c = VersionConstraint.from_string("<=5.0.0")
        assert c.max_version == "5.0.0" and c.max_inclusive is True
        assert VersionConstraint.from_string("<5.0.0").max_inclusive is False

    def test_from_string_exact_and_prefix(self):
        c = VersionConstraint.from_string("miesc==4.2.0")
        assert c.min_version == "4.2.0" and c.max_version == "4.2.0"

    def test_from_string_compatible_release(self):
        c = VersionConstraint.from_string("~=4.2.0")
        assert c.min_version == "4.2.0"
        assert c.max_version == "4.3.0"  # bumped minor, patch -> 0
        assert c.max_inclusive is False

    def test_from_string_range(self):
        c = VersionConstraint.from_string(">=4.0.0,<5.0.0")
        assert c.min_version == "4.0.0" and c.max_version == "5.0.0"

    def test_str_roundtrip_and_any(self):
        assert str(VersionConstraint.from_string(">=4.0.0,<5.0.0")) == ">=4.0.0, <5.0.0"
        assert str(VersionConstraint()) == "any"


class TestCompatibilityInfoStr:
    def test_all_statuses(self):
        assert str(CompatibilityInfo(status=CompatibilityStatus.COMPATIBLE)) == "compatible"
        assert "incompatible" in str(
            CompatibilityInfo(status=CompatibilityStatus.INCOMPATIBLE, message="too old")
        )
        assert "warning" in str(CompatibilityInfo(status=CompatibilityStatus.WARNING, message="py"))
        assert str(CompatibilityInfo(status=CompatibilityStatus.UNKNOWN)) == "unknown"


class TestValidateCompatibility:
    def _pm(self, version):
        pm = PluginManager()
        pm._miesc_version = version
        return pm

    def test_no_constraint_is_unknown(self):
        info = self._pm("4.5.0").validate_compatibility(requires_miesc=None)
        assert info.status == CompatibilityStatus.UNKNOWN

    def test_below_min_incompatible(self):
        info = self._pm("3.9.0").validate_compatibility(requires_miesc=">=4.0.0")
        assert info.status == CompatibilityStatus.INCOMPATIBLE

    def test_above_max_incompatible(self):
        info = self._pm("5.1.0").validate_compatibility(requires_miesc=">=4.0.0,<5.0.0")
        assert info.status == CompatibilityStatus.INCOMPATIBLE

    def test_within_range_compatible(self):
        info = self._pm("4.5.0").validate_compatibility(requires_miesc=">=4.0.0,<5.0.0")
        assert info.status == CompatibilityStatus.COMPATIBLE

    def test_exclusive_min_boundary(self):
        # current == min with a strict > constraint -> incompatible
        info = self._pm("4.0.0").validate_compatibility(requires_miesc=">4.0.0")
        assert info.status == CompatibilityStatus.INCOMPATIBLE
