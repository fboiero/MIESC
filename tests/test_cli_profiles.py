from miesc.cli.utils import get_profile


def test_short_full_alias_resolves_to_thorough_profile():
    profile = get_profile("f")

    assert profile is not None
    assert profile["description"] == "Comprehensive analysis across configured layers"
    assert profile["layers"] == [1, 2, 3, 4, 5, 6, 7, 8, 9]


def test_audit_profile_uses_all_configured_layers():
    profile = get_profile("audit")

    assert profile is not None
    assert profile["layers"] == [1, 2, 3, 4, 5, 6, 7, 8, 9]
