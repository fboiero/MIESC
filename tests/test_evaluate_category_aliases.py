from miesc.cli.commands.evaluate import _normalize_category


def test_smartbugs_access_control_aliases_from_intelligence_patterns():
    assert _normalize_category("incorrect_constructor_name") == "access_control"
    assert _normalize_category("delegatecall_unprotected") == "access_control"
    assert _normalize_category("delegatecall_to_untrusted") == "access_control"
    assert _normalize_category("mapping_write_arbitrary") == "access_control"
    assert _normalize_category("constructor_mismatch") == "access_control"
    assert _normalize_category("withdraw_no_balance_update") == "access_control"
    assert _normalize_category("confused_comparison") == "access_control"
