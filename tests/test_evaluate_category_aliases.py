from miesc.cli.commands.evaluate import _normalize_category


def test_smartbugs_access_control_aliases_from_intelligence_patterns():
    assert _normalize_category("incorrect_constructor_name") == "access_control"
    assert _normalize_category("delegatecall_unprotected") == "access_control"
    assert _normalize_category("delegatecall_to_untrusted") == "access_control"
    assert _normalize_category("mapping_write_arbitrary") == "access_control"
    assert _normalize_category("constructor_mismatch") == "access_control"
    assert _normalize_category("withdraw_no_balance_update") == "access_control"
    assert _normalize_category("confused_comparison") == "access_control"


def test_informational_detectors_never_map_to_a_category():
    """Slither `solc-version` describes known compiler bugs ("overflow"); the keyword
    fallback must not turn that description into an arithmetic finding."""
    from miesc.cli.commands.evaluate import _normalize_category

    desc = "Pragma version^0.4.24 allows old versions with known severe issues: overflow in ..."
    assert _normalize_category("solc-version", "Incorrect versions of Solidity", desc) is None
    assert _normalize_category("unspecific-solidity-pragma", "", "overflow") is None
    # genuine arithmetic types still map
    assert _normalize_category("integer-overflow") == "arithmetic"
