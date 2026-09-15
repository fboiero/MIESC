import json

from miesc.cli.commands.evaluate import _load_ground_truth, _normalize_category


def test_smartbugs_access_control_aliases_from_intelligence_patterns():
    assert _normalize_category("incorrect_constructor_name") == "access_control"
    assert _normalize_category("delegatecall_unprotected") == "access_control"
    assert _normalize_category("delegatecall_to_untrusted") == "access_control"
    assert _normalize_category("mapping_write_arbitrary") == "access_control"
    assert _normalize_category("constructor_mismatch") == "access_control"
    assert _normalize_category("withdraw_no_balance_update") == "access_control"
    assert _normalize_category("confused_comparison") == "access_control"


class TestTimestampNotShadowedByRandomness:
    """MEJORAS2.md #4 — found while measuring the corpus-completion fix's real
    impact: once Slither could actually compile a real multi-file contract
    (MinterContract.sol), its own "timestamp" detector (SWC-116, unambiguously
    time_manipulation) started resolving to bad_randomness instead. Cause:
    bad_randomness's CATEGORY_ALIASES included "block.timestamp", which
    normalizes to "block_timestamp" — and the substring check matched
    "timestamp" as a substring of that before time_manipulation's own exact
    "timestamp" alias was ever reached (bad_randomness is checked first)."""

    def test_bare_timestamp_type_is_time_manipulation(self):
        assert _normalize_category("timestamp") == "time_manipulation"

    def test_blockhash_is_still_bad_randomness(self):
        assert _normalize_category("blockhash") == "bad_randomness"

    def test_genuine_bad_randomness_types_unaffected(self):
        assert _normalize_category("bad_randomness") == "bad_randomness"
        assert _normalize_category("weak-randomness") == "bad_randomness"
        assert _normalize_category("weak-prng") == "bad_randomness"


class TestModernCategories:
    """MEJORAS2.md #2 — categories real 2022+ DeFi audits actually report,
    absent from SmartBugs-curated's ~2018-2020 taxonomy."""

    def test_oracle_alias_and_keyword_fallback(self):
        assert _normalize_category("oracle_manipulation") == "oracle"
        assert _normalize_category("finding", description="stale price feed") == "oracle"

    def test_rounding_alias_and_keyword_fallback(self):
        assert _normalize_category("loss_of_precision") == "rounding"
        assert _normalize_category("finding", description="loss of precision") == "rounding"

    def test_business_logic_keyword_fallback(self):
        assert (
            _normalize_category("finding", description="breaks a core invariant")
            == "business_logic"
        )

    def test_fee_on_transfer_alias(self):
        assert _normalize_category("fee_on_transfer") == "fee_on_transfer"

    def test_erc4626_alias(self):
        assert _normalize_category("erc4626") == "erc4626"

    def test_classic_category_not_shadowed_by_new_keywords(self):
        # "timestamp" must still resolve to the classic category, not get
        # reclassified by the newer oracle/rounding keyword fallbacks.
        assert (
            _normalize_category("finding", description="block.timestamp dependence")
            == "time_manipulation"
        )


class TestLocationPathLeakage:
    """MEJORAS2.md #5b — Slither (and others) embed the analyzed file's own
    path in finding descriptions as a markdown location link. SmartBugs-
    curated's corpus_dir/category_name/*.sol layout means that path contains
    the ground-truth category name, so an unrelated finding (e.g. a naming
    lint) on a file under bad_randomness/ used to get miscategorized as
    bad_randomness purely because "randomness" is a substring of the folder
    name in the path — found while building the ML classifier's training
    set (every folder-based label was silently leaking into "detection")."""

    def test_naming_convention_on_bad_randomness_folder_not_misclassified(self):
        desc = (
            "Variable [BlackJack.BLACKJACK]"
            "(benchmarks/datasets/smartbugs-curated/dataset/bad_randomness/"
            "blackjack.sol#L51) is not in mixedCase\n"
        )
        assert _normalize_category("naming-convention", description=desc) is None

    def test_unrelated_finding_on_reentrancy_folder_not_misclassified(self):
        desc = (
            "Pragma version [^0.8.20]"
            "(benchmarks/datasets/smartbugs-curated/dataset/reentrancy/"
            "foo.sol#L1) is not specific\n"
        )
        assert _normalize_category("solc-version", description=desc) is None

    def test_unrelated_finding_on_unchecked_calls_folder_not_misclassified(self):
        desc = (
            "Constant [Foo.BAR]"
            "(benchmarks/datasets/smartbugs-curated/dataset/"
            "unchecked_low_level_calls/foo.sol#L3) is not in UPPER_CASE\n"
        )
        assert _normalize_category("naming-convention", description=desc) is None

    def test_genuine_keyword_in_bracketed_text_still_matches(self):
        # The symbol name (bracket text) is kept, only the path is dropped —
        # a real reentrancy-flavored description should still classify.
        desc = "Possible reentrancy in [Foo.withdraw](some/path/Foo.sol#L10)"
        assert _normalize_category("finding", description=desc) == "reentrancy"


class TestNoiseCheckTypesNeverMatchByKeyword:
    """Found while sanity-checking the smartbugs-curated closing benchmark:
    Slither's solc-version check cites a fixed list of "known severe issues"
    by compiler-bug *name* as routine upgrade advice — one of those names is
    literally "MemoryArrayCreationOverflow", so the keyword fallback matched
    "overflow" and miscategorized ~50% of all solc-version findings (measured
    on a real 40-contract sample) as "arithmetic". A version/style lint can
    never legitimately be a vulnerability category, so these types should
    never reach keyword matching regardless of their advice text."""

    def test_solc_version_overflow_boilerplate_not_misclassified(self):
        desc = (
            "Version constraint ^0.4.15 contains known severe issues "
            "(https://solidity.readthedocs.io/en/latest/bugs.html)\n"
            "\t- MemoryArrayCreationOverflow\n\t- DirtyBytesArrayToStorage\n"
        )
        assert _normalize_category("solc-version", description=desc) is None

    def test_naming_convention_never_matches_by_keyword(self):
        assert _normalize_category("naming-convention", description="reentrancy-like name") is None

    def test_genuine_arithmetic_type_still_matches(self):
        assert _normalize_category("integer-overflow") == "arithmetic"

    def test_genuine_arithmetic_keyword_fallback_still_works(self):
        assert (
            _normalize_category("finding", description="classic integer overflow bug")
            == "arithmetic"
        )


class TestUnknownIsNotOther:
    """solodit-real has zero ground-truth findings categorized "other" -
    several LLM adapters (llamaaudit, oyente, peculiar, ...) default
    type/category to the literal string "unknown" when parsing fails, with
    no title/description content to fall back on. "unknown" must not
    resolve to "other" - that would count pure parsing-failure noise as a
    matched category."""

    def test_unknown_type_does_not_match_other(self):
        assert _normalize_category("unknown") is None

    def test_genuine_other_alias_still_matches(self):
        assert _normalize_category("other") == "other"
        assert _normalize_category("unclassified") == "other"


class TestSlitherInformationalReentrancyIsNotReentrancy:
    """Slither's own docs classify reentrancy-benign/reentrancy-events as
    informational, no-security-impact patterns (event emitted after an
    external call, or a state write with no exploitable read-before-call
    path) - distinct from reentrancy-eth, the real exploitable one. Found
    on solodit-real's expanded corpus: VaultFactory.sol alone contributed
    5 of these as "reentrancy" false positives with zero real reentrancy
    in its ground truth (10.0% precision, 1 TP / 9 FP overall)."""

    def test_reentrancy_benign_is_not_a_match(self):
        assert _normalize_category("reentrancy-benign") is None
        assert _normalize_category("reentrancy_benign") is None

    def test_reentrancy_events_is_not_a_match(self):
        assert _normalize_category("reentrancy-events") is None
        assert _normalize_category("reentrancy_events") is None

    def test_genuine_reentrancy_types_still_match(self):
        assert _normalize_category("reentrancy-eth") == "reentrancy"
        assert _normalize_category("reentrancy-no-eth") == "reentrancy"
        assert _normalize_category("reentrancy") == "reentrancy"


class TestGroundTruthJsonManifest:
    """MEJORAS2.md #1 — Solodit-sourced per-finding ground truth, an
    alternative to SmartBugs-curated's one-category-per-folder inference."""

    def test_loads_and_aggregates_categories_per_file(self, tmp_path):
        (tmp_path / "Vault.sol").write_text("contract Vault {}")
        (tmp_path / "ground_truth.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {"file": "Vault.sol", "category": "oracle"},
                        {"file": "Vault.sol", "category": "rounding"},
                    ]
                }
            )
        )

        gt = _load_ground_truth(tmp_path)

        assert gt == {"Vault.sol": {"oracle", "rounding"}}

    def test_skips_findings_whose_file_does_not_exist(self, tmp_path):
        (tmp_path / "ground_truth.json").write_text(
            json.dumps({"findings": [{"file": "Missing.sol", "category": "oracle"}]})
        )

        gt = _load_ground_truth(tmp_path)

        assert gt == {}

    def test_manifest_takes_precedence_over_folder_structure(self, tmp_path):
        # A folder named "reentrancy" would normally be read as SmartBugs-style
        # ground truth — the manifest, when present, wins instead.
        (tmp_path / "reentrancy").mkdir()
        (tmp_path / "reentrancy" / "C.sol").write_text("contract C {}")
        (tmp_path / "ground_truth.json").write_text(
            json.dumps({"findings": [{"file": "reentrancy/C.sol", "category": "oracle"}]})
        )

        gt = _load_ground_truth(tmp_path)

        assert gt == {"reentrancy/C.sol": {"oracle"}}
