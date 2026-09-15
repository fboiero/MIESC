"""
Tests for MEJORAS.md item #4: git-activity weighting on DeepAuditAgent's
attack-surface score, and the entry-point classification in xray_agent.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

from pathlib import Path

from miesc.agents.deep_audit_agent import DeepAuditAgent
from miesc.agents.xray_agent import _classify_entry_points, run_xray

CONTRACT_WITH_MIXED_ENTRY_POINTS = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Mixed {
    address owner;

    function deposit() public payable {}

    function withdraw() external {}

    function rescueFunds() external onlyOwner {}

    function _internalHelper() internal {}

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}
"""


class TestCountGitCommits:
    def test_tracked_file_in_this_repo_returns_positive_count(self):
        agent = DeepAuditAgent()
        # This repo's own README.md is tracked with real history.
        count = agent._count_git_commits(str(Path(__file__).resolve().parents[1] / "README.md"))
        assert count > 0

    def test_untracked_path_returns_zero(self, tmp_path):
        agent = DeepAuditAgent()
        path = tmp_path / "NotInGit.sol"
        path.write_text("contract C {}")
        assert agent._count_git_commits(str(path)) == 0

    def test_nonexistent_repo_dir_returns_zero(self):
        agent = DeepAuditAgent()
        assert agent._count_git_commits("/nonexistent/dir/Contract.sol") == 0


class TestAttackSurfaceGitWeighting:
    def test_default_zero_commits_matches_pre_existing_behavior(self):
        agent = DeepAuditAgent()
        score = agent._compute_attack_surface(
            entries=["withdraw", "deposit"], ext_calls=["x.call"], taint=[1]
        )
        score_explicit_zero = agent._compute_attack_surface(
            entries=["withdraw", "deposit"], ext_calls=["x.call"], taint=[1], git_activity_commits=0
        )
        assert score == score_explicit_zero

    def test_git_activity_increases_score_but_stays_capped(self):
        agent = DeepAuditAgent()
        base = agent._compute_attack_surface(["a", "b", "c"], ["x.call", "y.call"], [1, 2])
        weighted = agent._compute_attack_surface(
            ["a", "b", "c"], ["x.call", "y.call"], [1, 2], git_activity_commits=50
        )
        assert weighted > base
        assert weighted <= 100.0

    def test_empty_inputs_stay_zero_even_with_git_activity(self):
        agent = DeepAuditAgent()
        assert agent._compute_attack_surface([], [], [], git_activity_commits=999) == 0.0


class TestEntryPointClassification:
    def test_buckets_permissionless_role_gated_and_skips_internal(self, tmp_path):
        agent = DeepAuditAgent()
        cg, _, _ = agent._build_call_graph(CONTRACT_WITH_MIXED_ENTRY_POINTS)
        buckets = _classify_entry_points(cg)

        permissionless_names = {e["name"] for e in buckets["permissionless"]}
        admin_names = {e["name"] for e in buckets["admin"]}

        assert {"deposit", "withdraw"} <= permissionless_names
        assert "rescueFunds" in admin_names
        all_names = permissionless_names | admin_names | {e["name"] for e in buckets["role_gated"]}
        assert "_internalHelper" not in all_names

    def test_none_call_graph_returns_empty_buckets(self):
        buckets = _classify_entry_points(None)
        assert buckets == {"permissionless": [], "role_gated": [], "admin": []}


class TestRunXray:
    def test_run_xray_over_real_fixture(self):
        report = run_xray(["examples/contracts/DeFiVault.sol"])
        assert len(report["files"]) == 1
        file_report = report["files"][0]
        assert file_report["protocol_type"]
        assert 0 <= file_report["attack_surface_score"] <= 100
        assert file_report["entry_points"]["permissionless"]
        assert report["hotspots"]
