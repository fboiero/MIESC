"""MissingAccessControl must look one call deep into internal helpers — Vyper has no
modifiers, so `self._check_admin()`-style helpers are the idiomatic way to share an
access check (Ronda 4 item: killed 3/13 FPs in the vyper-real corpus's LT.vy)."""

from miesc.adapters.vyper_adapter import VyperAnalyzer

INDIRECT_CHECK_SOURCE = """\
# @version 0.3.7

admin: address

@internal
@view
def _check_admin():
    assert msg.sender == self.admin, "Access"

@external
def set_admin(new_admin: address):
    self._check_admin()
    self.admin = new_admin
"""

NO_CHECK_SOURCE = """\
# @version 0.3.7

admin: address

@external
def set_admin(new_admin: address):
    self.admin = new_admin
"""


def _access_control_findings(source, tmp_path):
    vy_file = tmp_path / "Vault.vy"
    vy_file.write_text(source)
    result = VyperAnalyzer().analyze(str(vy_file))
    return [f for f in result["findings"] if f["type"] == "missing_access_control"]


def test_indirect_check_via_internal_helper_is_not_flagged(tmp_path):
    assert _access_control_findings(INDIRECT_CHECK_SOURCE, tmp_path) == []


def test_function_with_no_check_at_all_is_still_flagged(tmp_path):
    assert len(_access_control_findings(NO_CHECK_SOURCE, tmp_path)) == 1
