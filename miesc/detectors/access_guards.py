"""Shared predicates for access-control rules: caller guards and self-service withdrawals.

Two questions the regex-level access-control rules kept answering differently, now
answered in one place:

* **Is this function guarded by the caller's identity?** An ``only*`` modifier on the
  header (``onlyOwner``, ``onlywizard``, ``onlyBy(owner)``), a condition that compares
  ``msg.sender`` (``require(msg.sender == owner)``, ``if (msg.sender != organizer) throw``),
  or a condition that uses a mapping indexed by ``msg.sender`` as a boolean
  (``require(isOwner[msg.sender])``, ``if (!admins[msg.sender]) revert()``). A numeric
  check on such a mapping (``require(balances[msg.sender] >= amount)``) is a balance
  check, not a guard, and does not count.
* **Is this a self-service withdrawal?** Value goes to ``msg.sender`` and the amount
  comes from the caller's own entry in a mapping (or is a ``msg.value`` refund). A
  public ``withdraw()`` of that shape is how users get their deposits back; it is not a
  missing-access-control bug. Sending the contract balance to the caller is.

Measured on SmartBugs-curated (2026-10-23): the "withdraw without onlyOwner" shape was the
single largest source of spurious ``access_control`` findings (25 findings on contracts
labelled reentrancy / unchecked calls / arithmetic), and every labelled access-control
contract keeps its hit under these predicates. See REPRODUCE.md.
"""

from __future__ import annotations

import re

__all__ = [
    "has_caller_guard",
    "is_self_service_withdrawal",
    "moves_value",
    "OWNER_LIKE_RE",
    "function_text_at",
]

_GUARD_MODIFIER_RE = re.compile(r"\bonly[A-Za-z_]\w*", re.I)
# Everything after require/assert/if/while/( up to the end of that statement or block.
_CONDITION_RE = re.compile(r"\b(?:require|assert|if|while)\s*\(((?:[^;{}])*)", re.S)
_SENDER_COMPARE_RE = re.compile(r"msg\.sender\s*(?:==|!=)|(?:==|!=)\s*msg\.sender")
# `isOwner[msg.sender]` used as a boolean: preceded by `!`/`(`/`&&`/`||`/`,` and followed by
# `)`/`&&`/`||`/`,`/`==`/`!=` — not by an arithmetic comparison.
_SENDER_MAPPING_BOOL_RE = re.compile(
    r"(?:^|[(!,]|&&|\|\|)\s*!?\s*\w+\s*\[\s*msg\.sender\s*\]\s*(?:$|[),]|&&|\|\||==|!=)"
)
_SENDER_MAPPING_READ_RE = re.compile(r"\b\w+\s*\[\s*msg\.sender\s*\]")
_VALUE_SINK_RE = re.compile(
    r"(?:payable\s*\(\s*)?(?P<rcpt>msg\.sender|\w+)\s*\)?\s*\.\s*"
    r"(?:(?:transfer|send)\s*\((?P<a1>[^;]*)"
    r"|call\s*(?:\.value\s*\((?P<a2>[^)]*)\)|\{\s*value\s*:\s*(?P<a3>[^}]*)\}))"
)
_CONTRACT_BALANCE_RE = re.compile(r"\bthis\.balance\b|address\s*\(\s*this\s*\)\s*\.\s*balance")
OWNER_LIKE_RE = re.compile(
    r"^_?(?:owner|admin|creator|root|master|contract_?owner|owner_?addr(?:ess)?)_?$", re.I
)


def has_caller_guard(header: str, body: str) -> bool:
    """True when the function restricts who may call it (see module docstring)."""
    if _GUARD_MODIFIER_RE.search(header):
        return True
    for condition in _CONDITION_RE.finditer(body):
        text = condition.group(1)
        if _SENDER_COMPARE_RE.search(text) or _SENDER_MAPPING_BOOL_RE.search(text):
            return True
    return False


def is_self_service_withdrawal(body: str) -> bool:
    """True when the value sent is bound to the caller's or the recipient's own entry.

    Shapes: ``msg.sender.transfer(balances[msg.sender])``, ``to.transfer(amount)`` after
    ``balances[msg.sender] -= amount``, ``recipient.call.value(rewards[recipient])()``, or a
    ``msg.value`` refund. False when the amount mentions the contract balance, or when no
    mapping keyed by ``msg.sender`` or by the recipient is read in the function.
    """
    for sink in _VALUE_SINK_RE.finditer(body):
        amount = sink.group("a1") or sink.group("a2") or sink.group("a3") or ""
        if _CONTRACT_BALANCE_RE.search(amount):
            return False
        recipient = sink.group("rcpt")
        if "msg.value" in amount or _SENDER_MAPPING_READ_RE.search(body):
            return True
        if recipient != "msg.sender" and re.search(
            r"\b\w+\s*\[\s*%s\s*\]" % re.escape(recipient), body
        ):
            return True
    return False


_FUNCTION_START_RE = re.compile(r"\bfunction\b|\bconstructor\s*\(")


def function_text_at(source: str, pos: int) -> tuple[str, str]:
    """Return ``(header, body)`` of the function whose definition starts at or after ``pos``.

    The header runs to the opening brace, the body is brace-matched. Empty strings when
    no function starts there.
    """
    start = _FUNCTION_START_RE.search(source, pos)
    if not start:
        return "", ""
    open_brace = source.find("{", start.end())
    semicolon = source.find(";", start.end())
    if open_brace == -1 or (semicolon != -1 and semicolon < open_brace):
        return source[start.start() : semicolon if semicolon != -1 else len(source)], ""
    depth = 0
    end = open_brace
    while end < len(source):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                break
        end += 1
    return source[start.start() : open_brace], source[open_brace : end + 1]


def moves_value(body: str) -> bool:
    """True when the function body sends ether (transfer/send/call.value/call{value})."""
    return bool(_VALUE_SINK_RE.search(body))
