"""
Yul / inline-assembly memory and storage safety — advisory effect-summary plan.

The later phases of ``docs/sdd/SDD_YUL_ASSEMBLY_MEMORY_SAFETY_HARDENING_20260811.md``. Phase 1 of
that SDD already shipped as a **Finding-emitting detector** (``YulAssemblySafetyDetector`` in
``miesc/detectors/yul_assembly_safety_detector.py``, PR #207): it extracts assembly blocks and flags
three high-precision hazards. This module is the SDD's *other* half — the provider-neutral
``YulAssemblySafetyPlan``: a **structured model of what each inline-assembly block does** to memory,
storage, calldata and returndata, which the SDD (l.9) names as the real gap (Slither only emits an
informational ``assembly`` warning; the detector only pattern-matches three hazards).

It is **advisory**: a plan is an effect inventory, never a ``Finding`` and never an "unsafe assembly"
accusation. ``promotion.state`` stays ``hypothesis``. It does **not** duplicate the detector — it
*imports* its block extractor and masker, and fills the ``hazards`` field by calling the detector's
own classifier (so a block the repo already flags never shows an empty, misleading ``hazards: []``).
``metadata.evaluated_hazard_categories`` records exactly which of the ten SDD categories were
checked, so an empty ``hazards`` means "the three evaluated categories found nothing", not "clean".

What is new here is the deterministic **opcode→effect tokenizer**: memory is written by
``calldatacopy``/``returndatacopy``/``codecopy``/``extcodecopy``/``mcopy`` as well as ``mstore``, and
read by ``keccak256``/``log*``/``return``/``revert``/``call*``/``create*``; each memory target is
classified by region (scratch / free-pointer / zero-slot / fixed / computed) and each storage slot by
provenance (literal / ``.slot`` / keccak / calldata-or-param). ``tload``/``tstore`` are kept out of
the storage fields (transient storage is a distinct space). Later phases (the LLM reasoning agent,
the remaining seven hazard categories, and the validation obligations / cross-subsystem bridges)
build on this.

Known limits: the call family's return buffer (``call(..., retOffset, retSize)``) is recorded as a
memory *read* and an external effect but not yet as a memory *write*, so the ``call(..., 0, 0x20)``
return-decode idiom shows no write; a parenthesis-free ``modifier onlyOwner {`` is not recognised as
an enclosing context; and the hazard slot-taint still comes from the detector's function span (which
has no bodiless-declaration guard), so taint can be off for interface-shadowed shapes even though the
enclosing name is corrected here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set

from miesc.detectors.yul_assembly_safety_detector import (
    YulAssemblySafetyDetector,
    _AssemblyBlock,
    _extract_assembly_blocks,
    _mask_comments_and_strings,
)
from miesc.llm.agentic_contracts import (
    MAX_AGENT_ITEMS,
    MAX_AGENT_TEXT_CHARS,
    _json_safe_mapping,
    _safe_label,
    _safe_text,
    _safe_text_list,
)

# The ten hazard categories named in the SDD. A category outside this set is dropped (in
# ``to_dict`` and the parser). The deterministic miner here evaluates only the three the shipped
# detector covers (``_DETECTOR_HAZARD_MAP``); the rest wait for the LLM reasoning agent and are
# recorded as deferred so an empty ``hazards`` list is never read as "all ten clean".
_HAZARD_CATEGORIES = frozenset(
    {
        "unsafe_memory_safe_annotation",
        "scratch_space_overflow",
        "free_memory_pointer_corruption",
        "zero_slot_corruption",
        "arbitrary_storage_write",
        "manual_calldata_decode_without_bounds",
        "unchecked_downcast",
        "unbounded_returndata_copy",
        "custom_dispatch_ambiguity",
        "low_level_call_side_effect",
    }
)

# Detector hazard id -> SDD category. These three are the categories this phase actually evaluates.
_DETECTOR_HAZARD_MAP = {
    "yul-memory-safe-violation": "unsafe_memory_safe_annotation",
    "yul-unbounded-returndatacopy": "unbounded_returndata_copy",
    "yul-arbitrary-sstore": "arbitrary_storage_write",
}
_EVALUATED_CATEGORIES = tuple(dict.fromkeys(_DETECTOR_HAZARD_MAP.values()))
_DEFERRED_CATEGORIES = tuple(sorted(_HAZARD_CATEGORIES - set(_EVALUATED_CATEGORIES)))

# Per-category negative check (the condition that would reject the hazard), mirroring the detector's
# own suppression logic so each hazard carries at least one as the SDD requires.
_NEGATIVE_CHECKS = {
    "unsafe_memory_safe_annotation": "the block restores the free-memory pointer / zero slot or "
    "terminates (return/revert) before falling through — the clobber-then-restore idiom",
    "unbounded_returndata_copy": "the copy allocates returndatasize() against the free-memory "
    "pointer, or a return/revert forwards the copied region immediately (the proxy idiom)",
    "arbitrary_storage_write": "the slot is a constant or keccak256 of a fixed layout key, not an "
    "attacker-chosen value",
}


# --------------------------------------------------------------------------------------
# Opcode -> effect tables (the deterministic tokenizer core).
# --------------------------------------------------------------------------------------
# Memory writers -> the 0-based argument index whose value is the destination offset.
_MEM_WRITE_DEST = {
    "mstore": 0,
    "mstore8": 0,
    "calldatacopy": 0,
    "returndatacopy": 0,
    "codecopy": 0,
    "mcopy": 0,
    "extcodecopy": 1,  # extcodecopy(addr, dst, offset, len) — dst is the 2nd arg
}
# Opcodes that read memory (their operands reference a memory region).
_MEM_READ_OPCODES = {
    "mload",
    "keccak256",
    "sha3",
    "return",
    "revert",
    "log0",
    "log1",
    "log2",
    "log3",
    "log4",
    "call",
    "callcode",
    "delegatecall",
    "staticcall",
    "create",
    "create2",
    "mcopy",
}
_CALLDATA_OPCODES = {"calldataload", "calldatacopy", "calldatasize"}
_RETURNDATA_OPCODES = {"returndatasize", "returndatacopy"}
_EXTERNAL_OPCODES = {
    "call",
    "callcode",
    "delegatecall",
    "staticcall",
    "create",
    "create2",
    "selfdestruct",
}
# Every opcode this module reasons about — used to keep ``instructions`` to real opcodes (a
# user-defined Yul function call that happens to look like ``foo(...)`` is not listed).
_SAFETY_OPCODES = (
    set(_MEM_WRITE_DEST)
    | _MEM_READ_OPCODES
    | _CALLDATA_OPCODES
    | _RETURNDATA_OPCODES
    | _EXTERNAL_OPCODES
    | {"sstore", "sload", "tstore", "tload"}
)

_OPCODE_CALL_RE = re.compile(r"\b([a-z][a-z0-9]*)\s*\(")
_CALLDATA_BIND_RE = re.compile(r"\blet\s+(?P<name>[A-Za-z_]\w*)\s*:=\s*calldataload\b")
_LET_RE = re.compile(r"\blet\s+(?P<name>[A-Za-z_]\w*)")
_SLOT_ACCESSOR_RE = re.compile(r"\b([A-Za-z_]\w*\.(?:slot|offset|length))\b")
_LITERAL_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")
# A broader enclosing-context matcher than the detector's (which only sees ``function name(``), so a
# block in fallback / receive / constructor / a modifier is not left as "unknown".
_CONTEXT_RE = re.compile(
    r"\b(?:function\s+(?P<fname>[A-Za-z_]\w*)|function(?=\s*\()|"
    r"(?P<kw>fallback|receive|constructor)|modifier\s+(?P<mname>[A-Za-z_]\w*))\s*\("
)
_EXTERNAL_VIS = {"external", "public"}


# --------------------------------------------------------------------------------------
# Provider-neutral data contract.
# --------------------------------------------------------------------------------------
@dataclass
class AssemblySummary:
    dialect: str = "evm"
    is_memory_safe_annotated: bool = False
    instructions: List[str] = field(default_factory=list)
    memory_reads: List[str] = field(default_factory=list)
    memory_writes: List[str] = field(default_factory=list)
    storage_reads: List[str] = field(default_factory=list)
    storage_writes: List[str] = field(default_factory=list)
    calldata_reads: List[str] = field(default_factory=list)
    returndata_reads: List[str] = field(default_factory=list)
    external_effects: List[str] = field(default_factory=list)
    solidity_variable_bindings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dialect": self.dialect if self.dialect in ("evm", "yul", "unknown") else "unknown",
            "is_memory_safe_annotated": bool(self.is_memory_safe_annotated),
            "instructions": _safe_text_list(self.instructions),
            "memory_reads": _safe_text_list(self.memory_reads),
            "memory_writes": _safe_text_list(self.memory_writes),
            "storage_reads": _safe_text_list(self.storage_reads),
            "storage_writes": _safe_text_list(self.storage_writes),
            "calldata_reads": _safe_text_list(self.calldata_reads),
            "returndata_reads": _safe_text_list(self.returndata_reads),
            "external_effects": _safe_text_list(self.external_effects),
            "solidity_variable_bindings": _safe_text_list(self.solidity_variable_bindings),
        }


@dataclass
class YulHazard:
    """An advisory hazard hypothesis on an assembly block — never a confirmed finding.

    Carries at least one ``negative_check`` (the condition that would reject it) so a reader weighs
    it rather than treating it as a defect.
    """

    category: str
    evidence: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    negative_checks: List[str] = field(default_factory=list)
    confidence: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        conf = self.confidence if self.confidence in ("low", "medium", "high") else "low"
        return {
            "category": (
                _safe_label(self.category)
                if self.category in _HAZARD_CATEGORIES
                else "unclassified"
            ),
            "evidence": _safe_text_list(self.evidence),
            "preconditions": _safe_text_list(self.preconditions),
            "negative_checks": _safe_text_list(self.negative_checks),
            "confidence": conf,
        }


@dataclass
class YulAssemblySafetyPlan:
    id: str
    objective: str
    source_anchor: str = ""
    enclosing_function: str = ""
    summary: Optional[AssemblySummary] = None
    hazards: List[YulHazard] = field(default_factory=list)
    promotion_state: str = "hypothesis"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "source_anchor": _safe_text(self.source_anchor, 200) or "",
            "enclosing_function": _safe_label(self.enclosing_function) or "",
            "assembly_summary": (self.summary or AssemblySummary()).to_dict(),
            "hazards": [h.to_dict() for h in self.hazards[:MAX_AGENT_ITEMS]],
            # Validation obligations are a later SDD phase; emitted empty but present for the contract.
            "validation_obligations": [],
            "promotion": {"state": self.promotion_state, "evidence": [], "blockers": []},
            "metadata": _json_safe_mapping(
                {
                    # ``evaluated_hazard_categories`` / ``deferred_hazard_categories`` are stamped by
                    # the miner (which actually ran the detector), NOT here — a plan rebuilt from
                    # provider output must not claim the detector checked anything.
                    **self.metadata,
                    "capability": "yul_assembly_memory_safety_hardening",
                    "schema_version": "1",
                }
            ),
        }


def _hazards_from_raw(raw: Mapping[str, Any]) -> List[YulHazard]:
    out: List[YulHazard] = []
    raw_list = raw.get("hazards")
    if not isinstance(raw_list, list):
        return out
    for rh in raw_list[:MAX_AGENT_ITEMS]:
        if not isinstance(rh, Mapping):
            continue
        category = _safe_label(rh.get("category")) or ""
        if category not in _HAZARD_CATEGORIES:
            continue
        negative_checks = _safe_text_list(rh.get("negative_checks"))
        if not negative_checks:
            continue  # a hazard without the condition that would reject it is not a usable obligation
        out.append(
            YulHazard(
                category=category,
                evidence=_safe_text_list(rh.get("evidence")),
                preconditions=_safe_text_list(rh.get("preconditions")),
                negative_checks=negative_checks,
                confidence=str(rh.get("confidence") or "low"),
            )
        )
    return out


def _summary_from_raw(raw: Mapping[str, Any]) -> AssemblySummary:
    s: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    return AssemblySummary(
        dialect=str(s.get("dialect") or "evm"),
        is_memory_safe_annotated=bool(s.get("is_memory_safe_annotated")),
        instructions=_safe_text_list(s.get("instructions")),
        memory_reads=_safe_text_list(s.get("memory_reads")),
        memory_writes=_safe_text_list(s.get("memory_writes")),
        storage_reads=_safe_text_list(s.get("storage_reads")),
        storage_writes=_safe_text_list(s.get("storage_writes")),
        calldata_reads=_safe_text_list(s.get("calldata_reads")),
        returndata_reads=_safe_text_list(s.get("returndata_reads")),
        external_effects=_safe_text_list(s.get("external_effects")),
        solidity_variable_bindings=_safe_text_list(s.get("solidity_variable_bindings")),
    )


def parse_yul_assembly_safety_plans(data: Any) -> List[YulAssemblySafetyPlan]:
    """Parse provider/output data into bounded Yul assembly safety plans (provider-neutral)."""
    import json

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []
    if not isinstance(data, Mapping):
        return []
    raw_items = data.get("yul_assembly_safety_plans", data.get("plans", []))
    if not isinstance(raw_items, list):
        return []

    plans: List[YulAssemblySafetyPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not objective:
            continue
        plans.append(
            YulAssemblySafetyPlan(
                id=_safe_label(raw.get("id")) or "yul",
                objective=objective,
                source_anchor=_safe_text(raw.get("source_anchor"), 200) or "",
                enclosing_function=_safe_label(raw.get("enclosing_function")) or "",
                summary=_summary_from_raw(raw.get("assembly_summary") or {}),
                hazards=_hazards_from_raw(raw),
            )
        )
    return plans


# --------------------------------------------------------------------------------------
# Deterministic tokenizer helpers.
# --------------------------------------------------------------------------------------
def _as_int(token: str) -> Optional[int]:
    token = token.strip()
    if not _LITERAL_RE.match(token):
        return None
    try:
        return int(token, 0)
    except ValueError:
        return None


def _top_level_args(body: str, open_paren: int) -> List[str]:
    """Top-level, comma-separated argument strings of the call whose ``(`` is at ``open_paren``."""
    depth = 0
    args: List[str] = []
    cur: List[str] = []
    for i in range(open_paren, len(body)):
        c = body[i]
        if c == "(":
            depth += 1
            if depth == 1:
                continue
        elif c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                break
        if depth == 1 and c == ",":
            args.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    return [a.strip() for a in args if a.strip()]


# A memory write covers ``[start, start+len)``: ``mstore`` writes 32 bytes, ``mstore8`` one, and a
# copy opcode writes its length argument (the index here). A write that *starts* in scratch but
# whose extent reaches 0x40/0x60 still corrupts the pointer/zero slot, so the region is classified by
# the whole range, not just the start — otherwise ``calldatacopy(0, _, calldatasize())`` (which runs
# straight over the free pointer) would read as harmless "scratch".
_WRITE_FIXED_LEN = {"mstore": 32, "mstore8": 1}
_WRITE_LEN_ARG = {
    "calldatacopy": 2,
    "returndatacopy": 2,
    "codecopy": 2,
    "mcopy": 2,
    "extcodecopy": 3,
}


def _overlaps(start: int, end: Optional[int], lo: int, hi: int) -> bool:
    """Whether the write range ``[start, end)`` overlaps the slot range ``[lo, hi)``.

    The free-pointer slot is the whole word ``[0x40, 0x60)`` and the zero slot ``[0x60, 0x80)``, so a
    write anywhere inside them corrupts the slot — not only a write landing exactly on ``0x40`` /
    ``0x60``. ``end`` None = unbounded (a dynamic-length copy runs to high memory).
    """
    if end is None:
        return start < hi
    return start < hi and lo < end


def _region(op: str, args: List[str], dest_idx: int) -> str:
    """Classify a memory write by the slot range its whole ``[start, start+len)`` range overlaps."""
    dest = args[dest_idx] if dest_idx < len(args) else ""
    start = _as_int(dest)
    if start is None:
        return "computed"
    if op in _WRITE_FIXED_LEN:
        length: Optional[int] = _WRITE_FIXED_LEN[op]
    else:
        li = _WRITE_LEN_ARG.get(op)
        length = _as_int(args[li]) if (li is not None and li < len(args)) else None
    end = None if length is None else start + length
    if _overlaps(start, end, 0x40, 0x60):
        base = "free_memory_pointer"
    elif _overlaps(start, end, 0x60, 0x80):
        base = "zero_slot"
    elif start < 0x40:
        base = "scratch"
    else:
        base = "fixed"
    # A dynamic (non-literal) length runs unbounded into high memory — flag it explicitly.
    return base + ("_unbounded" if end is None else "")


def _classify_slot_expr(low: str) -> Optional[str]:
    """Provenance of a slot expression by its text, or None if it is a bare identifier."""
    if _as_int(low) is not None:
        return "literal"
    if "calldataload" in low:
        return "calldata"
    if ".slot" in low:
        return "slot_binding"
    if "keccak" in low:
        return "keccak"
    return None


def _slot_provenance(slot: str, tainted: Set[str], body: str) -> str:
    """Classify a storage slot by how its value is derived, resolving one ``let`` level.

    A bare identifier (``sstore(s, _)``) is looked up to its ``let s := <expr>`` binding, so a slot
    computed as ``keccak256(...)`` or read from calldata is classified by that expression rather than
    left as the catch-all ``computed``.
    """
    s = slot.strip()
    direct = _classify_slot_expr(s.lower())
    if direct is not None:
        return direct
    ident = re.match(r"^([A-Za-z_]\w*)$", s)
    if ident:
        name = ident.group(1)
        if name in tainted:
            return "tainted_param"
        binding = re.search(r"\blet\s+" + re.escape(name) + r"\s*:=\s*([^\n}]+)", body)
        if binding:
            resolved = _classify_slot_expr(binding.group(1).lower())
            if resolved is not None:
                return resolved
    return "computed"


def _tainted_names(block: _AssemblyBlock) -> Set[str]:
    """Yul vars bound from calldata, plus external/public function parameters."""
    calldata_vars = {m.group("name") for m in _CALLDATA_BIND_RE.finditer(block.body)}
    params = block.params if block.visibility in _EXTERNAL_VIS else set()
    return calldata_vars | params


def _enclosing_context(masked: str, index: int) -> Optional[str]:
    """Name of the *innermost* enclosing function / fallback / receive / constructor / modifier.

    The detector's extractor only recognises ``function name(`` and has no bodiless-declaration
    guard, so a block below an interface method or the 0.4 unnamed ``function () {}`` fallback is
    mislabeled. This matcher skips a declaration whose ``(...)`` is closed by ``;`` before any ``{``
    (an interface/abstract signature), handles the unnamed fallback, and returns the innermost
    (latest-starting) real scope that contains ``index``.
    """
    best: Optional[str] = None
    best_start = -1
    for m in _CONTEXT_RE.finditer(masked):
        brace = masked.find("{", m.end())
        if brace == -1:
            continue
        semi = masked.find(";", m.end())
        if semi != -1 and semi < brace:
            continue  # bodiless declaration (interface / abstract): not an enclosing scope
        end = _match_brace(masked, brace)
        if end == -1 or not (brace <= index <= end) or m.start() <= best_start:
            continue
        name = m.group("fname") or m.group("kw") or m.group("mname") or "fallback"
        best, best_start = name, m.start()
    return best


def _match_brace(source: str, start: int) -> int:
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _summarize(block: _AssemblyBlock) -> AssemblySummary:
    """Build the structured effect summary for one assembly block (deterministic, no provider)."""
    body = block.body
    tainted = _tainted_names(block)
    instructions: Set[str] = set()
    memory_reads: Set[str] = set()
    memory_writes: List[str] = []
    storage_reads: List[str] = []
    storage_writes: List[str] = []
    calldata_reads: Set[str] = set()
    returndata_reads: Set[str] = set()
    external_effects: List[str] = []

    for m in _OPCODE_CALL_RE.finditer(body):
        op = m.group(1)
        if op not in _SAFETY_OPCODES:
            continue
        instructions.add(op)
        if op in _MEM_WRITE_DEST:
            args = _top_level_args(body, m.end() - 1)
            memory_writes.append(f"{op}({_region(op, args, _MEM_WRITE_DEST[op])})")
        if op in _MEM_READ_OPCODES:
            memory_reads.add(op)
        if op == "sstore" or op == "sload":
            args = _top_level_args(body, m.end() - 1)
            slot = args[0] if args else ""
            entry = f"{op}({_slot_provenance(slot, tainted, body)})"
            (storage_writes if op == "sstore" else storage_reads).append(entry)
        if op in _CALLDATA_OPCODES:
            calldata_reads.add(op)
        if op in _RETURNDATA_OPCODES:
            returndata_reads.add(op)
        if op in _EXTERNAL_OPCODES:
            external_effects.append(op)
        # tload / tstore are recorded as instructions only — transient storage is a distinct space
        # and must not land in the storage_reads / storage_writes fields.

    bindings = sorted(
        {m.group("name") for m in _LET_RE.finditer(body)}
        | {m.group(1) for m in _SLOT_ACCESSOR_RE.finditer(body)}
        | {p for p in block.params if re.search(r"\b" + re.escape(p) + r"\b", body)}
    )

    return AssemblySummary(
        dialect="evm",
        is_memory_safe_annotated=block.memory_safe,
        instructions=sorted(instructions)[:MAX_AGENT_ITEMS],
        memory_reads=sorted(memory_reads)[:MAX_AGENT_ITEMS],
        memory_writes=_dedup(memory_writes)[:MAX_AGENT_ITEMS],
        storage_reads=_dedup(storage_reads)[:MAX_AGENT_ITEMS],
        storage_writes=_dedup(storage_writes)[:MAX_AGENT_ITEMS],
        calldata_reads=sorted(calldata_reads)[:MAX_AGENT_ITEMS],
        returndata_reads=sorted(returndata_reads)[:MAX_AGENT_ITEMS],
        external_effects=_dedup(external_effects)[:MAX_AGENT_ITEMS],
        solidity_variable_bindings=bindings[:MAX_AGENT_ITEMS],
    )


def _dedup(seq: List[str]) -> List[str]:
    return list(dict.fromkeys(seq))


def _hazards_for_block(
    detector: YulAssemblySafetyDetector, block: _AssemblyBlock, source: str
) -> List[YulHazard]:
    """Fill hazards by calling the shipped detector's classifier (no second classifier written)."""
    hazards: List[YulHazard] = []
    for finding in detector._classify(block, source):
        hz = (finding.metadata or {}).get("hazard")
        category = _DETECTOR_HAZARD_MAP.get(hz or "")
        if not category:
            continue
        hazards.append(
            YulHazard(
                category=category,
                evidence=[finding.title],
                preconditions=[],
                negative_checks=[_NEGATIVE_CHECKS[category]],
                confidence=str(getattr(finding, "confidence", "medium") or "medium"),
            )
        )
    return hazards


def mine_yul_assembly_safety(
    source_code: str,
    file_path: Optional[Path] = None,
) -> List[YulAssemblySafetyPlan]:
    """Deterministically build an advisory effect-summary plan per inline-assembly block.

    One plan per assembly block, with its structured effect summary and the hazards the shipped
    detector reports (the three evaluated categories). Never raises and never emits a Finding.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return []
    masked = _mask_comments_and_strings(source_code)
    if "assembly" not in masked:
        return []
    anchor = Path(file_path).name if file_path else "<memory>"
    blocks = _extract_assembly_blocks(source_code, masked)
    detector = YulAssemblySafetyDetector()

    plans: List[YulAssemblySafetyPlan] = []
    for block in blocks:
        # Always prefer the body-aware innermost-scope matcher: the detector's span finder has no
        # bodiless-declaration guard, so it can mislabel (e.g. attribute a block to an interface
        # method above it) rather than only returning "unknown". Known limit: the taint inputs
        # (block.params / block.visibility) still come from the detector's span, so slot taint can be
        # off for the same interface-shadowed shapes — the enclosing name is corrected, the taint is
        # not (patching the detector is out of scope for this plan layer).
        enclosing = _enclosing_context(masked, block.start) or block.func_name
        summary = _summarize(block)
        hazards = _hazards_for_block(detector, block, source_code)
        plans.append(
            YulAssemblySafetyPlan(
                id=f"yul-{anchor}-{enclosing}-{block.line}",
                objective=f"Inline-assembly effect summary in {enclosing}() at {anchor}:{block.line}",
                source_anchor=f"{anchor}:{block.line}",
                enclosing_function=enclosing,
                summary=summary,
                hazards=hazards,
                # The miner actually ran the detector, so it records which categories were checked —
                # an empty ``hazards`` then means "these three found nothing", not "all ten clean".
                metadata={
                    "evaluated_hazard_categories": list(_EVALUATED_CATEGORIES),
                    "deferred_hazard_categories": list(_DEFERRED_CATEGORIES),
                },
            )
        )
    return plans[:MAX_AGENT_ITEMS]


__all__ = [
    "AssemblySummary",
    "YulHazard",
    "YulAssemblySafetyPlan",
    "parse_yul_assembly_safety_plans",
    "mine_yul_assembly_safety",
]
