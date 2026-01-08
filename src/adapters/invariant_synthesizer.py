"""
LLM-Powered Invariant Synthesis for Smart Contracts.

Generates formal invariants using:
- RAG-enhanced LLM analysis
- Pattern matching from vulnerability knowledge base
- Multi-format output (Solidity, Certora CVL, Echidna, Halmos)

Based on research:
- "PropertyGPT: LLM-driven Formal Verification of Smart Contracts" (arXiv:2405.02580)
- "SmartInv: LLM-Synthesized Invariants for Formal Verification" (arXiv:2411.00848)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-06
License: AGPL-3.0
"""

import hashlib
import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters.smartllm_rag_knowledge import (
    FORMAL_INVARIANTS,
    get_all_vulnerability_patterns,
    get_relevant_knowledge,
)
from src.core.llm_config import (
    USE_CASE_PROPERTY_GENERATION,
    get_model,
    get_ollama_host,
    get_retry_config,
)

logger = logging.getLogger(__name__)


class InvariantFormat(Enum):
    """Supported invariant output formats."""

    SOLIDITY = "solidity"  # Solidity require/assert statements
    CERTORA = "certora"  # Certora CVL specifications
    ECHIDNA = "echidna"  # Echidna property tests
    HALMOS = "halmos"  # Halmos symbolic tests
    FOUNDRY = "foundry"  # Foundry invariant tests
    NATURAL = "natural"  # Natural language description


class InvariantCategory(Enum):
    """Categories of invariants."""

    ACCOUNTING = "accounting"  # Balance/supply consistency
    SOLVENCY = "solvency"  # Vault/protocol solvency
    ACCESS_CONTROL = "access_control"  # Permission invariants
    STATE_TRANSITION = "state_transition"  # Valid state transitions
    REENTRANCY = "reentrancy"  # Reentrancy guards
    OVERFLOW = "overflow"  # Arithmetic safety
    TEMPORAL = "temporal"  # Time-based invariants
    CUSTOM = "custom"  # User-defined


@dataclass
class SynthesizedInvariant:
    """Represents a synthesized invariant."""

    name: str
    description: str
    category: InvariantCategory
    importance: str  # CRITICAL, HIGH, MEDIUM, LOW
    natural_language: str
    solidity_assertion: Optional[str] = None
    certora_spec: Optional[str] = None
    echidna_property: Optional[str] = None
    halmos_test: Optional[str] = None
    foundry_test: Optional[str] = None
    confidence: float = 0.0
    source: str = "llm"  # llm, pattern, static
    related_vulnerabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "importance": self.importance,
            "natural_language": self.natural_language,
            "solidity_assertion": self.solidity_assertion,
            "certora_spec": self.certora_spec,
            "echidna_property": self.echidna_property,
            "halmos_test": self.halmos_test,
            "foundry_test": self.foundry_test,
            "confidence": self.confidence,
            "source": self.source,
            "related_vulnerabilities": self.related_vulnerabilities,
            "metadata": self.metadata,
        }


class InvariantSynthesizer:
    """
    LLM-powered invariant synthesizer for smart contracts.

    Uses Ollama with deepseek-coder model to generate formal invariants
    from contract source code. Integrates with RAG knowledge base for
    pattern-based invariant suggestions.
    """

    def __init__(self):
        """Initialize the invariant synthesizer."""
        self._model = get_model(USE_CASE_PROPERTY_GENERATION)
        self._ollama_host = get_ollama_host()
        retry_config = get_retry_config()
        self._max_retries = retry_config["attempts"]
        self._retry_delay = retry_config["delay"]

        # Cache for generated invariants
        self._cache_dir = Path.home() / ".miesc" / "invariant_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        # Load RAG patterns
        self._formal_invariants = FORMAL_INVARIANTS
        self._vulnerability_patterns = get_all_vulnerability_patterns()

        logger.info(
            f"InvariantSynthesizer initialized with model={self._model}, "
            f"patterns={len(self._formal_invariants)}"
        )

    def synthesize(
        self,
        contract_path: str,
        formats: Optional[List[InvariantFormat]] = None,
        categories: Optional[List[InvariantCategory]] = None,
        max_invariants: int = 20,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Synthesize invariants for a smart contract.

        Args:
            contract_path: Path to the Solidity contract
            formats: Output formats to generate (default: all)
            categories: Categories to focus on (default: all)
            max_invariants: Maximum number of invariants to generate
            use_cache: Whether to use cached results

        Returns:
            Dictionary with synthesized invariants and metadata
        """
        start_time = time.time()

        if formats is None:
            formats = [
                InvariantFormat.SOLIDITY,
                InvariantFormat.CERTORA,
                InvariantFormat.ECHIDNA,
            ]

        if categories is None:
            categories = list(InvariantCategory)

        try:
            # Read contract
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return self._error_result(f"Could not read contract: {contract_path}", start_time)

            # Check cache
            cache_key = self._get_cache_key(contract_code, formats, categories)
            if use_cache:
                cached = self._get_cached_result(cache_key)
                if cached:
                    cached["from_cache"] = True
                    cached["execution_time"] = time.time() - start_time
                    return cached

            # Stage 1: Static pattern-based invariants
            logger.info("Stage 1/3: Pattern-based invariant detection")
            pattern_invariants = self._detect_pattern_invariants(contract_code)

            # Stage 2: LLM-generated invariants
            logger.info("Stage 2/3: LLM invariant synthesis")
            llm_invariants = self._synthesize_with_llm(
                contract_code, contract_path, categories, max_invariants
            )

            # Stage 3: Merge and format
            logger.info("Stage 3/3: Merging and formatting invariants")
            all_invariants = self._merge_invariants(pattern_invariants, llm_invariants)

            # Generate multi-format output
            formatted_invariants = self._format_invariants(all_invariants, formats)

            result = {
                "status": "success",
                "contract": contract_path,
                "invariants": [inv.to_dict() for inv in formatted_invariants],
                "summary": {
                    "total": len(formatted_invariants),
                    "by_category": self._count_by_category(formatted_invariants),
                    "by_importance": self._count_by_importance(formatted_invariants),
                    "formats_generated": [f.value for f in formats],
                },
                "metadata": {
                    "model": self._model,
                    "pattern_invariants": len(pattern_invariants),
                    "llm_invariants": len(llm_invariants),
                    "rag_patterns_used": len(self._formal_invariants),
                },
                "execution_time": time.time() - start_time,
                "from_cache": False,
            }

            # Cache result
            self._cache_result(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"Invariant synthesis error: {e}", exc_info=True)
            return self._error_result(str(e), start_time)

    def _detect_pattern_invariants(self, contract_code: str) -> List[SynthesizedInvariant]:
        """Detect invariants based on code patterns and RAG knowledge."""
        invariants = []
        code_lower = contract_code.lower()

        # Detect contract type and suggest relevant invariants
        contract_type = self._detect_contract_type(contract_code)

        # ERC-20 Token invariants
        if contract_type in ["erc20", "token"]:
            if "totalsupply" in code_lower and "balanceof" in code_lower:
                inv = self._create_from_pattern("total_supply_consistency")
                if inv:
                    invariants.append(inv)

            if "transfer" in code_lower:
                invariants.append(
                    SynthesizedInvariant(
                        name="transfer_preserves_supply",
                        description="Transfer does not change total supply",
                        category=InvariantCategory.ACCOUNTING,
                        importance="CRITICAL",
                        natural_language="For any transfer, the sum of sender and "
                        + "receiver balances remains constant",
                        confidence=0.95,
                        source="pattern",
                        related_vulnerabilities=["SWC-132"],
                    )
                )

        # Vault/ERC-4626 invariants
        if contract_type in ["vault", "erc4626"]:
            inv = self._create_from_pattern("vault_solvency")
            if inv:
                invariants.append(inv)

            inv = self._create_from_pattern("share_price_lower_bound")
            if inv:
                invariants.append(inv)

            invariants.append(
                SynthesizedInvariant(
                    name="deposit_increases_shares",
                    description="Depositing assets increases shares proportionally",
                    category=InvariantCategory.ACCOUNTING,
                    importance="HIGH",
                    natural_language="For any deposit of X assets, the user receives "
                    + "at least convertToShares(X) shares",
                    confidence=0.90,
                    source="pattern",
                    related_vulnerabilities=["vault_inflation_attack"],
                )
            )

        # Reentrancy guard detection
        if "nonreentrant" in code_lower or "reentrancyguard" in code_lower:
            invariants.append(
                SynthesizedInvariant(
                    name="reentrancy_lock_valid",
                    description="Reentrancy lock is properly set during execution",
                    category=InvariantCategory.REENTRANCY,
                    importance="CRITICAL",
                    natural_language="When a nonReentrant function is executing, "
                    + "the lock is set and cannot be re-entered",
                    confidence=0.95,
                    source="pattern",
                    related_vulnerabilities=["SWC-107", "reentrancy"],
                )
            )

        # Access control patterns
        if "owner" in code_lower and (
            "onlyowner" in code_lower or "msg.sender == owner" in code_lower
        ):
            inv = self._create_from_pattern("owner_immutable_on_renounce")
            if inv:
                invariants.append(inv)

            invariants.append(
                SynthesizedInvariant(
                    name="owner_functions_protected",
                    description="Owner-only functions can only be called by owner",
                    category=InvariantCategory.ACCESS_CONTROL,
                    importance="CRITICAL",
                    natural_language="Functions with onlyOwner modifier can only be "
                    + "executed by the current owner",
                    confidence=0.95,
                    source="pattern",
                    related_vulnerabilities=["SWC-105", "access_control"],
                )
            )

        # External call patterns (reentrancy risk)
        if ".call{" in contract_code or ".call(" in contract_code:
            # Check for checks-effects-interactions
            call_pos = contract_code.find(".call{")
            if call_pos == -1:
                call_pos = contract_code.find(".call(")

            if call_pos > 0:
                after_call = contract_code[call_pos:]
                if "-=" in after_call or "+=" in after_call:
                    invariants.append(
                        SynthesizedInvariant(
                            name="state_before_external_call",
                            description="State updates should happen before external calls",
                            category=InvariantCategory.REENTRANCY,
                            importance="CRITICAL",
                            natural_language="All state changes must be completed "
                            + "before any external call (checks-effects-interactions)",
                            confidence=0.85,
                            source="pattern",
                            related_vulnerabilities=["SWC-107", "reentrancy"],
                        )
                    )

        # Mapping-based balance tracking
        if "mapping" in code_lower and "balance" in code_lower:
            invariants.append(
                SynthesizedInvariant(
                    name="balance_non_negative",
                    description="User balances cannot be negative",
                    category=InvariantCategory.ACCOUNTING,
                    importance="HIGH",
                    natural_language="For all users u, balances[u] >= 0 "
                    + "(guaranteed by uint type but important for logic)",
                    confidence=0.99,
                    source="pattern",
                    related_vulnerabilities=["SWC-101", "integer_underflow"],
                )
            )

        logger.info(f"Pattern detection found {len(invariants)} invariants")
        return invariants

    def _synthesize_with_llm(
        self,
        contract_code: str,
        contract_path: str,
        categories: List[InvariantCategory],
        max_invariants: int,
    ) -> List[SynthesizedInvariant]:
        """Use LLM to synthesize invariants."""
        if not self._is_ollama_available():
            logger.warning("Ollama not available, skipping LLM synthesis")
            return []

        # Get RAG context
        rag_context = get_relevant_knowledge(contract_code)

        # Build invariant examples from RAG
        invariant_examples = self._build_invariant_examples(categories)

        prompt = self._build_synthesis_prompt(
            contract_code, contract_path, rag_context, invariant_examples, max_invariants
        )

        # Call LLM
        response = self._call_ollama(prompt)
        if not response:
            return []

        # Parse LLM response
        return self._parse_llm_invariants(response)

    def _build_synthesis_prompt(
        self,
        contract_code: str,
        contract_path: str,
        rag_context: str,
        invariant_examples: str,
        max_invariants: int,
    ) -> str:
        """Build the LLM prompt for invariant synthesis."""
        return f"""You are an expert in formal verification of smart contracts.
Your task is to generate formal invariants for the given contract.

SMART CONTRACT TO ANALYZE:
```solidity
{contract_code[:6000]}
```

FORMAL INVARIANT KNOWLEDGE BASE:
{invariant_examples}

VULNERABILITY CONTEXT (from RAG):
{rag_context[:2000]}

TASK: Generate up to {max_invariants} formal invariants for this contract.

For each invariant, provide:
1. name: A descriptive identifier (snake_case)
2. category: One of [accounting, solvency, access_control, state_transition,
   reentrancy, overflow, temporal]
3. importance: CRITICAL, HIGH, MEDIUM, or LOW
4. natural_language: Plain English description
5. formal_spec: Mathematical or logical specification

INVARIANT TYPES TO CONSIDER:
- Accounting: Balance consistency, supply conservation
- Solvency: Protocol can meet obligations
- Access Control: Permission boundaries
- State Transitions: Valid state changes only
- Reentrancy: No unexpected callbacks
- Overflow: Arithmetic bounds
- Temporal: Time-based constraints

OUTPUT FORMAT (valid JSON):
```json
{{
  "invariants": [
    {{
      "name": "total_supply_equals_sum_balances",
      "category": "accounting",
      "importance": "CRITICAL",
      "natural_language": "The total supply equals the sum of all balances",
      "formal_spec": "sum(balanceOf[u]) == totalSupply for all users u",
      "related_functions": ["transfer", "mint", "burn"]
    }}
  ]
}}
```

IMPORTANT RULES:
- Only generate invariants that apply to THIS specific contract
- Focus on CRITICAL and HIGH importance invariants first
- Include formal specification in mathematical notation
- Reference specific functions that must preserve the invariant
- Output ONLY valid JSON"""

    def _build_invariant_examples(self, categories: List[InvariantCategory]) -> str:
        """Build invariant examples from RAG knowledge base."""
        examples = []

        for inv_name, inv_info in self._formal_invariants.items():
            cat = inv_info.get("category", "")
            # Check if category matches
            try:
                inv_cat = InvariantCategory(cat)
                if inv_cat in categories:
                    examples.append(
                        f"- {inv_name}: {inv_info['description']}\n"
                        f"  Invariant: {inv_info['invariant']}\n"
                        f"  Importance: {inv_info['importance']}"
                    )
            except ValueError:
                # Unknown category, include anyway
                examples.append(
                    f"- {inv_name}: {inv_info['description']}\n"
                    f"  Invariant: {inv_info['invariant']}"
                )

        return "\n".join(examples[:10])  # Limit to 10 examples

    def _parse_llm_invariants(self, llm_response: str) -> List[SynthesizedInvariant]:
        """Parse LLM response to extract invariants."""
        invariants = []

        try:
            # Extract JSON from response
            json_match = re.search(r"```json\s*(.*?)\s*```", llm_response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(1))
            else:
                # Try direct JSON parse
                json_start = llm_response.find("{")
                json_end = llm_response.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    data = json.loads(llm_response[json_start:json_end])
                else:
                    return []

            llm_invariants = data.get("invariants", [])

            for inv in llm_invariants:
                if not isinstance(inv, dict):
                    continue

                # Map category string to enum
                cat_str = inv.get("category", "custom")
                try:
                    category = InvariantCategory(cat_str)
                except ValueError:
                    category = InvariantCategory.CUSTOM

                invariants.append(
                    SynthesizedInvariant(
                        name=inv.get("name", "unnamed_invariant"),
                        description=inv.get("formal_spec", inv.get("natural_language", "")),
                        category=category,
                        importance=inv.get("importance", "MEDIUM"),
                        natural_language=inv.get("natural_language", ""),
                        confidence=0.75,
                        source="llm",
                        related_vulnerabilities=inv.get("related_vulnerabilities", []),
                        metadata={
                            "related_functions": inv.get("related_functions", []),
                            "formal_spec": inv.get("formal_spec", ""),
                        },
                    )
                )

            logger.info(f"LLM synthesis generated {len(invariants)} invariants")

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM response as JSON: {e}")
        except Exception as e:
            logger.error(f"Error parsing LLM invariants: {e}")

        return invariants

    def _merge_invariants(
        self,
        pattern_invariants: List[SynthesizedInvariant],
        llm_invariants: List[SynthesizedInvariant],
    ) -> List[SynthesizedInvariant]:
        """Merge and deduplicate invariants from different sources."""
        merged = []
        seen_names = set()

        # Pattern invariants have higher confidence
        for inv in pattern_invariants:
            if inv.name not in seen_names:
                merged.append(inv)
                seen_names.add(inv.name)

        # Add LLM invariants if not duplicate
        for inv in llm_invariants:
            if inv.name not in seen_names:
                # Check for semantic similarity
                is_duplicate = False
                for existing in merged:
                    if self._is_semantically_similar(inv, existing):
                        is_duplicate = True
                        break

                if not is_duplicate:
                    merged.append(inv)
                    seen_names.add(inv.name)

        # Sort by importance
        importance_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        merged.sort(key=lambda x: importance_order.get(x.importance, 4))

        return merged

    def _is_semantically_similar(
        self, inv1: SynthesizedInvariant, inv2: SynthesizedInvariant
    ) -> bool:
        """Check if two invariants are semantically similar."""
        # Simple heuristic: check for common keywords
        words1 = set(inv1.natural_language.lower().split())
        words2 = set(inv2.natural_language.lower().split())

        if not words1 or not words2:
            return False

        overlap = len(words1 & words2)
        min_len = min(len(words1), len(words2))

        return overlap / min_len > 0.7 if min_len > 0 else False

    def _format_invariants(
        self,
        invariants: List[SynthesizedInvariant],
        formats: List[InvariantFormat],
    ) -> List[SynthesizedInvariant]:
        """Generate multi-format output for invariants."""
        for inv in invariants:
            if InvariantFormat.SOLIDITY in formats:
                inv.solidity_assertion = self._to_solidity(inv)

            if InvariantFormat.CERTORA in formats:
                inv.certora_spec = self._to_certora(inv)

            if InvariantFormat.ECHIDNA in formats:
                inv.echidna_property = self._to_echidna(inv)

            if InvariantFormat.HALMOS in formats:
                inv.halmos_test = self._to_halmos(inv)

            if InvariantFormat.FOUNDRY in formats:
                inv.foundry_test = self._to_foundry(inv)

        return invariants

    def _to_solidity(self, inv: SynthesizedInvariant) -> str:
        """Convert invariant to Solidity assertion."""
        # Generate based on category
        if inv.category == InvariantCategory.ACCOUNTING:
            return f"""// Invariant: {inv.name}
// {inv.natural_language}
function check_{inv.name}() internal view {{
    // TODO: Implement specific check
    // assert(condition);
}}"""

        elif inv.category == InvariantCategory.REENTRANCY:
            return f"""// Invariant: {inv.name}
// {inv.natural_language}
modifier checkReentrancy_{inv.name}() {{
    require(!_locked, "Reentrancy detected");
    _locked = true;
    _;
    _locked = false;
}}"""

        else:
            return f"""// Invariant: {inv.name}
// {inv.natural_language}
// Formal spec: {inv.description}"""

    def _to_certora(self, inv: SynthesizedInvariant) -> str:
        """Convert invariant to Certora CVL specification."""
        formal_spec = inv.metadata.get("formal_spec", inv.description)

        if inv.category == InvariantCategory.ACCOUNTING:
            return f"""// {inv.natural_language}
invariant {inv.name}()
    // {formal_spec}
    true  // TODO: Implement formal specification
{{
    preserved {{
        requireInvariant {inv.name}();
    }}
}}"""

        elif inv.category == InvariantCategory.ACCESS_CONTROL:
            return f"""// {inv.natural_language}
rule {inv.name}(method f, address caller) {{
    env e;
    require e.msg.sender == caller;

    // {formal_spec}
    // TODO: Add specific access control checks

    satisfy true;
}}"""

        else:
            return f"""// Invariant: {inv.name}
// {inv.natural_language}
// {formal_spec}

invariant {inv.name}()
    true  // TODO: Implement
{{
    preserved {{
        // Preservation proof
    }}
}}"""

    def _to_echidna(self, inv: SynthesizedInvariant) -> str:
        """Convert invariant to Echidna property test."""
        return f"""// Property: {inv.name}
// {inv.natural_language}
function echidna_{inv.name}() public view returns (bool) {{
    // {inv.description}
    // TODO: Implement property check
    return true;
}}"""

    def _to_halmos(self, inv: SynthesizedInvariant) -> str:
        """Convert invariant to Halmos symbolic test."""
        return f"""/// @custom:halmos --solver-timeout-assertion 60000
function check_{inv.name}(uint256 x) public {{
    // Invariant: {inv.natural_language}
    // {inv.description}

    // TODO: Set up symbolic state
    // vm.assume(preconditions);

    // TODO: Execute operations

    // TODO: Assert invariant holds
    // assert(postcondition);
}}"""

    def _to_foundry(self, inv: SynthesizedInvariant) -> str:
        """Convert invariant to Foundry invariant test."""
        return f"""// Invariant: {inv.name}
// {inv.natural_language}
function invariant_{inv.name}() public {{
    // {inv.description}
    // TODO: Implement invariant check
    // assertTrue(condition);
}}"""

    def _create_from_pattern(self, pattern_name: str) -> Optional[SynthesizedInvariant]:
        """Create invariant from RAG pattern."""
        pattern = self._formal_invariants.get(pattern_name)
        if not pattern:
            return None

        try:
            category = InvariantCategory(pattern.get("category", "custom"))
        except ValueError:
            category = InvariantCategory.CUSTOM

        return SynthesizedInvariant(
            name=pattern_name,
            description=pattern.get("invariant", ""),
            category=category,
            importance=pattern.get("importance", "MEDIUM"),
            natural_language=pattern.get("description", ""),
            confidence=0.90,
            source="pattern",
        )

    def _detect_contract_type(self, contract_code: str) -> str:
        """Detect the type of contract."""
        code_lower = contract_code.lower()

        # ERC-4626 Vault
        if "erc4626" in code_lower or ("totalsupply" in code_lower and "totalassets" in code_lower):
            return "erc4626"

        # Generic vault
        if "vault" in code_lower and ("deposit" in code_lower and "withdraw" in code_lower):
            return "vault"

        # ERC-20 Token
        if "erc20" in code_lower or (
            "transfer" in code_lower and "balanceof" in code_lower and "totalsupply" in code_lower
        ):
            return "erc20"

        # ERC-721 NFT
        if "erc721" in code_lower or "ownerof" in code_lower:
            return "erc721"

        # Governance
        if "governance" in code_lower or "vote" in code_lower or "proposal" in code_lower:
            return "governance"

        # Staking
        if "stake" in code_lower or "staking" in code_lower:
            return "staking"

        # DEX/AMM
        if "swap" in code_lower or "liquidity" in code_lower or "amm" in code_lower:
            return "dex"

        return "generic"

    def _is_ollama_available(self) -> bool:
        """Check if Ollama is available."""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=5,
                text=True,
            )
            return result.returncode == 0 and "deepseek" in result.stdout.lower()
        except Exception:
            return False

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """Call Ollama LLM with retry logic."""
        for attempt in range(1, self._max_retries + 1):
            try:
                logger.debug(f"Ollama call attempt {attempt}/{self._max_retries}")

                result = subprocess.run(
                    ["ollama", "run", self._model, prompt],
                    capture_output=True,
                    timeout=180,  # 3 minutes
                    text=True,
                )

                if result.returncode == 0 and result.stdout:
                    return result.stdout.strip()

            except subprocess.TimeoutExpired:
                logger.warning(f"Ollama timeout (attempt {attempt})")
            except Exception as e:
                logger.error(f"Ollama error (attempt {attempt}): {e}")

            if attempt < self._max_retries:
                time.sleep(self._retry_delay)

        return None

    def _read_contract(self, contract_path: str) -> Optional[str]:
        """Read contract file."""
        try:
            with open(contract_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading contract: {e}")
            return None

    def _get_cache_key(
        self,
        contract_code: str,
        formats: List[InvariantFormat],
        categories: List[InvariantCategory],
    ) -> str:
        """Generate cache key."""
        content = (
            contract_code + str([f.value for f in formats]) + str([c.value for c in categories])
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            age = time.time() - cache_file.stat().st_mtime
            if age > 86400:  # 24 hours
                cache_file.unlink()
                return None

            with open(cache_file, "r") as f:
                return json.load(f)
        except Exception:
            return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache result."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"Error caching result: {e}")

    def _count_by_category(self, invariants: List[SynthesizedInvariant]) -> Dict[str, int]:
        """Count invariants by category."""
        counts = {}
        for inv in invariants:
            cat = inv.category.value
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def _count_by_importance(self, invariants: List[SynthesizedInvariant]) -> Dict[str, int]:
        """Count invariants by importance."""
        counts = {}
        for inv in invariants:
            imp = inv.importance
            counts[imp] = counts.get(imp, 0) + 1
        return counts

    def _error_result(self, error: str, start_time: float) -> Dict[str, Any]:
        """Create error result."""
        return {
            "status": "error",
            "error": error,
            "invariants": [],
            "execution_time": time.time() - start_time,
        }


# Convenience function
def synthesize_invariants(
    contract_path: str,
    formats: Optional[List[str]] = None,
    max_invariants: int = 20,
) -> Dict[str, Any]:
    """
    Convenience function to synthesize invariants for a contract.

    Args:
        contract_path: Path to the Solidity contract
        formats: Output formats (solidity, certora, echidna, halmos, foundry)
        max_invariants: Maximum number of invariants

    Returns:
        Dictionary with synthesized invariants
    """
    synthesizer = InvariantSynthesizer()

    # Convert format strings to enums
    format_enums = None
    if formats:
        format_enums = []
        for f in formats:
            try:
                format_enums.append(InvariantFormat(f))
            except ValueError:
                logger.warning(f"Unknown format: {f}")

    return synthesizer.synthesize(
        contract_path=contract_path,
        formats=format_enums,
        max_invariants=max_invariants,
    )


__all__ = [
    "InvariantSynthesizer",
    "InvariantFormat",
    "InvariantCategory",
    "SynthesizedInvariant",
    "synthesize_invariants",
]
