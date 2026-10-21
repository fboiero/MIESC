"""Every captured real LLM response parses or fails cleanly (wave C4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from miesc.llm.json_extraction import extract_llm_json

FIXTURES = Path(__file__).parent / "fixtures" / "llm_responses"
EXPECTED_UNPARSEABLE = {
    line.strip()
    for line in (FIXTURES / "expected_unparseable.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
}
FILES = sorted(p for p in FIXTURES.glob("*.txt") if p.name != "expected_unparseable.txt")


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_fixture_parses_or_fails_cleanly(path: Path):
    text = path.read_text(encoding="utf-8")
    result = extract_llm_json(text, want="auto", log_prefix=path.stem)
    if path.name in EXPECTED_UNPARSEABLE:
        assert not result.ok
        assert result.error
        assert result.raw_excerpt == text[:2000]
    else:
        assert result.ok, f"{path.name}: {result.error}; attempts={result.attempts}"
        assert result.strategy


def test_frontier_unescaped_quotes_fixture_yields_the_finding():
    pytest.importorskip("json_repair")
    path = FIXTURES / "frontier_ollama_qwen2.5-coder-32b_unescaped_quotes.txt"
    result = extract_llm_json(path.read_text(encoding="utf-8"), want="array")
    assert result.ok and result.strategy == "json_repair"
    assert result.data[0]["type"] == "reentrancy"
