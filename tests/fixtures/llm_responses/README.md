# Real LLM responses used as parser fixtures

Raw model output captured on 2026-10-20 from local Ollama models while running
`miesc scan --model ollama` and `miesc audit full` on `examples/contracts/VulnerableBank.sol`
(`MIESC_LLM_DUMP_DIR` saves one file per response). Nothing is edited: these are the
strings the adapters actually had to parse. `tests/test_llm_response_fixtures.py` asserts
that every file either parses through `miesc.llm.json_extraction` or is reported as a
clean parse failure (never an exception). Files listed in `expected_unparseable.txt`
are known prose-only answers.

Name pattern: `<adapter>_<model>_<what makes it hard>.txt`.
