import aiohttp
import pytest

from src.llm.remediation_generator import RemediationGenerator, RemediationResult


@pytest.mark.asyncio
async def test_generate_remediations_sequential_counts_runtime_failures(monkeypatch):
    generator = RemediationGenerator()
    findings = [{"id": "A", "type": "reentrancy"}, {"id": "B", "type": "access-control"}]

    async def fake_generate(finding, _code):
        if finding["id"] == "B":
            raise RuntimeError("LLM unavailable")
        return object()

    monkeypatch.setattr(generator, "generate_remediation", fake_generate)

    result = await generator.generate_remediations(findings, "contract Test {}", parallel=False)

    assert isinstance(result, RemediationResult)
    assert result.success_count == 1
    assert result.failure_count == 1
    assert len(result.remediations) == 1


@pytest.mark.asyncio
async def test_query_llm_returns_empty_dict_on_client_error(monkeypatch):
    generator = RemediationGenerator()

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def post(self, *_args, **_kwargs):
            raise aiohttp.ClientError("connection refused")

    monkeypatch.setattr(aiohttp, "ClientSession", lambda: FakeSession())

    assert await generator._query_llm("fix this") == {}
