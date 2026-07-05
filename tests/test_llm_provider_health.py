"""Tests for shared LLM provider health helpers."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp

from src.llm.provider_health import (
    extract_openai_compatible_model_ids,
    fetch_openai_compatible_model_ids,
)


def _aiohttp_session_with_response(method: str, response: MagicMock) -> MagicMock:
    """Build an aiohttp.ClientSession mock whose request method is an async CM."""
    request_context = MagicMock()
    request_context.__aenter__ = AsyncMock(return_value=response)
    request_context.__aexit__ = AsyncMock(return_value=None)

    session_instance = MagicMock()
    setattr(session_instance, method, MagicMock(return_value=request_context))

    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session_instance)
    session.__aexit__ = AsyncMock(return_value=None)
    return session


def test_extract_openai_compatible_model_ids_data_id_payload():
    """Test extracting model IDs from OpenAI-compatible data payloads."""
    payload = {"data": [{"id": "deepseek-v4-flash"}, {"id": "deepseek-v4-pro"}]}

    assert extract_openai_compatible_model_ids(payload) == {
        "deepseek-v4-flash",
        "deepseek-v4-pro",
    }


def test_extract_openai_compatible_model_ids_models_name_payload():
    """Test extracting model IDs from alternate models/name payloads."""
    payload = {"models": [{"name": "model-a"}, {"name": "model-b"}, {"other": "ignored"}]}

    assert extract_openai_compatible_model_ids(payload) == {"model-a", "model-b"}


def test_extract_openai_compatible_model_ids_nested_models_data_alias():
    """Test nested models/data aliases are accepted only when list-shaped."""
    payload = {"data": {"ignored": True}, "models": {"data": [{"id": "model-a"}]}}

    assert extract_openai_compatible_model_ids(payload) == {"model-a"}
    assert extract_openai_compatible_model_ids({"models": {"data": {"id": "bad"}}}) == set()


def test_extract_openai_compatible_model_ids_malformed_shapes():
    """Test malformed model payload shapes are ignored safely."""
    payload = {
        "data": "not-a-model-list",
        "models": [
            {"id": ["not", "hashable"]},
            {"id": ""},
            {"name": 123},
            "not-a-model-object",
            {"id": "model-a", "name": "ignored-fallback"},
        ],
    }

    assert extract_openai_compatible_model_ids(payload) == {"model-a"}
    assert extract_openai_compatible_model_ids(["not-a-payload-object"]) == set()
    assert extract_openai_compatible_model_ids({"data": None, "models": None}) == set()


def test_extract_openai_compatible_model_ids_falls_back_from_malformed_id_to_name():
    """Test malformed id fields do not suppress a valid model name fallback."""
    payload = {
        "data": [
            {"id": ["bad"], "name": " fallback-model "},
            {"id": "   ", "name": "ignored-empty-id"},
        ]
    }

    assert extract_openai_compatible_model_ids(payload) == {"fallback-model", "ignored-empty-id"}


def test_extract_openai_compatible_model_ids_ignores_nested_model_identifiers():
    """Test nested id/name objects do not leak reprs or become accepted identifiers."""
    payload = {
        "data": [
            {"id": {"value": "model-a"}, "name": {"value": "model-b"}},
            {"id": " valid-model ", "name": {"value": "ignored"}},
        ]
    }

    assert extract_openai_compatible_model_ids(payload) == {"valid-model"}


def test_extract_openai_compatible_model_ids_ignores_oversized_ids():
    """Test oversized model identifiers are ignored at the payload boundary."""
    payload = {"data": [{"id": "x" * 201}, {"id": "valid-model"}]}

    assert extract_openai_compatible_model_ids(payload) == {"valid-model"}


def test_extract_openai_compatible_model_ids_dedupes_normalized_duplicates():
    """Test duplicate IDs collapse after whitespace normalization."""
    payload = {
        "data": [
            {"id": " model-a "},
            {"id": "model-a", "name": "ignored-fallback"},
            {"id": "", "name": " model-a "},
            {"id": "model-b"},
        ]
    }

    assert extract_openai_compatible_model_ids(payload) == {"model-a", "model-b"}


def test_fetch_openai_compatible_model_ids_success():
    """Test fetching model IDs from a compatible endpoint."""

    async def run_test():
        response = MagicMock()
        response.status = 200
        response.json = AsyncMock(return_value={"data": [{"id": "deepseek-v4-flash"}]})
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example/",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == {"deepseek-v4-flash"}
        session.__aenter__.return_value.get.assert_called_once()
        url = session.__aenter__.return_value.get.call_args.args[0]
        assert url == "https://api.deepseek.example/v1/models"

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_rejects_malformed_endpoint_credentials():
    """Test malformed endpoint/key shapes are rejected before opening a session."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                ["https://api.deepseek.example"],
                {"token": "bad"},
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_rejects_empty_base_url():
    """Test empty base URL text is rejected before opening a session."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                "  ",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_rejects_non_http_base_url():
    """Test unsupported URL schemes are rejected before opening a session."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                "file:///tmp/models",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_rejects_empty_api_key():
    """Test empty API key text is rejected before opening a session."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "  ",
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_rejects_malformed_timeout():
    """Test malformed timeout shapes are rejected before opening a session."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                timeout=["10"],
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_rejects_non_positive_timeout():
    """Test non-positive timeout values are rejected before opening a session."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                timeout=0,
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_rejects_non_finite_timeout():
    """Test non-finite timeout values are rejected before opening a session."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                timeout=float("inf"),
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_defaults_malformed_provider_name(caplog):
    """Test malformed provider_name shapes do not leak reprs into logs."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                ["https://api.deepseek.example"],
                "test-key",
                provider_name={"name": "DeepSeek"},
            )

        assert models == set()
        session.assert_not_called()

    with caplog.at_level("DEBUG", logger="src.llm.provider_health"):
        asyncio.run(run_test())

    assert "provider model check received malformed endpoint credentials" in caplog.text
    assert "{'name': 'DeepSeek'}" not in caplog.text


def test_fetch_openai_compatible_model_ids_defaults_blank_provider_name(caplog):
    """Test blank provider labels fall back to the generic log prefix."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                ["https://api.deepseek.example"],
                "test-key",
                provider_name="   ",
            )

        assert models == set()
        session.assert_not_called()

    with caplog.at_level("DEBUG", logger="src.llm.provider_health"):
        asyncio.run(run_test())

    assert "provider model check received malformed endpoint credentials" in caplog.text


def test_fetch_openai_compatible_model_ids_malformed_payload():
    """Test malformed successful JSON payloads are treated as unavailable."""

    async def run_test():
        response = MagicMock()
        response.status = 200
        response.json = AsyncMock(return_value={"data": "not-a-model-list", "models": None})
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
            )

        assert models == set()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_accepts_sync_json_payload():
    """Test sync JSON adapters are tolerated at the response boundary."""

    async def run_test():
        response = MagicMock()
        response.status = 200
        response.json = MagicMock(return_value={"data": [{"id": "model-a"}]})
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
            )

        assert models == {"model-a"}

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_json_decode_error():
    """Test JSON decoding failures are treated as unavailable."""

    async def run_test():
        response = MagicMock()
        response.status = 200
        response.json = AsyncMock(side_effect=ValueError("invalid json"))
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
            )

        assert models == set()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_logs_non_object_payload(caplog):
    """Test non-object JSON payloads are rejected at fetch boundary."""

    async def run_test():
        response = MagicMock()
        response.status = 200
        response.json = AsyncMock(return_value=["not-a-payload-object"])
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()

    with caplog.at_level("DEBUG", logger="src.llm.provider_health"):
        asyncio.run(run_test())

    assert "DeepSeek model check returned malformed JSON body" in caplog.text


def test_fetch_openai_compatible_model_ids_malformed_response_status(caplog):
    """Test malformed response status shapes are rejected before body parsing."""

    async def run_test():
        response = MagicMock()
        response.status = "200"
        response.json = AsyncMock(return_value={"data": [{"id": "deepseek-v4-flash"}]})
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()
        response.json.assert_not_awaited()

    with caplog.at_level("DEBUG", logger="src.llm.provider_health"):
        asyncio.run(run_test())

    assert "DeepSeek model check returned malformed response status" in caplog.text


def test_fetch_openai_compatible_model_ids_non_200():
    """Test non-200 model endpoint responses are treated as unavailable."""

    async def run_test():
        response = MagicMock()
        response.status = 401
        response.json = AsyncMock(return_value={"error": "unauthorized"})
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "bad-key",
            )

        assert models == set()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_connection_error():
    """Test connection failures are treated as unavailable."""

    async def run_test():
        session_instance = MagicMock()
        session_instance.get.side_effect = aiohttp.ClientError("connection refused")

        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session_instance)
        session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
            )

        assert models == set()

    asyncio.run(run_test())
