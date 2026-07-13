"""Tests for shared LLM provider health helpers."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from miesc.llm.provider_health import (
    _authorization_headers,
    _model_id_text,
    _model_list,
    _provider_label,
    _valid_model_base_url,
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


def test_extract_openai_compatible_model_ids_nested_models_alias():
    """Test nested models/models aliases are accepted only when list-shaped."""
    payload = {"models": {"models": [{"id": "model-a"}]}}

    assert extract_openai_compatible_model_ids(payload) == {"model-a"}
    assert extract_openai_compatible_model_ids({"models": {"models": {"id": "bad"}}}) == set()


def test_extract_openai_compatible_model_ids_nested_model_alias():
    """Test nested models/model aliases are accepted only when list-shaped."""
    payload = {"models": {"model": [{"id": "model-a"}]}}

    assert extract_openai_compatible_model_ids(payload) == {"model-a"}
    assert extract_openai_compatible_model_ids({"models": {"model": {"id": "bad"}}}) == set()


def test_model_list_accepts_items_alias():
    payload = {"models": {"items": [{"id": "model-a"}]}}

    assert _model_list(payload) == [{"id": "model-a"}]
    assert _model_list({"models": {"items": [{"id": "model-a"}, "bad"]}}) == [
        {"id": "model-a"},
        "bad",
    ]


def test_provider_label_and_base_url_reject_control_chars():
    assert _provider_label("Deep\nSeek") == "provider"
    assert _valid_model_base_url("https://api.deepseek.example") is True
    assert _valid_model_base_url("http://8.8.8.8") is True
    assert _valid_model_base_url("https://api.deepseek.example/v1") is False
    assert _valid_model_base_url("https://api.deepseek.example/\n") is False
    assert _valid_model_base_url("https://api.deepseek.example\u2028") is False
    assert _valid_model_base_url("https://api.deepseek.example\u2029") is False


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:11434",
        "http://miesc.localhost:11434",
        "http://127.0.0.1:11434",
        "http://[::1]:11434",
        "http://10.0.0.7",
        "http://172.16.0.7",
        "http://192.168.1.7",
        "http://169.254.1.7",
        "http://0.0.0.0",
        "http://224.0.0.1",
    ],
)
def test_model_base_url_rejects_local_private_and_non_routable_hosts(base_url):
    assert _valid_model_base_url(base_url) is False


def test_model_id_text_rejects_del_characters():
    assert _model_id_text("  model-a  ") == "model-a"
    assert _model_id_text(b"  model-b  ") == "model-b"
    assert _model_id_text("model\x7fshadow") == ""
    assert _model_id_text("model\u2028shadow") == ""


def test_model_id_text_handles_strip_accessor_failure():
    class MalformedText(str):
        def strip(self):
            raise RuntimeError("secret model id")

    assert _model_id_text(MalformedText("model-a")) == ""


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


def test_extract_openai_compatible_model_ids_handles_mapping_accessor_failures():
    """Hostile mapping subclasses should not leak reprs or crash extraction."""

    class MalformedPayload(dict):
        def get(self, key, default=None):
            raise RuntimeError("secret payload body")

    class MalformedModel(dict):
        def get(self, key, default=None):
            raise RuntimeError("secret model body")

    assert extract_openai_compatible_model_ids(MalformedPayload({"data": []})) == set()
    assert (
        extract_openai_compatible_model_ids({"data": [MalformedModel({"id": "model-a"})]}) == set()
    )


def test_model_list_handles_nested_mapping_accessor_failures():
    """Nested provider payload aliases should tolerate broken mapping accessors."""

    class MalformedModels(dict):
        def get(self, key, default=None):
            raise RuntimeError("secret nested body")

    assert _model_list({"models": MalformedModels({"data": [{"id": "model-a"}]})}) is None


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


def test_extract_openai_compatible_model_ids_ignores_control_chars():
    """Test model identifiers with control characters are ignored."""
    payload = {"data": [{"id": "bad\nmodel"}, {"name": "also\tbad"}, {"id": "valid-model"}]}

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


def test_extract_openai_compatible_model_ids_bounds_payload_size():
    """Test oversized model payloads are bounded before returning IDs."""
    payload = {"data": [{"id": f"model-{i}"} for i in range(1205)]}

    models = extract_openai_compatible_model_ids(payload)

    assert len(models) == 1000
    assert "model-0" in models
    assert "model-999" in models
    assert "model-1000" not in models


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


def test_fetch_openai_compatible_model_ids_rejects_credentials_in_base_url():
    """Test URLs with embedded credentials are rejected before opening a session."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                "https://user:password@api.deepseek.example",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:11434",
        "http://127.0.0.1:11434",
        "http://[::1]:11434",
        "http://10.0.0.7",
        "http://169.254.1.7",
    ],
)
def test_fetch_openai_compatible_model_ids_rejects_private_hosts_before_network(base_url):
    """Provider health checks should not open sessions to local/private hosts."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                base_url,
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


@pytest.mark.parametrize(
    "base_url",
    [
        "https://api.deepseek.example/v1",
        "https://api.deepseek.example?tenant=a",
        "https://api.deepseek.example#models",
    ],
)
def test_fetch_openai_compatible_model_ids_rejects_endpoint_path_parts(base_url):
    """Test base URLs must not include endpoint paths, query strings, or fragments."""

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                base_url,
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


def test_authorization_headers_keep_api_key_out_of_debug_logs(caplog):
    """Test API key handling stays isolated from provider health debug logging."""
    secret = "sk-test-secret"

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
        headers = _authorization_headers(secret)

    assert headers == {"Authorization": f"Bearer {secret}"}
    assert secret not in caplog.text


def test_authorization_headers_reject_control_chars():
    assert _authorization_headers("  sk-test-secret  ") == {
        "Authorization": "Bearer sk-test-secret"
    }
    assert _authorization_headers("sk-test\nsecret") == {"Authorization": "Bearer "}
    assert _authorization_headers("sk-test\rsecret") == {"Authorization": "Bearer "}
    assert _authorization_headers("sk-test\u2028secret") == {"Authorization": "Bearer "}
    assert _authorization_headers("x" * 201) == {"Authorization": "Bearer "}
    assert _authorization_headers(123) == {"Authorization": "Bearer "}
    assert _authorization_headers(b"  sk-test-bytes  ") == {"Authorization": "Bearer sk-test-bytes"}


def test_provider_label_trims_and_rejects_control_chars():
    assert _provider_label("  DeepSeek  ") == "DeepSeek"
    assert _provider_label("DeepSeek\x7f") == "provider"
    assert _provider_label("DeepSeek\u2029") == "provider"
    assert _provider_label(b"  DeepSeek  ") == "DeepSeek"


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


def test_fetch_openai_compatible_model_ids_rejects_bool_timeout():
    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                timeout=True,
                provider_name="DeepSeek",
            )

        assert models == set()
        session.assert_not_called()

    asyncio.run(run_test())


def test_fetch_openai_compatible_model_ids_accepts_float_timeout():
    async def run_test():
        response = MagicMock()
        response.status = 200
        response.json = AsyncMock(return_value={"data": [{"id": "model-a"}]})
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                timeout=1.5,
                provider_name="DeepSeek",
            )

        assert models == {"model-a"}
        timeout = session.__aenter__.return_value.get.call_args.kwargs["timeout"]
        assert timeout.total == 1.5

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


def test_fetch_openai_compatible_model_ids_rejects_string_and_bytes_timeout():
    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            assert (
                await fetch_openai_compatible_model_ids(
                    "https://api.deepseek.example",
                    "test-key",
                    timeout="10",
                )
                == set()
            )
            assert (
                await fetch_openai_compatible_model_ids(
                    "https://api.deepseek.example",
                    "test-key",
                    timeout=b"10",
                )
                == set()
            )

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

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
        asyncio.run(run_test())

    assert "provider model check received malformed endpoint credentials" in caplog.text
    assert "{'name': 'DeepSeek'}" not in caplog.text


def test_fetch_openai_compatible_model_ids_bounds_provider_label(caplog):
    """Test oversized provider names are bounded in debug logging."""
    provider_name = "x" * 120

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            models = await fetch_openai_compatible_model_ids(
                [],
                "test-key",
                provider_name=provider_name,
            )

        assert models == set()
        session.assert_not_called()

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
        asyncio.run(run_test())

    assert "x" * 80 in caplog.text
    assert "x" * 81 not in caplog.text


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

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
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


def test_fetch_openai_compatible_model_ids_redacts_json_exception_text(caplog):
    async def run_test():
        response = MagicMock()
        response.status = 200
        response.json = AsyncMock(side_effect=ValueError("Bearer sk-secret prompt body"))
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
        asyncio.run(run_test())

    assert "ValueError" in caplog.text
    assert "Bearer sk-secret" not in caplog.text
    assert "prompt body" not in caplog.text


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

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
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

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
        asyncio.run(run_test())

    assert "DeepSeek model check returned malformed response status" in caplog.text


def test_fetch_openai_compatible_model_ids_rejects_bool_response_status(caplog):
    async def run_test():
        response = MagicMock()
        response.status = True
        response.json = AsyncMock(return_value={"data": [{"id": "model-a"}]})
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()
        response.json.assert_not_awaited()

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
        asyncio.run(run_test())

    assert "DeepSeek model check returned malformed response status" in caplog.text


def test_fetch_openai_compatible_model_ids_malformed_json_accessor(caplog):
    """Test malformed response JSON accessors are rejected before invocation."""

    async def run_test():
        response = MagicMock()
        response.status = 200
        response.json = {"data": [{"id": "deepseek-v4-flash"}]}
        session = _aiohttp_session_with_response("get", response)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
        asyncio.run(run_test())

    assert "DeepSeek model check returned malformed JSON accessor" in caplog.text


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


def test_fetch_openai_compatible_model_ids_redacts_client_error_text(caplog):
    async def run_test():
        session_instance = MagicMock()
        session_instance.get.side_effect = aiohttp.ClientError("Bearer sk-secret response body")

        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session_instance)
        session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=session):
            models = await fetch_openai_compatible_model_ids(
                "https://api.deepseek.example",
                "test-key",
                provider_name="DeepSeek",
            )

        assert models == set()

    with caplog.at_level("DEBUG", logger="miesc.llm.provider_health"):
        asyncio.run(run_test())

    assert "ClientError" in caplog.text
    assert "Bearer sk-secret" not in caplog.text
    assert "response body" not in caplog.text


def test_fetch_openai_compatible_model_ids_handles_strip_accessor_failures():
    class MalformedUrl(str):
        def strip(self):
            raise RuntimeError("secret url")

    class MalformedKey(str):
        def strip(self):
            raise RuntimeError("secret key")

    async def run_test():
        with patch("aiohttp.ClientSession") as session:
            assert (
                await fetch_openai_compatible_model_ids(
                    MalformedUrl("https://api.deepseek.example"),
                    "test-key",
                )
                == set()
            )
            assert (
                await fetch_openai_compatible_model_ids(
                    "https://api.deepseek.example",
                    MalformedKey("test-key"),
                )
                == set()
            )

        session.assert_not_called()

    asyncio.run(run_test())
