# LLM providers: cloud APIs and local models, configurable

MIESC can run its LLM passes against **Anthropic (Claude)**, **OpenAI (GPT)**, **DeepSeek**,
**Kimi (Moonshot)**, a **local Ollama** server, or **any OpenAI-compatible endpoint** you
declare (vLLM, OpenRouter, Together, a corporate gateway). One registry
(`miesc/core/llm_providers.py`) holds the endpoints, the key variables and the default
models; `scan --model`, `audit deep --llm-provider`, `MIESC_LLM_PROVIDER` and `miesc doctor`
all read it.

The reproducible paper profile stays LLM-free (`make bench`, `--no-llm`): nothing here changes
the published numbers.

## Built-in providers

| Name | Protocol | Endpoint | Key variable(s) | Default model |
|---|---|---|---|---|
| `anthropic` | Anthropic Messages | api.anthropic.com | `ANTHROPIC_API_KEY` | `claude-sonnet-4-6` |
| `openai` | OpenAI chat | api.openai.com | `OPENAI_API_KEY` | `gpt-4o` |
| `deepseek` | OpenAI-compatible | api.deepseek.com | `DEEPSEEK_API_KEY` | `deepseek-v4-flash` |
| `kimi` | OpenAI-compatible | api.moonshot.ai/v1 | `MOONSHOT_API_KEY` or `KIMI_API_KEY` | `kimi-k2-turbo-preview` |
| `ollama` | Ollama HTTP | `OLLAMA_HOST` (localhost:11434) | none | `qwen2.5-coder:14b` |

`<NAME>_BASE_URL` overrides an endpoint (`DEEPSEEK_BASE_URL`, `MOONSHOT_BASE_URL` for the
China region `https://api.moonshot.cn/v1`, `OPENAI_BASE_URL`). Keys are read from the
environment at call time and are never stored, logged or written into results or provenance;
only the endpoint host is recorded.

Model ids follow each vendor's catalogue and change over time. `miesc doctor` probes every
OpenAI-compatible provider whose key is set and says whether its default model is listed;
override the default under `llm.providers.<name>.default_model` when a vendor renames it.

## Choosing a model

```bash
miesc scan contract.sol --model kimi                      # provider -> its default model
miesc scan contract.sol --model kimi:kimi-k2-thinking     # provider:model
miesc scan contract.sol --model deepseek:pro              # provider:alias (deepseek-v4-pro)
miesc scan contract.sol --model ollama:qwen2.5-coder:32b  # Ollama tags keep their colon
miesc scan contract.sol --model claude                    # historical aliases still work
miesc audit deep contract.sol --llm-provider kimi         # narrative provider
MIESC_LLM_PROVIDER=kimi MIESC_LLM_MODEL=kimi-k2-thinking miesc audit full contract.sol
```

Resolution order: `provider:model` when the prefix is a registered name; the historical
aliases (`claude`, `claude-opus`, `gpt`, `gpt-5`, `deepseek-v4-pro`, `qwen32b`, `codellama`,
...); a bare provider name; a bare model id, whose provider is inferred from its prefix
(`claude-*`, `gpt-*`/`o*`, `deepseek-*`, `kimi-*`/`moonshot-*`, anything else is an Ollama
tag). An unknown prefix is rejected before any analysis runs, with the list of known names.

`--model auto` is not a value: with no `--model`, `FrontierLLMAdapter(provider="auto")` takes
the first of `anthropic`, `openai`, `deepseek`, `kimi` whose key is set.

## Adding your own endpoint

In `~/.miesc/config.yaml` (or `./miesc.yaml`, or the file named by `MIESC_CONFIG`):

```yaml
llm:
  providers:
    openrouter:
      kind: openai                      # openai | anthropic | ollama (client protocol)
      base_url: https://openrouter.ai/api/v1
      api_key_env: OPENROUTER_API_KEY   # one name or a list, checked in order
      default_model: qwen/qwen-2.5-coder-32b-instruct
      models:                           # optional aliases for provider:alias
        fast: meta-llama/llama-3.3-70b-instruct
      timeout: 300
    vllm:
      kind: openai
      base_url: http://gpu-box:8000/v1
      api_key_env: VLLM_API_KEY
      default_model: Qwen/Qwen2.5-Coder-32B-Instruct
    kimi:                               # overriding one field of a built-in
      default_model: kimi-k2-thinking
```

Then `miesc scan contract.sol --model openrouter:fast`, `--llm-provider vllm`, or
`MIESC_LLM_PROVIDER=vllm`. Entries with an unknown `kind`, a non-HTTP `base_url`, a URL with
credentials embedded, or a cloud `kind` without `api_key_env` are ignored (and `doctor` will not
list them).

## What goes where

| Path | Reads the registry for |
|---|---|
| `miesc scan --model` | the frontier pass (layer 9) on a file or directory |
| `miesc audit deep --llm-provider` | the executive narrative |
| `MIESC_LLM_PROVIDER` / `MIESC_LLM_MODEL` | the orchestrator behind `audit full` and the agents |
| `miesc doctor` | the "LLM Providers" table: key set or not, default model reachable or not |
| `--verify-model` (`scan`, `audit`) | the advisory LLM pass of the recall-safe `--verify-fp` gate; same `provider[:model]` forms, cheaper tier by default (`gpt-4o-mini`, `claude-haiku-4-5`, `deepseek-chat`), `MIESC_VERIFY_<NAME>_MODEL` overrides |

Not yet on the registry: the `--ensemble` provider list (`miesc/llm/ensemble_detector.py`) and
the older OpenAI-only agents under `miesc/agents/`; they keep their own `OPENAI_API_KEY` /
`ANTHROPIC_API_KEY` reading for now.

## Costs and determinism

Cloud calls are billed by the vendor. For a comparison across providers set
`MIESC_FRONTIER_NO_FALLBACK=1`, otherwise a failed Anthropic or OpenAI call falls back to the
other one when its key is set. OpenAI-compatible calls send `temperature 0` and a fixed seed
(`MIESC_LLM_SEED`, default 42) where the endpoint honours them. The frontier tool's result
metadata records `provider`, `model` and `base_url_host`; the provenance block records
`MIESC_LLM_PROVIDER` / `MIESC_LLM_MODEL` when they are set in the environment.
