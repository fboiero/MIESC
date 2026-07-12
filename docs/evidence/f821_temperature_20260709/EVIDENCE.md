# Evidencia peritable — Bug latente F821 `temperature` (2026-07-09)

Hallazgo de un `NameError` latente en `FrontierLLMAdapter._analyze_openai`,
detectado durante la revisión de CI del PR #70 (integración de DeepSeek-V4).

## 1. Hallazgo

`src/adapters/frontier_llm_adapter.py`, método `_analyze_openai(self,
source_code, **kwargs)`: el método NO define ni recibe `temperature`, pero lo usa
en la rama no-reasoning del path OpenAI:

```python
else:
    token_param["max_tokens"] = 8192
    extra["temperature"] = temperature   # <-- indefinido → NameError
```

`ruff` lo marca como **F821 Undefined name `temperature`**. Cualquier llamada por
el path estándar de OpenAI (`--model gpt-4o` / `gpt-4.1`, no la rama gpt-5/o-series
de reasoning) dispararía `NameError: name 'temperature' is not defined`.

## 2. Causa raíz

Los métodos hermanos (`_analyze_anthropic`, los helpers de conversación con
herramientas) sí toman `temperature: float = 0.2` como parámetro. El path
no-reasoning de `_analyze_openai` simplemente omitía ese binding.

## 3. Fix

Definir `temperature` desde `kwargs` con el mismo default `0.2` de los hermanos:

```python
model = kwargs.get("model", "gpt-4o")
temperature = kwargs.get("temperature", 0.2)
```

Una línea; sin cambio de comportamiento salvo hacer el código existente
alcanzable sin crashear.

## 4. Verificación

```
# antes
$ ruff check src/adapters/frontier_llm_adapter.py --select F821
  frontier_llm_adapter.py:1426: F821 Undefined name `temperature`   (1 error)
# después
$ ruff check src/adapters/frontier_llm_adapter.py --select F821
  All checks passed!
```

Sintaxis (`py_compile`) OK. Diff: 1 archivo, 1 inserción.

## 5. Trazabilidad

- Rama: `fix/frontier-temperature-f821` (desde `origin/main` @ `cfd9c864`)
- Commit: `346ba235`
- PR: https://github.com/fboiero/MIESC/pull/71
- Contexto: detectado revisando la CI de https://github.com/fboiero/MIESC/pull/70

## 6. Nota

En el mismo archivo persiste un `F401` cosmético (`dataclasses.field` importado y
sin usar, línea 29) y ~64 `I001` (import-sort) en todo `src/` — deuda de lint
pre-existente en `main`, ajena a este bug. No se tocó para mantener el fix mínimo
y enfocado en el `NameError`.
