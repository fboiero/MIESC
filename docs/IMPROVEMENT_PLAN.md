# MIESC — Plan de Mejoras

**Versión actual**: 5.4.2 · **Revisión del plan**: Junio 2026
**Estado**: código-completo. El backlog de ingeniería está mayormente saldado;
el foco se corre a **distribución y publicación**.

> Reemplaza al plan v5.1.0 (Febrero 2026), cuyos quick-wins ya se completaron
> (cobertura, escaneos de seguridad en CI, `.env.example`, link checker, Trivy,
> refactor de la CLI). Los números canónicos de benchmark y las claims matrices
> de los papers viven en los artefactos congelados, no en este documento.

---

## 1. Estado real (Junio 2026)

- **Tests**: ~6.000 pasando; cobertura ~78% (objetivo 80%).
- **Herramientas**: ~35 módulos (estáticos + ML + LLM + internos).
- **Capa LLM**: 6 adapters consolidados sobre `OllamaCallMixin`; manejo de
  timeout uniforme (`status="timeout"` en clock-kill, no falso "0 findings").
- **Benchmarks** (referencia; fuente canónica = artefactos congelados):
  SmartBugs recall alto static-only y mayor con Ollama; EVMBench ensemble #1.
- **Deuda visible**: ~0 TODOs/FIXMEs en `src/`/`miesc/`; sin issues abiertos.

**Conclusión**: el proyecto no espera más código para ser sólido. Espera ser
**publicado y distribuido**.

---

## 2. Backlog repensado (por impacto real)

### Tier 0 — Desbloquea todo (acción de Fernando)
- [ ] **Submit a SSRN** → obtener **DOI**.
- [ ] **Upload a arXiv** (bundle listo en `paper/miesc-arxiv.tar.gz`).
- [ ] Una vez con DOI: disparar grants + anuncios.

> Estos son los verdaderos bloqueantes. Nada de abajo mueve la aguja tanto.

### Tier 1 — Housekeeping (rápido, bajo riesgo)
- [ ] Mergear PRs de Dependabot: **#57** (codecov-action 6→7, solo CI) y
      **#58** (4 bumps PATCH: aiohttp, cbor2, idna, wcwidth).
- [ ] Mantener **CI Lint&Format** verde (black + ruff sobre `src/ tests/`)
      antes de cada merge — incorporar al flujo, no descubrirlo en CI.
- [x] Refrescar este plan a la realidad v5.4.2.

### Tier 2 — Crecimiento (producto / comunidad)
- [ ] **DPGA**: completar el proceso de certificación en curso.
- [ ] Grants (Starknet Foundation, EF ESP, NGI Zero) — actualizados a v5.4.x.
- [ ] Anuncios de release y difusión.
- [ ] UI/Streamlit: evolucionar en el repo `platform` (core queda en HTML/API).

### Tier 3 — Código nice-to-have (bajo)
- [ ] C4: descomponer `gptlens_adapter.py` (más chico tras extraer el mixin).
- [ ] DRY adicional entre adapters: compartir cache read/write y `_read_contract`
      vía el mismo patrón de mixin.
- [ ] Más cobertura del **path LLM** (no solo el estático).
- [ ] Subir cobertura 78% → 80%.

---

## 3. Métricas de éxito (actualizadas)

| Métrica | Estado | Objetivo |
|---------|--------|----------|
| Test coverage | ~78% | 80% |
| Tests en verde | ~6.000 | mantener |
| TODOs/FIXMEs en código | ~0 | 0 |
| Issues abiertos | 0 | 0 |
| CI Lint&Format | mantener verde | verde |
| Publicación (DOI/arXiv) | **pendiente** | **hecho** |

---

## 4. Cronograma sugerido

```
Ahora:      Tier 1 (PRs + lint verde) — yo
En paralelo: Tier 0 (SSRN/arXiv) — Fernando  ← desbloquea Tier 2
Luego:      Tier 2 (DPGA, grants, anuncios)
Oportunista: Tier 3 (refactors/cobertura, sin urgencia)
```

*Próxima revisión: cuando se obtenga el DOI (cierra Tier 0) o cambie el alcance.*
