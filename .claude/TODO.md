# MIESC - Pendientes post v5.0.3

## Resuelto ✅

1. **Release to PyPI workflow** (run #21588442138)
   - Build, tests, PyPI publish, Docker multi-arch, release notes: todo OK
   - Test PyPI falló por Trusted Publisher no configurado (es opcional, no bloquea)

2. **Estado general del CI** - 10/10 workflows verdes

3. **Release notes v5.0.3** - Corregidas (antes decía "No Changes")
   - Comando `pip install` corregido (sin prefix `v`)
   - Comando `docker pull` corregido (repo en minúsculas)

4. **Workflow release.yml** - `if: always()` removido del job `publish` (era peligroso)

5. **Remote Plugin Marketplace** (commit `b473589`)
   - `src/plugins/marketplace.py`: MarketplaceClient con fetch, cache, search, browse, submissions
   - `data/marketplace/marketplace-index.json`: Index seed con plugin delegatecall
   - `data/marketplace/schema.json`: JSON Schema para validación CI
   - `data/marketplace/CONTRIBUTING.md`: Guía de submission
   - `tests/test_marketplace.py`: 67 tests (100% passing)
   - `.github/workflows/validate-marketplace.yml`: CI para validar PRs al index
   - CLI: `miesc plugins marketplace`, `miesc plugins submit`
   - `miesc plugins search` ahora busca marketplace + PyPI
   - `miesc plugins install` resuelve slugs del marketplace

## Verificado ✅

- PyPI: `pip install miesc==5.0.3` disponible (wheel + sdist)
- Docker: `docker pull ghcr.io/fboiero/miesc:5.0.3` funcional (amd64+arm64)
- Docker tags: `5.0.3`, `5.0`, `latest`
- CLI: `MIESC version 5.0.3` con 14 comandos operativos
- GitHub Release: https://github.com/fboiero/MIESC/releases/tag/v5.0.3

## Pendiente (Roadmap)

- [ ] Configurar Trusted Publisher en Test PyPI (opcional, baja prioridad)
- [ ] API Key Management (v5.0 Phase 3.1 / v4.5 Sprint 6.1)
- [ ] Team/Organization Model (v5.0 Phase 3.2 / v4.5 Sprint 6.2)
- [ ] Web Dashboard FastAPI (v5.0 Phase 3.2 / v4.5 Sprint 6.3)
- [ ] Continuous Monitoring (v5.0 Phase 3.3 / v4.5 Sprint 6.4)
