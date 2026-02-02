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

## Verificado ✅

- PyPI: `pip install miesc==5.0.3` disponible (wheel + sdist)
- Docker: `docker pull ghcr.io/fboiero/miesc:5.0.3` funcional (amd64+arm64)
- Docker tags: `5.0.3`, `5.0`, `latest`
- CLI: `MIESC version 5.0.3` con 14 comandos operativos
- GitHub Release: https://github.com/fboiero/MIESC/releases/tag/v5.0.3

## Pendiente

- [ ] Configurar Trusted Publisher en Test PyPI (opcional, baja prioridad)
