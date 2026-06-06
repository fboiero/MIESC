# Estado de release y publicación — MIESC v5.4.2

## 1. PyPI

Estado: completado.

El paquete `miesc==5.4.2` ya está publicado en PyPI:
https://pypi.org/project/miesc/5.4.2/

Verificación:
```bash
pip install miesc==5.4.2
miesc --version  # debe decir 5.4.2
```

No intentar republish de `5.4.2`: PyPI no permite reemplazar archivos de una
versión ya publicada. Para cambios nuevos, usar una versión nueva.

## 2. Docker / GHCR

Estado: completado.

La imagen fija `ghcr.io/fboiero/miesc:5.4.2` resuelve a:

```text
sha256:17c06605e44236a01237c7210a7734d08b801e6338872550d0fcf4070190b3d8
```

El tag móvil `ghcr.io/fboiero/miesc:latest` existe y actualmente es un índice
OCI multi-arch:

```text
sha256:1deaab8f13e2b91b8280f2d1bfc075571edde3c513d99c32c4c8697e91598be7
```

Para evidencia reproducible, usar `5.4.2` o su digest. Usar `latest` sólo para
instalaciones nuevas o smoke tests de conveniencia.

Verificar:
```bash
docker run --rm ghcr.io/fboiero/miesc:latest --version
# Debe decir MIESC version 5.4.2
```

## 3. Publicar paper (pendiente humano)

El archivo con instrucciones detalladas está en:
`/Users/fboiero/Documents/GitHub/MIESC/paper/INSTRUCCIONES_PUBLICACION.md`

Resumen:
1. Subir a TechRxiv (inmediato, sin endorsement)
2. Intentar arXiv con cs.SE
3. Enviar emails de endorsement a 4 autores

Cuando haya DOI o arXiv ID:

1. Actualizar `CITATION.cff`.
2. Agregar el link en `README.md`, `README_ES.md` y `docs/ANNOUNCE_DRAFT.md`.
3. Registrar el DOI/arXiv ID en `docs/policies/RELEASE_STATUS_5.4.2.md`.
4. Revalidar `sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh`.

## 4. Plataforma web (opcional)

La webapp interactiva fue movida fuera del core público. Para demo online,
usar el repositorio de plataforma y consumir MIESC desde un tag o imagen Docker
publicada.

El core público mantiene las superficies reproducibles:

```bash
python -m miesc.api.rest --host 127.0.0.1 --port 8000
python -m src.utils.web_dashboard --results analysis/results --output analysis/dashboard
```

## Resumen de prioridades

| # | Acción | Estado | Próximo paso |
|---|--------|--------|--------------|
| 1 | PyPI 5.4.2 | Completado | Sólo verificar instalación si hace falta |
| 2 | GHCR latest | Completado | Sólo verificar digest si hace falta |
| 3 | Paper TechRxiv | Pendiente | Subir `paper/miesc-paper.pdf` |
| 4 | Paper arXiv | Pendiente | Subir `paper/miesc-arxiv.tar.gz` |
| 5 | Endorsement arXiv | Condicional | Enviar emails si arXiv lo pide |
| 6 | Demo en plataforma web | Opcional | Consumir core desde PyPI o GHCR |
