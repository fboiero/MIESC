# Instrucciones para release y publicación — MIESC v5.4.1

## 1. Publicar en PyPI (URGENTE)

El package en PyPI está en v5.0.3, hay que actualizar a 5.4.1.

```bash
cd /Users/fboiero/Documents/GitHub/MIESC

# Build
python3 -m build

# Upload (necesita credenciales de PyPI)
python3 -m twine upload dist/miesc-5.4.1*
```

Si no hay cuenta PyPI configurada:
```bash
# Crear token en https://pypi.org/manage/account/token/
# Guardar en ~/.pypirc o usar --username __token__ --password pypi-...
python3 -m twine upload --username __token__ --password pypi-XXXXX dist/miesc-5.4.1*
```

Verificar después:
```bash
pip install miesc==5.4.1
miesc --version  # debe decir 5.4.1
```

## 2. Docker: Retagear latest en GHCR

La imagen `ghcr.io/fboiero/miesc:5.4.1` existe pero `latest` no apunta a ella.

```bash
# Login a GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u fboiero --password-stdin

# Pull, retag, push
docker pull ghcr.io/fboiero/miesc:5.4.1
docker tag ghcr.io/fboiero/miesc:5.4.1 ghcr.io/fboiero/miesc:latest
docker push ghcr.io/fboiero/miesc:latest
```

Verificar:
```bash
docker run --rm ghcr.io/fboiero/miesc:latest --version
# Debe decir MIESC version 5.4.1
```

## 3. Publicar paper (ver INSTRUCCIONES_PUBLICACION.md)

El archivo con instrucciones detalladas está en:
`/Users/fboiero/Documents/GitHub/MIESC/paper/INSTRUCCIONES_PUBLICACION.md`

Resumen:
1. Subir a TechRxiv (inmediato, sin endorsement)
2. Intentar arXiv con cs.SE
3. Enviar emails de endorsement a 4 autores

## 4. Webapp en Streamlit Cloud (OPCIONAL)

La webapp funciona localmente con `make webapp`. Para deployarla:

1. Ir a https://share.streamlit.io
2. Login con GitHub (fboiero)
3. New App → repo: fboiero/MIESC → branch: main → file: webapp/app.py
4. Deploy

Nota: la webapp usa imports deprecated (src.miesc_core) que funcionan
pero muestran warnings. No es bloqueante.

## Resumen de prioridades

| # | Acción | Impacto | Esfuerzo |
|---|--------|---------|----------|
| 1 | Publicar PyPI 5.4.1 | ALTO — pip install funciona | 5 min |
| 2 | Retagear Docker latest | ALTO — docker run funciona | 5 min |
| 3 | Paper TechRxiv + arXiv | ALTO — citeable | 30 min |
| 4 | Webapp Streamlit Cloud | MEDIO — demo online | 10 min |
