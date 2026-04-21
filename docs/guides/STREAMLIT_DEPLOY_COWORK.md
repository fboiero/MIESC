# Streamlit Cloud Deploy — Prompt para Cowork

Copiá este prompt a Cowork:

---

```
Tarea: Deploy el webapp de MIESC a Streamlit Cloud.

Repo: https://github.com/fboiero/MIESC
Branch: main
Entry point: streamlit_app.py (en la raíz del repo)

Pasos:
1. Abrí https://share.streamlit.io en el browser del user.
2. Si el user no tiene cuenta, guialo a hacer Sign up con GitHub 
   (cuenta fboiero).
3. Click "New app".
4. Completá:
   - Repository: fboiero/MIESC
   - Branch: main
   - Main file path: streamlit_app.py
   - App URL: miesc (para que quede miesc.streamlit.app o similar)
5. En "Advanced settings":
   - Python version: 3.11 (recomendado, 3.12+ puede tener issues con
     algunas deps)
   - Requirements file: webapp/requirements.txt (IMPORTANTE: no usar el
     requirements.txt de la raíz porque tiene slither-analyzer que 
     necesita compilar binarios y falla en Streamlit Cloud)
6. Click "Deploy!"
7. Esperá ~3 minutos a que buildee. El primer deploy siempre es más lento.
8. Si falla:
   - Error "ModuleNotFoundError": verificá que webapp/requirements.txt 
     tiene la dep. Si falta, agregala al archivo y re-deployeá.
   - Error "src.licensing not found": la app necesita el path del repo.
     streamlit_app.py ya agrega el root al sys.path — no debería fallar.
   - Timeout: Streamlit Cloud free tier tiene 1GB RAM. Si la app consume
     más, reducí las features (deshabilitar LLM, reducir imports).
9. Una vez deployeado:
   a) Copiá la URL pública (tipo https://miesc.streamlit.app o 
      https://fboiero-miesc-streamlit-app-xxxxx.streamlit.app)
   b) Verificá que carga (debe mostrar el dashboard con tabs: 
      Upload & Analyze, Results, Report, System Status)
   c) Testeá: subí un .sol de ejemplo (examples/contracts/EtherStore.sol)
      y verificá que el analysis pattern-based funciona (no necesita 
      slither en Streamlit Cloud)
10. Una vez verificado:
    a) Agregá la URL al README.md como badge o link:
       [![Streamlit](https://img.shields.io/badge/Demo-Streamlit-FF4B4B)](URL)
    b) Commit: "docs: Add Streamlit Cloud live demo link"
    c) Push a main

REGLAS:
- NO modifiques webapp/app.py ni streamlit_app.py antes del deploy.
  Ya están testeados y funcionan.
- Si el deploy falla, copiá el error COMPLETO y frená. No inventes fixes.
- La URL final importa — se va a usar en las 3 aplicaciones de grant.

Cuando esté deployeado, respondeme con:
- URL pública del demo
- Confirmación de que el dashboard carga
- Screenshot o descripción de qué se ve al cargar
```

---

## Notas técnicas

- `streamlit_app.py` está en la raíz porque Streamlit Cloud autodetecta
  ese nombre. Bootstraps `webapp/app.py` via `from webapp.app import *`.
- `webapp/requirements.txt` es LEAN — solo streamlit, plotly, pydantic,
  pyyaml, jinja2, click, sqlalchemy. NO incluye slither ni heavy deps.
- La webapp funciona en "demo mode" sin tools instalados: muestra el
  dashboard, permite pegar código, corre pattern-based detectors (no
  subprocess-based tools).
- La URL se usa en los grant drafts (`grants/01_STARKNET_FOUNDATION.md`,
  `grants/02_EF_ESP.md`, `grants/03_NGI_ZERO.md`).
