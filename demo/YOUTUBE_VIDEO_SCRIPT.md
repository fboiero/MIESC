# MIESC - Video de Demostración para YouTube

## Información del Video

| Propiedad | Valor |
|-----------|-------|
| **Duración objetivo** | 5-7 minutos |
| **Audiencia** | Desarrolladores Solidity, auditores de seguridad, equipos DeFi |
| **Idioma** | Español (con subtítulos en inglés opcional) |
| **Formato** | Terminal + overlays explicativos |

---

## Estructura del Video

### INTRO (0:00 - 0:30) - 30 segundos

**Visual:** Logo MIESC animado, luego terminal con banner

**Narración:**
> "MIESC - Multi-layer Intelligent Evaluation for Smart Contracts.
> Un framework de seguridad que integra 31 herramientas en 9 capas de defensa
> para analizar smart contracts de Ethereum.
> En este video vamos a ver cómo instalarlo y usarlo paso a paso."

**Comandos:** (solo mostrar banner)
```bash
miesc --version
```

**Texto en pantalla:**
- "31 herramientas de seguridad"
- "9 capas de defensa"
- "100% Precisión en benchmarks"

---

### SECCIÓN 1: Instalación (0:30 - 1:30) - 60 segundos

**Visual:** Terminal limpia

**Narración:**
> "La instalación es simple. Solo necesitas Python 3.12 y pip.
> Ejecutamos pip install miesc y en segundos está listo.
> Verificamos con miesc doctor que muestra todas las herramientas disponibles."

**Comandos:**
```bash
# Mostrar instalación
pip install miesc

# Verificar versión
miesc --version

# Verificar herramientas
miesc doctor
```

**Puntos a destacar:**
- Instalación rápida
- Doctor muestra 31/31 herramientas
- Colores indican disponibilidad

---

### SECCIÓN 2: Escaneo Rápido (1:30 - 2:30) - 60 segundos

**Visual:** Terminal con contrato vulnerable

**Narración:**
> "Empecemos con un escaneo rápido. El comando miesc scan analiza un contrato
> en segundos usando las herramientas más rápidas.
> Vemos que detectó vulnerabilidades de reentrancy y access control."

**Comandos:**
```bash
# Mostrar contrato vulnerable brevemente
cat contracts/audit/VulnerableBank.sol | head -30

# Escaneo rápido
miesc scan contracts/audit/VulnerableBank.sol

# Modo CI (para pipelines)
miesc scan contracts/audit/VulnerableBank.sol --ci
```

**Puntos a destacar:**
- Análisis en segundos
- Detecta reentrancy
- Modo CI para automatización

---

### SECCIÓN 3: Auditoría Completa de 9 Capas (2:30 - 4:00) - 90 segundos

**Visual:** Terminal mostrando progreso por capas

**Narración:**
> "Para un análisis profundo, usamos miesc audit full.
> Esto ejecuta las 9 capas de defensa:
> Capa 1 - Análisis estático con Slither, Aderyn y Solhint.
> Capa 2 - Testing dinámico con Echidna y Foundry.
> Capa 3 - Ejecución simbólica con Mythril.
> Capa 4 - Verificación formal con Certora.
> Capa 5 - Property testing.
> Capa 6 - Análisis con IA y LLMs.
> Capa 7 - Reconocimiento de patrones con ML.
> Capa 8 - Seguridad DeFi especializada.
> Capa 9 - Detección avanzada y threat modeling.
> Cada herramienta agrega una capa de confianza al resultado."

**Comandos:**
```bash
# Auditoría rápida (4 herramientas principales)
miesc audit quick contracts/audit/VulnerableBank.sol

# Auditoría completa (todas las capas)
miesc audit full contracts/audit/VulnerableBank.sol --verbose

# Auditoría de capa específica
miesc audit layer 3 contracts/audit/VulnerableBank.sol
```

**Overlay visual:** Diagrama de las 9 capas

---

### SECCIÓN 4: Generación de Reportes (4:00 - 4:45) - 45 segundos

**Visual:** Terminal + preview del reporte

**Narración:**
> "MIESC genera reportes profesionales para clientes.
> Guardamos los resultados en JSON y luego aplicamos una plantilla.
> Tenemos templates para reportes ejecutivos, técnicos y para PR de GitHub.
> El reporte incluye descripción, impacto, y recomendaciones de remediación."

**Comandos:**
```bash
# Guardar resultados en JSON
miesc audit quick contracts/audit/VulnerableBank.sol -o results.json

# Generar reporte profesional
miesc report results.json -t professional -o AUDIT_REPORT.md

# Generar resumen ejecutivo
miesc report results.json -t executive --client "DeFi Protocol" -o summary.md

# Ver el reporte
cat AUDIT_REPORT.md | head -50
```

---

### SECCIÓN 5: Benchmark y Tracking (4:45 - 5:15) - 30 segundos

**Visual:** Terminal con comparación

**Narración:**
> "Para equipos que quieren trackear su postura de seguridad,
> el comando benchmark guarda el estado actual y permite comparar
> con versiones anteriores. Así pueden ver el progreso después de cada fix."

**Comandos:**
```bash
# Guardar benchmark actual
miesc benchmark contracts/ --save

# Comparar con última ejecución
miesc benchmark contracts/ --compare last

# Ver historial
miesc benchmark contracts/ --history
```

---

### SECCIÓN 6: Integraciones (5:15 - 6:00) - 45 segundos

**Visual:** Código de configuración

**Narración:**
> "MIESC se integra con tu flujo de trabajo existente.
> Para Foundry, solo agregas un hook en foundry.toml.
> Para Hardhat, instalas el plugin y configuras en hardhat.config.
> También hay extensión de VS Code y hooks de pre-commit.
> Todo se ejecuta automáticamente cuando compilas o haces commit."

**Mostrar archivos:**
```toml
# foundry.toml
[profile.default]
post_build_hook = "miesc audit quick ./src --ci"
```

```javascript
// hardhat.config.js
require("hardhat-miesc");
module.exports = {
  miesc: { runOnCompile: true, failOn: "high" }
};
```

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/fboiero/MIESC
    hooks:
      - id: miesc-quick
```

---

### SECCIÓN 7: Custom Detectors (6:00 - 6:30) - 30 segundos

**Visual:** Código Python

**Narración:**
> "Los investigadores de seguridad pueden crear detectores personalizados.
> Es una API simple en Python. Defines el patrón a buscar y MIESC
> lo ejecuta junto con las demás herramientas."

**Comandos:**
```bash
# Listar detectores
miesc detectors list

# Ejecutar detectores custom
miesc detectors run contracts/audit/VulnerableBank.sol
```

---

### CIERRE (6:30 - 7:00) - 30 segundos

**Visual:** Logo + URLs

**Narración:**
> "MIESC es open source bajo licencia AGPL.
> Instalalo con pip install miesc.
> Documentación completa en fboiero.github.io/MIESC.
> Dale star en GitHub y contribuye al proyecto.
> MIESC - Seguridad profesional para smart contracts."

**Texto en pantalla:**
```
pip install miesc
github.com/fboiero/MIESC
fboiero.github.io/MIESC

Star on GitHub!
```

---

## Metadatos para YouTube

### Título
```
MIESC - Auditoría de Smart Contracts con 31 Herramientas en 9 Capas | Tutorial Completo
```

### Título alternativo (inglés)
```
MIESC - Smart Contract Security: 31 Tools, 9 Defense Layers | Full Tutorial
```

### Descripción
```
MIESC (Multi-layer Intelligent Evaluation for Smart Contracts) es un framework de seguridad
defense-in-depth que integra 31 herramientas de análisis en 9 capas especializadas.

En este video aprenderás:
- Cómo instalar MIESC
- Escaneo rápido de vulnerabilidades
- Auditoría completa de 9 capas
- Generación de reportes profesionales
- Integración con Foundry, Hardhat y VS Code
- Tracking de postura de seguridad

Capas de análisis:
1. Análisis Estático (Slither, Aderyn, Solhint)
2. Testing Dinámico (Echidna, Medusa, Foundry)
3. Ejecución Simbólica (Mythril, Manticore, Halmos)
4. Verificación Formal (Certora, SMTChecker)
5. Property Testing (PropertyGPT, Wake)
6. Análisis AI/LLM (SmartLLM, GPTScan)
7. Reconocimiento de Patrones (DA-GNN, SmartGuard)
8. Seguridad DeFi (MEV Detector, Gas Analyzer)
9. Detección Avanzada (Threat Model, SmartBugs)

Instalación:
pip install miesc

Enlaces:
- GitHub: https://github.com/fboiero/MIESC
- Documentación: https://fboiero.github.io/MIESC
- PyPI: https://pypi.org/project/miesc/

Resultados validados (SmartBugs-curated, 50 contratos):
- Precisión: 100%
- Recall: 70%
- F1-Score: 82.35%

#smartcontract #ethereum #solidity #security #audit #blockchain #defi #web3
#slither #mythril #echidna #foundry #hardhat
```

### Tags
```
smart contract, ethereum, solidity, security, audit, blockchain, defi, web3,
slither, mythril, echidna, foundry, hardhat, vulnerability, reentrancy,
static analysis, symbolic execution, formal verification, fuzzing,
security tools, python, cli, open source
```

### Thumbnail sugerido
- Fondo oscuro con código Solidity
- Logo MIESC prominente
- Texto: "31 TOOLS | 9 LAYERS"
- Iconos de vulnerabilidades detectadas

---

## Comandos de Grabación

### Grabar con asciinema
```bash
asciinema rec demo_miesc.cast --cols 120 --rows 35
```

### Convertir a GIF/MP4
```bash
# Instalar agg (asciinema gif generator)
cargo install agg

# Convertir a GIF
agg demo_miesc.cast demo_miesc.gif --theme monokai --font-size 14

# Convertir a MP4 con ffmpeg
ffmpeg -i demo_miesc.gif -movflags faststart -pix_fmt yuv420p demo_miesc.mp4
```

### Agregar voz (macOS)
```bash
# Generar audio con voz del sistema
say -v "Jorge" "texto de narración" -o narration.aiff
ffmpeg -i narration.aiff narration.mp3
```

### Combinar video y audio
```bash
ffmpeg -i demo_miesc.mp4 -i narration.mp3 -c:v copy -c:a aac -shortest final_video.mp4
```

---

## Checklist Pre-Grabación

- [ ] Limpiar terminal (clear, reset)
- [ ] Aumentar tamaño de fuente del terminal
- [ ] Tema oscuro con buen contraste
- [ ] Tener contratos de ejemplo listos
- [ ] Verificar que todas las herramientas funcionan (`miesc doctor`)
- [ ] Practicar los comandos 2-3 veces
- [ ] Preparar overlays/gráficos
- [ ] Testear audio de narración
