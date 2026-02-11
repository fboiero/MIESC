# MIESC v5.1.0 - Guía de Instalación Completa

**[English Version](INSTALLATION.md)**

Esta guía cubre la instalación completa de MIESC desde cero, incluyendo todas las dependencias y herramientas.

## Tabla de Contenidos

- [Instalación Rápida](#instalación-rápida)
- [Requisitos del Sistema](#requisitos-del-sistema)
- [Instalación Paso a Paso](#instalación-paso-a-paso)
- [Instalación de Herramientas por Capa](#instalación-de-herramientas-por-capa)
- [Instalación con Docker](#instalación-con-docker)
- [Verificación](#verificación)
- [Solución de Problemas](#solución-de-problemas)

---

## Instalación Rápida

Para usuarios que quieren comenzar rápidamente con funcionalidad básica:

```bash
# Clonar repositorio
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Instalar MIESC y dependencias core
pip install -e .

# Instalar Slither (requerido para análisis básico)
pip install slither-analyzer

# Verificar instalación
python scripts/verify_installation.py
```

---

## Requisitos del Sistema

### Requisitos Mínimos

| Componente | Requisito |
|------------|-----------|
| SO | macOS 12+, Ubuntu 20.04+, Windows 10+ (WSL2) |
| Python | 3.12 o superior |
| Memoria | 8 GB RAM |
| Disco | 5 GB espacio libre |

### Requisitos Recomendados

| Componente | Requisito |
|------------|-----------|
| SO | macOS 14+, Ubuntu 22.04+ |
| Python | 3.12+ |
| Memoria | 16 GB RAM |
| Disco | 20 GB espacio libre (para todas las herramientas) |
| Node.js | 18+ (para Solhint) |
| Rust | 1.70+ (para Aderyn, Foundry) |
| Go | 1.21+ (para Medusa) |

---

## Instalación Paso a Paso

### Paso 1: Clonar Repositorio

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
```

### Paso 2: Crear Entorno Virtual (Recomendado)

```bash
python3.12 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# o: .venv\Scripts\activate  # Windows
```

### Paso 3: Instalar MIESC

```bash
# Instalación básica
pip install -e .

# Instalación completa (todas las dependencias opcionales)
pip install -e .[full]

# Instalación de desarrollo
pip install -e .[dev]
```

### Paso 4: Instalar Compilador de Solidity

```bash
pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20

# Verificar
solc --version
```

### Paso 5: Instalar Herramientas de Análisis Core

```bash
# Análisis Estático (Capa 1)
pip install slither-analyzer

# Verificar
slither --version
```

---

## Instalación de Herramientas por Capa

MIESC usa 31 herramientas organizadas en 9 capas. Instala las herramientas según tus necesidades.

### Capa 1: Análisis Estático (3 herramientas)

| Herramienta | Instalación | Requerida |
|-------------|-------------|-----------|
| Slither | `pip install slither-analyzer` | Sí |
| Aderyn | `cargo install aderyn` | Recomendada |
| Solhint | `npm install -g solhint` | Recomendada |

```bash
# Instalar todas las herramientas de Capa 1
pip install slither-analyzer
cargo install aderyn
npm install -g solhint
```

### Capa 2: Pruebas Dinámicas (4 herramientas)

| Herramienta | Instalación | Notas |
|-------------|-------------|-------|
| Echidna | Binario de releases | Fuzzer basado en propiedades |
| Medusa | Binario de releases | Fuzzer guiado por cobertura |
| Foundry | `curl -L foundry.paradigm.xyz \| bash && foundryup` | Toolkit completo |
| DogeFuzz | Incluido | Sin instalación externa |

```bash
# Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Echidna (macOS)
brew install echidna

# Echidna (Linux) - descargar de GitHub releases
wget https://github.com/crytic/echidna/releases/latest/download/echidna-linux-x86_64.tar.gz
tar -xzf echidna-linux-x86_64.tar.gz
sudo mv echidna /usr/local/bin/

# Medusa - descargar de GitHub releases
# https://github.com/crytic/medusa/releases
```

### Capa 3: Ejecución Simbólica (3 herramientas)

| Herramienta | Instalación | Notas |
|-------------|-------------|-------|
| Mythril | `pip install mythril` | Puede conflictuar con slither |
| Manticore | `pip install manticore[native]` | Solo Python 3.10 |
| Halmos | `pip install halmos` | Integración con Foundry |

```bash
# Mythril (instalar en venv separado si hay conflictos)
pip install mythril

# Halmos
pip install halmos

# Manticore (requiere Python 3.10)
# Mejor instalado en Docker o entorno separado
```

### Capa 4: Verificación Formal (3 herramientas)

| Herramienta | Instalación | Notas |
|-------------|-------------|-------|
| Certora | [certora.com](https://docs.certora.com) | Comercial, tier gratuito |
| SMTChecker | Incluido con solc | Incorporado |
| Wake | `pip install eth-wake` | Framework Python |

```bash
pip install eth-wake
```

### Capa 5: Pruebas de Propiedades (2 herramientas)

| Herramienta | Instalación | Notas |
|-------------|-------------|-------|
| PropertyGPT | Incluido | Generación de CVL |
| Vertigo | `pip install vertigo-rs` | Pruebas de mutación |

### Capa 6: Análisis IA/LLM (4 herramientas)

| Herramienta | Instalación | Notas |
|-------------|-------------|-------|
| SmartLLM | Incluido + Ollama | Análisis LLM local |
| GPTScan | Incluido | Requiere clave API de OpenAI |
| LLMSmartAudit | Incluido | LLM multi-agente |
| LLMBugScanner | Incluido + Ollama | Modelo deepseek-coder |

```bash
# Instalar Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Descargar modelos requeridos
ollama pull deepseek-coder:6.7b
ollama pull codellama
```

### Capa 7: Reconocimiento de Patrones / ML (4 herramientas)

| Herramienta | Instalación | Notas |
|-------------|-------------|-------|
| DA-GNN | Incluido | Red neuronal de grafos |
| SmartGuard | Incluido | Coincidencia de patrones |
| SmartBugs-ML | Incluido | Clasificador ML |
| ContractCloneDetector | Incluido | Detección de clones |

Todas incluidas, sin instalación externa requerida.

### Capa 8: Seguridad DeFi (4 herramientas)

| Herramienta | Instalación | Notas |
|-------------|-------------|-------|
| DeFi Analyzer | Incluido | Flash loan, oracle |
| MEV Detector | Incluido | Exposición a MEV |
| Gas Analyzer | Incluido | Optimización de gas |
| CrossChain | Incluido | Riesgos cross-chain |

Todas incluidas, sin instalación externa requerida.

### Capa 9: Detección Avanzada (4 herramientas)

| Herramienta | Instalación | Notas |
|-------------|-------------|-------|
| Advanced Detector | Incluido | Rug pull, honeypot |
| SmartBugs Detector | Incluido | Categorías SWC |
| Threat Model | Incluido | Modelado de amenazas |
| ZK Circuit | `cargo install circomspect` | Análisis ZK |

```bash
# Para análisis de circuitos ZK
cargo install circomspect
npm install -g circom snarkjs
```

---

## Instalación con Docker

Para un entorno completo y aislado con todas las herramientas preinstaladas:

### ARM64 (Apple Silicon)

```bash
docker build -t miesc:v5.1.0 .
docker run --rm -v $(pwd):/contracts miesc:v5.1.0 audit quick /contracts/MiContrato.sol
```

### x86_64 (Intel/AMD)

```bash
docker build --platform linux/amd64 -f Dockerfile.x86 -t miesc:v5.1.0-x86 .
docker run --platform linux/amd64 --rm -v $(pwd):/contracts miesc:v5.1.0-x86 audit quick /contracts/MiContrato.sol
```

### Imagen Pre-construida

```bash
# Descargar de GitHub Container Registry
docker pull ghcr.io/fboiero/miesc:latest    # Estándar (multi-arch, ~2-3GB)
docker pull ghcr.io/fboiero/miesc:full      # Completa - solo amd64 (~4GB)

# Ejecutar auditoría
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:latest audit quick /contracts/MiContrato.sol

# O construir localmente (usar el script de build para compatibilidad ARM)
./scripts/build-images.sh standard
./scripts/build-images.sh full              # En ARM: solicita confirmación para build nativo
docker run --rm -v $(pwd):/contracts miesc:latest audit quick /contracts/MiContrato.sol
```

---

## Verificación

Después de la instalación, verifica que todo funciona:

```bash
# Ejecutar script de verificación
python scripts/verify_installation.py

# O usar el CLI
miesc doctor
```

Salida esperada:

```
MIESC v5.1.0 - Verificación de Instalación
============================================================

1. Entorno Python
----------------------------------------
  [OK] Python 3.12.x

2. Dependencias Core de Python
----------------------------------------
  [OK] slither-analyzer (0.10.x)
  [OK] fastapi (0.104.x)
  ...

5. Registro de Adaptadores MIESC
----------------------------------------
  [OK] Todos los 31/31 adaptadores registrados
  [OK] XX herramientas actualmente disponibles

Resumen de Instalación
============================================================
¡MIESC está listo para usar!
```

---

## Solución de Problemas

### Falla la instalación de Mythril

Mythril puede conflictuar con slither-analyzer debido a requisitos de versión de z3-solver.

**Solución**: Instala Mythril en un entorno virtual separado o usa Docker:

```bash
# Opción 1: venv separado
python3 -m venv mythril-env
source mythril-env/bin/activate
pip install mythril

# Opción 2: Docker
docker run -it mythril/myth analyze /ruta/a/contrato.sol
```

### Manticore en ARM (Apple Silicon)

Manticore requiere arquitectura x86_64 y Python 3.10.

**Solución**: Usa Docker con emulación:

```bash
docker build --platform linux/amd64 -f Dockerfile.x86 -t miesc:x86 .
```

### Problemas de versión de solc

```bash
solc-select install 0.8.20
solc-select use 0.8.20
```

### Ollama no responde

```bash
# Iniciar servicio de Ollama
ollama serve &

# Verificar estado
ollama list

# Descargar modelos requeridos
ollama pull deepseek-coder:6.7b
```

### Falta Rust/Cargo

```bash
# Instalar Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Falta Node.js/npm

```bash
# macOS
brew install node

# Ubuntu
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Errores de permiso denegado

```bash
# Arreglar permisos de pip
pip install --user -e .

# O usar entorno virtual
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Próximos Pasos

Después de la instalación:

1. **Inicio Rápido**: `miesc audit quick contrato.sol`
2. **Auditoría Completa**: `miesc audit full contrato.sol`
3. **Interfaz Web**: `make webapp`
4. **Documentación**: [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)

---

## Soporte

- **Issues**: [github.com/fboiero/MIESC/issues](https://github.com/fboiero/MIESC/issues)
- **Email**: fboiero@frvm.utn.edu.ar
- **Documentación**: [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)

---

**Versión**: 5.1.0 | **Última Actualización**: Febrero 2026
