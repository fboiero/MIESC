# Probar Imágenes Docker de MIESC v5.0.3

**[English Version](DOCKER_TESTING_GUIDE.md)**

Instrucciones para descargar y verificar las últimas imágenes Docker.

---

## 1. Limpiar imágenes en caché antiguas (opcional)

```bash
docker rmi ghcr.io/fboiero/miesc:latest ghcr.io/fboiero/miesc:full 2>/dev/null
```

## 2. Descargar y verificar

```bash
# Estándar (~2GB, multi-arch: funciona nativamente en x86_64 y ARM)
docker pull ghcr.io/fboiero/miesc:latest
docker run --rm ghcr.io/fboiero/miesc:latest --version
docker run --rm ghcr.io/fboiero/miesc:latest doctor

# Completa (~3GB, solo amd64 en el registry)
docker pull ghcr.io/fboiero/miesc:full
docker run --rm ghcr.io/fboiero/miesc:full --version
docker run --rm ghcr.io/fboiero/miesc:full doctor
```

Ambos comandos deberían mostrar **MIESC versión 5.0.3**.

## 3. Ejecutar un escaneo de prueba

```bash
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MiContrato.sol
```

## 4. Tags disponibles

| Tag | Contenido |
|-----|-----------|
| `miesc:latest` / `miesc:5.0.3` | Estándar: Slither, Aderyn, Solhint, Foundry (~15 herramientas) |
| `miesc:full` / `miesc:5.0.3-full` | Completa: + Mythril, Manticore, Echidna, Halmos, PyTorch (~30 herramientas) |

> **Nota:** Ignora cualquier versión anterior (pre-5.0.3) que pueda aparecer en el registry. Siempre usa los tags listados arriba.

## 5. ARM / Apple Silicon

La imagen `:latest` (estándar) es multi-arch y corre nativamente en ARM.

La imagen `:full` en el registry es solo amd64. En ARM corre bajo emulación QEMU (~3-5x más lento). Para rendimiento nativo, construye localmente:

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
./scripts/build-images.sh full
```

El script de build detectará ARM y pedirá confirmación (la compilación de z3-solver toma ~30-60 min). La imagen resultante corre a velocidad nativa.

Alternativamente, usa el asistente de configuración que te guía por todas las opciones:

```bash
./scripts/docker-setup.sh
```
