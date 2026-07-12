# Lista de Materiales de Software (SBOM)

**[English Version](SBOM.md)**

Este documento describe el proceso de generación, distribución y verificación del SBOM de MIESC.

---

## Descripción General

MIESC proporciona una Lista de Materiales de Software (SBOM) para la transparencia de la cadena de suministro. El SBOM lista todas las dependencias, sus versiones y licencias.

**Formato**: [CycloneDX](https://cyclonedx.org/) JSON (estándar de la industria)

---

## Disponibilidad del SBOM

### SBOM de Releases

Cada release de GitHub incluye:

| Archivo | Descripción |
|---------|-------------|
| `sbom.json` | SBOM completo en formato CycloneDX JSON |
| `licenses.csv` | Resumen de licencias de todas las dependencias |

Descargar desde: [GitHub Releases](https://github.com/fboiero/MIESC/releases)

### SBOM de Artefactos

Las instantáneas semanales del SBOM se almacenan como artefactos de GitHub Actions:

1. Ir a [Actions > SBOM Generation](https://github.com/fboiero/MIESC/actions/workflows/sbom.yml)
2. Seleccionar una ejecución del workflow
3. Descargar el artefacto `sbom-*`

Los artefactos se retienen durante **90 días**.

---

## Contenido del SBOM

El SBOM incluye:

- **Nombre del componente**: Nombre del paquete
- **Versión**: Versión instalada
- **Licencia**: Identificador de licencia SPDX
- **Hashes**: Sumas de verificación SHA256 (cuando estén disponibles)
- **PURL**: Package URL para su identificación

### Entrada de Ejemplo

```json
{
  "type": "library",
  "name": "slither-analyzer",
  "version": "0.10.0",
  "purl": "pkg:pypi/slither-analyzer@0.10.0",
  "licenses": [
    {
      "license": {
        "id": "AGPL-3.0-only"
      }
    }
  ]
}
```

---

## Generar el SBOM Localmente

### Usando CycloneDX

```bash
# Instalar CycloneDX
pip install cyclonedx-bom

# Generar desde el entorno instalado
cyclonedx-py environment -o sbom.json --of JSON

# Generar desde un archivo de requirements
cyclonedx-py requirements requirements.txt -o sbom.json --of JSON
```

### Usando pip-licenses

```bash
# Instalar pip-licenses
pip install pip-licenses

# Generar reporte de licencias
pip-licenses --format=markdown

# Generar CSV para análisis
pip-licenses --format=csv > licenses.csv
```

### Usando Syft

```bash
# Instalar syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Generar SBOM desde un directorio
syft dir:. -o cyclonedx-json > sbom.json

# Generar desde una imagen Docker
syft ghcr.io/fboiero/miesc:latest -o cyclonedx-json > docker-sbom.json
```

---

## Verificación del SBOM

### Validar el Formato

```bash
# Instalar cyclonedx-cli
npm install -g @cyclonedx/cyclonedx-cli

# Validar el SBOM
cyclonedx validate --input-file sbom.json
```

### Comprobar Vulnerabilidades

```bash
# Usando grype (Anchore)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
grype sbom:sbom.json

# Usando osv-scanner (Google)
pip install osv-scanner
osv-scanner --sbom sbom.json
```

---

## Calendario de Actualización del SBOM

| Disparador | Cuándo |
|------------|--------|
| Release | En cada release de GitHub |
| Programado | Semanalmente (domingo 2 AM UTC) |
| Manual | Bajo demanda vía workflow_dispatch |

---

## Cumplimiento de Licencias

### Licencias Permitidas

MIESC (AGPL-3.0) es compatible con:

| Licencia | Compatible | Notas |
|----------|------------|-------|
| MIT | ✅ | Permisiva |
| Apache-2.0 | ✅ | Permisiva |
| BSD-2-Clause | ✅ | Permisiva |
| BSD-3-Clause | ✅ | Permisiva |
| ISC | ✅ | Permisiva |
| LGPL-2.1+ | ✅ | Copyleft débil |
| LGPL-3.0 | ✅ | Copyleft débil |
| GPL-3.0 | ✅ | Mismos términos |
| AGPL-3.0 | ✅ | Misma licencia |

### Potencialmente Problemáticas

| Licencia | Estado | Acción |
|----------|--------|--------|
| GPL-2.0-only | ⚠️ Revisar | Comprobar compatibilidad |
| Propietaria | ❌ Evitar | No se puede incluir |
| SSPL | ❌ Evitar | No aprobada por la OSI |

---

## Seguridad de la Cadena de Suministro

### Atestaciones SLSA

Los releases futuros incluirán atestaciones [SLSA](https://slsa.dev/):

- **Nivel 1**: Documentación (actual)
- **Nivel 2**: Procedencia firmada (en progreso)
- **Nivel 3**: Builds endurecidos (planificado)

### Fijado de Dependencias

Todas las dependencias están fijadas en:

- `pyproject.toml`: Restricciones de versión
- `requirements-lock.txt`: Versiones exactas

### Escaneo de Vulnerabilidades

Las dependencias se escanean:

- **En cada PR**: comprobación con pip-audit
- **Semanalmente**: escaneo programado de vulnerabilidades
- **En cada release**: auditoría de seguridad completa

Ver [dependency-security.yml](https://github.com/fboiero/MIESC/blob/main/.github/workflows/dependency-security.yml).

---

## Integración con Otras Herramientas

### Dependency-Track

Importar el SBOM en [Dependency-Track](https://dependencytrack.org/):

```bash
curl -X POST "https://your-dt-server/api/v1/bom" \
  -H "X-Api-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @sbom.json
```

### Grafo de Dependencias de GitHub

El SBOM se sube automáticamente al grafo de dependencias de GitHub cuando está disponible.

### Snyk

```bash
snyk sbom --file=sbom.json
```

---

## Política de Retención

| Tipo de SBOM | Retención | Ubicación |
|--------------|-----------|-----------|
| SBOM de Release | Permanente | Assets del Release de GitHub |
| SBOM de Artefacto | 90 días | Artefactos de GitHub Actions |
| SBOM de Docker | Con la imagen | Registro de contenedores |

---

## Contacto

Preguntas sobre el SBOM o la seguridad de la cadena de suministro:

- **Email**: fboiero@frvm.utn.edu.ar
- **Problemas de Seguridad**: [SECURITY.md](SECURITY.md)

---

## Referencias

- [Especificación de CycloneDX](https://cyclonedx.org/specification/overview/)
- [Lista de Licencias SPDX](https://spdx.org/licenses/)
- [Framework SLSA](https://slsa.dev/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)

---

*Última actualización: Febrero 2026*
