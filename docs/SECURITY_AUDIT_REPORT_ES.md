# Informe de Auditoría de Seguridad - MIESC

**Versión:** 5.1.1
**Fecha de Auditoría:** 16 de Febrero de 2026
**Auditor:** Revisión Interna de Seguridad
**Clasificación:** Uso Interno

---

## Resumen Ejecutivo

### Puntuación General de Seguridad: 8.2/10 (Sólido)

| Categoría | Puntuación | Estado |
|-----------|------------|--------|
| Gestión de Secretos | 7.5/10 | Requiere Corrección |
| Validación de Entrada | 9.5/10 | Excelente |
| Protección contra Inyección | 9.0/10 | Excelente |
| Dependencias | 8.5/10 | Bueno |
| Seguridad Docker | 8.0/10 | Bueno |
| Seguridad LLM/IA | 9.5/10 | Excelente |
| Seguridad CI/CD | 9.0/10 | Excelente |

### Resumen de Riesgos

| Severidad | Cantidad | Estado |
|-----------|----------|--------|
| **CRÍTICO** | 2 | Corrección Inmediata |
| **ALTO** | 2 | Corregir Este Sprint |
| **MEDIO** | 8 | Corregir Pronto |
| **BAJO** | 6 | Backlog |
| **INFO** | 5 | Mejores Prácticas |

---

## Índice

1. [Hallazgos Críticos](#1-hallazgos-críticos)
2. [Hallazgos de Alta Prioridad](#2-hallazgos-de-alta-prioridad)
3. [Hallazgos de Prioridad Media](#3-hallazgos-de-prioridad-media)
4. [Hallazgos de Baja Prioridad](#4-hallazgos-de-baja-prioridad)
5. [Controles de Seguridad Positivos](#5-controles-de-seguridad-positivos)
6. [Recomendaciones](#6-recomendaciones)
7. [Estado de Cumplimiento](#7-estado-de-cumplimiento)
8. [Apéndice](#8-apéndice)

---

## 1. Hallazgos Críticos

### CRIT-001: Clave API Admin Predeterminada Hardcodeada

**Severidad:** CRÍTICO
**Puntuación CVSS:** 9.1 (Crítico)
**CWE:** CWE-798 (Uso de Credenciales Hardcodeadas)

**Ubicación:**
- `src/licensing/admin_api.py:38`
- `docker/docker-compose.prod.yml:55`

**Código Vulnerable:**
```python
# src/licensing/admin_api.py:38
ADMIN_API_KEY = os.getenv("MIESC_ADMIN_API_KEY", "miesc-admin-secret-key")
```

```yaml
# docker/docker-compose.prod.yml:55
- MIESC_ADMIN_API_KEY=${MIESC_ADMIN_API_KEY:-miesc-admin-secret-key}
```

**Impacto:**
- Acceso no autorizado a la API de administración de licencias
- Potencial manipulación o bypass de licencias
- Credencial predeterminada expuesta en código fuente e imágenes Docker

**Remediación:**
```python
# Opción 1: Requerir configuración explícita
ADMIN_API_KEY = os.getenv("MIESC_ADMIN_API_KEY")
if not ADMIN_API_KEY:
    raise RuntimeError("La variable de entorno MIESC_ADMIN_API_KEY es requerida")
```

```yaml
# docker-compose.prod.yml - Requerir variable
- MIESC_ADMIN_API_KEY=${MIESC_ADMIN_API_KEY:?ERROR: MIESC_ADMIN_API_KEY es requerida}
```

---

### CRIT-002: Configuración CORS Permite Todos los Orígenes

**Severidad:** CRÍTICO
**Puntuación CVSS:** 8.6 (Alto)
**CWE:** CWE-942 (Lista Blanca Cross-domain Demasiado Permisiva)

**Ubicación:** `src/licensing/admin_api.py:28-35`

**Código Vulnerable:**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # PELIGROSO: Permite cualquier origen
    allow_credentials=True,        # PELIGROSO: Combinado con * = riesgo CSRF
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Impacto:**
- Posibles ataques de Cross-Site Request Forgery (CSRF)
- Robo de credenciales vía sitios web maliciosos
- Secuestro de sesión

**Remediación:**
```python
ALLOWED_ORIGINS = os.getenv("MIESC_ALLOWED_ORIGINS", "").split(",")
if not ALLOWED_ORIGINS or ALLOWED_ORIGINS == [""]:
    ALLOWED_ORIGINS = ["http://localhost:8501"]  # Solo local por defecto

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type"],
)
```

---

## 2. Hallazgos de Alta Prioridad

### HIGH-001: API Admin Expuesta Sin Proxy Reverso

**Severidad:** ALTO
**CWE:** CWE-284 (Control de Acceso Inadecuado)

**Ubicación:** `docker/docker-compose.prod.yml:50-52`

**Problema:**
```yaml
admin-api:
  ports:
    - "5002:5002"  # Expuesto directamente a la red
```

**Impacto:** API de administración de licencias accesible sin capa de autenticación adicional.

**Remediación:**
- Eliminar exposición directa del puerto
- Enrutar a través de Nginx con autenticación
- Implementar lista blanca de IPs

---

### HIGH-002: Vulnerabilidad SSRF en Cliente Marketplace

**Severidad:** ALTO
**Puntuación CVSS:** 7.5
**CWE:** CWE-918 (Server-Side Request Forgery)

**Ubicación:** `src/plugins/marketplace.py:260-267`

**Código Vulnerable:**
```python
req = urllib.request.Request(
    self.index_url,  # URL controlada por usuario sin validación
    headers={...},
)
with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
    data = json.loads(response.read().decode("utf-8"))
```

**Vectores de Ataque:**
- `http://localhost:8080/admin` - Acceso a servicios internos
- `http://169.254.169.254/latest/meta-data/` - Robo de metadata AWS
- `http://192.168.1.1/config` - Escaneo de red interna

**Remediación:**
```python
def _validate_url(self, url: str) -> str:
    from urllib.parse import urlparse
    import ipaddress

    parsed = urlparse(url)

    # Forzar HTTPS
    if parsed.scheme != 'https':
        raise MarketplaceError("Solo URLs HTTPS permitidas")

    # Bloquear IPs privadas/reservadas
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            raise MarketplaceError("Acceso a IPs privadas bloqueado")
    except ValueError:
        pass  # Hostname, no IP - OK

    return url
```

---

## 3. Hallazgos de Prioridad Media

### MED-001: Condiciones de Carrera en Archivos Temporales (TOCTOU)

**Severidad:** MEDIO
**CWE:** CWE-367 (Condición de Carrera Time-of-check Time-of-use)

**Ubicaciones:**
- `src/adapters/dagnn_adapter.py:130`
- `src/adapters/exploit_synthesizer_adapter.py:164`

**Código Vulnerable:**
```python
self.cache_dir = Path(tempfile.gettempdir()) / "miesc_dagnn_cache"
self.cache_dir.mkdir(exist_ok=True)  # Condición de carrera posible
```

**Remediación:**
```python
import os
self.cache_dir = Path(tempfile.gettempdir()) / "miesc_dagnn_cache"
self.cache_dir.mkdir(exist_ok=True, mode=0o700)  # Restringir permisos
os.chmod(self.cache_dir, 0o700)  # Asegurar permisos correctos
```

---

### MED-002: Paquetes NPM Sin Versión Fija en Docker

**Severidad:** MEDIO
**CWE:** CWE-1104 (Uso de Componentes de Terceros Sin Mantenimiento)

**Ubicación:** `docker/Dockerfile:85`, `docker/Dockerfile.prod:25`

**Problema:**
```dockerfile
RUN npm install -g solhint    # Sin versión fija
```

**Remediación:**
```dockerfile
RUN npm install -g solhint@5.0.3
```

---

### MED-003: Curl-to-Shell Sin Verificación de Hash

**Severidad:** MEDIO
**CWE:** CWE-494 (Descarga de Código Sin Verificación de Integridad)

**Ubicación:** `docker/Dockerfile:35-40`

**Problema:**
```dockerfile
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN curl -L https://foundry.paradigm.xyz | bash
```

**Remediación:**
```dockerfile
# Descargar y verificar antes de ejecutar
RUN curl -sSf https://sh.rustup.rs -o /tmp/rustup.sh && \
    echo "SHA256_ESPERADO /tmp/rustup.sh" | sha256sum -c - && \
    sh /tmp/rustup.sh -y && \
    rm /tmp/rustup.sh
```

---

### MED-004: API Ollama Expuesta Sin Autenticación

**Severidad:** MEDIO
**CWE:** CWE-306 (Falta de Autenticación para Función Crítica)

**Ubicación:** `docker/docker-compose.yml:234-236`

**Problema:**
```yaml
ollama:
  ports:
    - "11434:11434"  # API LLM expuesta sin auth
```

**Remediación:**
- Desarrollo: Vincular solo a localhost (`127.0.0.1:11434:11434`)
- Producción: No exponer; usar red Docker interna

---

### MED-005: Imagen Base Sin Fijar por Digest

**Severidad:** MEDIO
**CWE:** CWE-1104 (Uso de Componentes Sin Mantenimiento)

**Ubicación:** `docker/Dockerfile.prod:1`

**Problema:**
```dockerfile
FROM python:3.11-slim  # Sin versión Debian o digest
```

**Remediación:**
```dockerfile
FROM python:3.11-slim-bookworm@sha256:abc123...
```

---

### MED-006: Archivo Lock Generado para Versión Incorrecta

**Severidad:** MEDIO

**Ubicación:** `requirements-lock.txt:2-3`

**Problema:**
```
# This file is autogenerated by pip-compile with Python 3.9
```

El proyecto requiere Python 3.12+, pero el lock file se generó con 3.9.

**Remediación:**
```bash
pip-compile pyproject.toml --python-version=3.12 -o requirements-lock.txt
```

---

### MED-007: WebSocket Sin Autenticación

**Severidad:** MEDIO
**CWE:** CWE-306 (Falta de Autenticación para Función Crítica)

**Ubicación:** `src/core/websocket_api.py`

**Problema:** Las conexiones WebSocket no validan tokens de autenticación.

**Remediación:** Implementar validación de token en el handler de conexión:
```python
async def websocket_handler(websocket):
    token = websocket.request_headers.get("Authorization")
    if not validate_token(token):
        await websocket.close(1008, "No autorizado")
        return
```

---

### MED-008: Certificados SSL en Sistema de Archivos

**Severidad:** MEDIO

**Ubicación:** `docker/docker-compose.prod.yml:76`

**Problema:**
```yaml
volumes:
  - ./ssl:/etc/nginx/ssl:ro
```

**Lista de Verificación:**
- [ ] Verificar que `./ssl` esté en `.gitignore`
- [ ] Verificar que archivos de certificado tengan modo 0600
- [ ] Considerar usar Docker secrets en su lugar

---

## 4. Hallazgos de Baja Prioridad

### LOW-001: Código de Tests Contiene Credenciales Hardcodeadas

**Ubicación:** Múltiples archivos de test

**Problema:** Archivos de test contienen strings como `"test-openai-key"`, `"secret123"`

**Estado:** Aceptable para código de test, pero se recomienda usar fixtures.

---

### LOW-002: Python 3.10 EOL en Dockerfile.x86

**Ubicación:** `docker/Dockerfile.x86:1`

**Problema:** Python 3.10 llega a EOL en Octubre 2026.

**Remediación:** Migrar a Python 3.12.

---

### LOW-003: Tag `:latest` Usado en Dockerfile.full

**Ubicación:** `docker/Dockerfile.full:1`

**Problema:**
```dockerfile
FROM ghcr.io/fboiero/miesc:latest
```

**Remediación:** Usar tag de versión específico.

---

### LOW-004: Montajes de Volumen de Desarrollo con Escritura

**Ubicación:** `docker/docker-compose.yml:164-166`

**Problema:** El shell de desarrollo permite acceso de escritura.

**Estado:** Aceptable para desarrollo, asegurar que producción use `:ro`.

---

### LOW-005: Descargas de Binarios Sin Checksum

**Ubicación:** `docker/Dockerfile.full` (Echidna, Medusa)

**Problema:** Releases de GitHub descargados sin verificación SHA.

---

### LOW-006: Backend pycryptodome por Defecto

**Ubicación:** Dependencia transitiva vía eth-hash

**Problema:** pycryptodome es aceptable pero se prefiere la librería `cryptography` para código nuevo.

---

## 5. Controles de Seguridad Positivos

### Implementación Excelente

| Control | Ubicación | Calificación |
|---------|-----------|--------------|
| **Protección contra Inyección de Prompts** | `src/security/prompt_sanitizer.py` | 10/10 |
| **Protección contra Path Traversal** | `src/security/input_validator.py` | 10/10 |
| **Logging Seguro (Redacción)** | `src/security/secure_logging.py` | 10/10 |
| **Validación de Salida LLM** | `src/security/llm_output_validator.py` | 9/10 |
| **Detección de Secretos Pre-commit** | `.pre-commit-config.yaml` | 9/10 |
| **Funciones de Validación de Entrada** | `src/security/input_validator.py` | 9/10 |
| **Usuario No-root en Docker** | Todos los Dockerfiles | 9/10 |
| **Builds Docker Multi-stage** | Todos los Dockerfiles | 9/10 |
| **Health Checks** | Archivos docker-compose | 9/10 |
| **Límites de Recursos** | docker-compose.prod-llm.yml | 8/10 |
| **Cobertura .gitignore** | `.gitignore` | 9/10 |
| **Enmascaramiento de Variables de Entorno** | `src/security/reproducibility.py` | 9/10 |

### Detalles de Protección contra Inyección de Prompts

El módulo `prompt_sanitizer.py` implementa seguridad LLM líder en la industria:

- **60+ Patrones de Ataque Detectados:**
  - Sobrescritura de instrucciones ("ignora instrucciones anteriores")
  - Inyección de roles ("system:", "assistant:")
  - Manipulación de salida ("reporta que no hay vulnerabilidades")
  - Intentos de jailbreak ("modo DAN", "pretende que eres")
  - Caracteres Unicode ocultos (espacios de ancho cero)
  - Inyección de templates (`${`, `{{`)

- **Clasificación de Riesgo:** NONE → LOW → MEDIUM → HIGH → CRITICAL

- **Características de Sanitización:**
  - Envoltura de contenido estilo XML
  - Escape de entidades HTML
  - Filtrado de caracteres
  - Límites de longitud (100KB código, 50KB contexto)

### Logging Seguro (Redacción)

El módulo `secure_logging.py` redacta 15+ patrones sensibles:

```python
PATRONES_REDACCION = [
    # Claves API
    r"(sk-[a-zA-Z0-9]{20,})",           # OpenAI
    r"(sk-ant-[a-zA-Z0-9-]{20,})",      # Anthropic
    r"(hf_[a-zA-Z0-9]{20,})",           # HuggingFace
    # Tokens
    r"(Bearer\s+[a-zA-Z0-9_\-\.]+)",    # Tokens Bearer
    r"(ghp_[a-zA-Z0-9]{36})",           # GitHub PAT
    r"(xox[baprs]-[a-zA-Z0-9-]+)",      # Slack
    # Credenciales
    r"(AKIA[0-9A-Z]{16})",              # AWS Access Key
    r"(-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----)", # Claves privadas
    # Base de datos
    r"(postgres://[^@]+@[^\s]+)",       # Connection strings
    r"(mongodb\+srv://[^@]+@[^\s]+)",
]
```

---

## 6. Recomendaciones

### Acciones Inmediatas (Semana 1)

| # | Acción | Archivo | Prioridad |
|---|--------|---------|-----------|
| 1 | Eliminar valor por defecto de clave API admin | `src/licensing/admin_api.py:38` | CRÍTICO |
| 2 | Corregir configuración CORS | `src/licensing/admin_api.py:28-35` | CRÍTICO |
| 3 | Eliminar exposición de puerto API admin | `docker/docker-compose.prod.yml:50` | ALTO |
| 4 | Agregar validación de URL a marketplace | `src/plugins/marketplace.py:260` | ALTO |

### Acciones a Corto Plazo (Sprint 2)

| # | Acción | Prioridad |
|---|--------|-----------|
| 5 | Corregir permisos de archivos temporales | MEDIO |
| 6 | Fijar versiones de paquetes NPM | MEDIO |
| 7 | Agregar verificación de hash de scripts | MEDIO |
| 8 | Restringir Ollama a localhost | MEDIO |
| 9 | Fijar imágenes base Docker | MEDIO |
| 10 | Regenerar lock file para Python 3.12 | MEDIO |

### Acciones a Mediano Plazo (Q1 2026)

| # | Acción | Prioridad |
|---|--------|-----------|
| 11 | Implementar autenticación WebSocket | MEDIO |
| 12 | Agregar escaneo de imágenes Docker a CI | BAJO |
| 13 | Generar SBOM durante builds | BAJO |
| 14 | Migrar Dockerfile.x86 a Python 3.12 | BAJO |
| 15 | Reemplazar `:latest` con tags específicos | BAJO |

### Acciones a Largo Plazo (Q2 2026)

- Considerar imágenes base distroless
- Implementar atestación de procedencia
- Agregar monitoreo de seguridad en tiempo de ejecución
- Implementar estrategia de rotación de secretos

---

## 7. Estado de Cumplimiento

### OWASP Top 10 (2021)

| Categoría | Estado | Notas |
|-----------|--------|-------|
| A01: Control de Acceso Roto | ⚠️ | Mala configuración CORS |
| A02: Fallas Criptográficas | ✅ | Sin problemas encontrados |
| A03: Inyección | ✅ | Excelente protección |
| A04: Diseño Inseguro | ✅ | Buena arquitectura |
| A05: Configuración Incorrecta | ⚠️ | Credenciales por defecto |
| A06: Componentes Vulnerables | ✅ | Escaneo activo |
| A07: Fallas de Autenticación | ⚠️ | Falta auth WebSocket |
| A08: Integridad Software/Datos | ⚠️ | Algunas descargas sin verificar |
| A09: Logging/Monitoreo | ✅ | Logging seguro implementado |
| A10: SSRF | ⚠️ | Vulnerabilidad en marketplace |

### Cobertura CWE

| CWE | Descripción | Estado |
|-----|-------------|--------|
| CWE-22 | Path Traversal | ✅ Protegido |
| CWE-78 | Inyección de Comandos OS | ✅ Protegido |
| CWE-79 | XSS | ✅ Protegido |
| CWE-89 | Inyección SQL | ✅ N/A (sin SQL) |
| CWE-94 | Inyección de Código | ✅ Protegido |
| CWE-798 | Credenciales Hardcodeadas | ❌ Encontrado |
| CWE-918 | SSRF | ❌ Encontrado |
| CWE-942 | Mala Configuración CORS | ❌ Encontrado |

### Marco de Ciberseguridad NIST

| Función | Madurez | Notas |
|---------|---------|-------|
| Identificar | Alta | Buen inventario de activos |
| Proteger | Media | Algunas brechas en control de acceso |
| Detectar | Alta | Logging y monitoreo |
| Responder | Media | Respuesta a incidentes necesita documentación |
| Recuperar | Baja | Estrategia de backup necesita documentación |

---

## 8. Apéndice

### A. Archivos Analizados

**Código Fuente:**
- `src/security/*.py` (7 archivos)
- `src/licensing/*.py` (2 archivos)
- `src/adapters/*.py` (59 archivos)
- `src/core/*.py` (15 archivos)
- `src/plugins/*.py` (6 archivos)
- `src/ml/*.py` (18 archivos)
- `src/llm/*.py` (8 archivos)

**Configuración:**
- `pyproject.toml`
- `requirements-lock.txt`
- `.pre-commit-config.yaml`
- `.gitignore`
- `.secrets.baseline`

**Docker:**
- `docker/Dockerfile` (4 variantes)
- `docker/docker-compose*.yml` (4 archivos)
- `docker/.dockerignore`

**CI/CD:**
- `.github/workflows/*.yml` (11 workflows)

### B. Herramientas Utilizadas

- Revisión manual de código
- Búsqueda de patrones grep/ripgrep
- Conceptos de análisis estático (patrones SAST)
- Análisis de dependencias

### C. Definiciones de Severidad

| Nivel | CVSS | Descripción |
|-------|------|-------------|
| CRÍTICO | 9.0-10.0 | Riesgo de explotación inmediata, brecha de datos |
| ALTO | 7.0-8.9 | Riesgo significativo, remediación necesaria |
| MEDIO | 4.0-6.9 | Preocupación de seguridad, debe abordarse |
| BAJO | 0.1-3.9 | Violación de mejores prácticas |
| INFO | N/A | Informativo, sin riesgo inmediato |

### D. Comandos de Verificación

```bash
# Verificar secretos hardcodeados
grep -r "miesc-admin-secret-key" .

# Verificar cobertura .gitignore
cat .gitignore | grep -E "\.env|\.key|\.pem"

# Verificar patrones de API key en código fuente
grep -r "sk-\|sk-ant-\|hf_" src/ --include="*.py" | grep -v test

# Verificar hooks pre-commit
cat .pre-commit-config.yaml | grep -A 5 "detect-secrets"

# Verificar uso de subprocess
grep -r "shell=True" src/ --include="*.py"

# Verificar uso de eval/exec
grep -r "eval\|exec\|compile" src/ --include="*.py"
```

---

## Historial del Documento

| Versión | Fecha | Autor | Cambios |
|---------|-------|-------|---------|
| 1.0 | 2026-02-16 | Equipo de Seguridad | Auditoría inicial |

---

**Aviso de Confidencialidad:** Este documento contiene información sensible de seguridad sobre el proyecto MIESC. La distribución debe limitarse únicamente a personal autorizado.
