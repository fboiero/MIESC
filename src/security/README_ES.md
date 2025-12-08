# Módulo de Seguridad MIESC

[English](README.md) | **Español**

## Descripción General

Módulo de seguridad integral para el framework MIESC que proporciona:
- Validación y sanitización de entradas
- Limitación de tasa de API y gestión de cuotas
- Registro seguro con redacción automática de credenciales

## Módulos

### `input_validator.py`

Valida y sanitiza todas las entradas de usuario para prevenir:
- Ataques de path traversal
- Inyección de comandos
- Explotación de parámetros inválidos

**Funciones Principales:**
```python
from src.security import validate_contract_path, validate_solc_version

# Validar ruta de contrato (previene path traversal)
safe_path = validate_contract_path("examples/contract.sol")

# Validar versión de Solidity (previene inyección de comandos)
safe_version = validate_solc_version("0.8.20")

# Validar todas las entradas a la vez
validated = validate_analysis_inputs(
    contract_path="examples/contract.sol",
    solc_version="0.8.20",
    timeout=300,
    functions=["transfer", "withdraw"]
)
```

### `api_limiter.py`

Gestiona límites de tasa de API y cuotas para prevenir:
- Agotamiento de cuota de API
- Ataques de DoS económico
- Sobrecostos

**Clases Principales:**
```python
from src.security import RateLimiter, APIQuotaManager

# Decorador de limitación de tasa
@RateLimiter(max_calls=60, period=60)
def call_openai_api(prompt):
    return openai.ChatCompletion.create(...)

# Gestión de cuotas
quota = APIQuotaManager(
    daily_limit=1000,
    daily_cost_limit=100.0,
    cost_per_call={'gpt-4': 0.03}
)

quota.check_quota('gpt-4')  # Lanza RateLimitExceeded si se excede
quota.record_call('gpt-4')  # Registrar uso
stats = quota.get_usage_stats()  # Obtener estadísticas
```

### `secure_logging.py`

Redacción automática de información sensible de los logs:
- Claves API (OpenAI, Anthropic, HuggingFace)
- Contraseñas y secretos
- Tokens JWT
- Claves privadas
- Números de tarjetas de crédito

**Configuración:**
```python
from src.security import setup_secure_logging

logger = setup_secure_logging('miesc', level=logging.INFO)

# Las claves API se redactan automáticamente
logger.info("Using key: sk-1234567890abcdef")
# Salida: "Using key: sk-***REDACTED***"
```

## Ejemplos de Integración

### Implementación de Agente Seguro

```python
from src.agents.base_agent import BaseAgent
from src.security import (
    validate_contract_path,
    validate_solc_version,
    RateLimiter,
    setup_secure_logging
)

class SecureStaticAgent(BaseAgent):
    def __init__(self):
        super().__init__("SecureStaticAgent", ["static_analysis"], "static")

        # Configurar registro seguro
        self.logger = setup_secure_logging(f'miesc.{self.agent_name}')

        # Configurar limitación de tasa
        self.rate_limiter = RateLimiter(max_calls=100, period=60)

    def analyze(self, contract_path: str, **kwargs):
        # Validar entradas
        safe_path = validate_contract_path(contract_path)
        solc_version = kwargs.get('solc_version', '0.8.20')
        safe_version = validate_solc_version(solc_version)

        # Aplicar limitación de tasa
        self.rate_limiter._check_rate_limit()

        # Proceder con el análisis
        self.logger.info(f"Analizando {safe_path} con Solidity {safe_version}")
        # ... código de análisis ...
```

### Llamadas API Seguras

```python
from src.security import rate_limited_openai_call, openai_quota

@rate_limited_openai_call
def analyze_with_gpt(contract_code: str):
    """Análisis GPT con limitación de tasa y gestión de cuota"""

    # Verificar cuota antes de operación costosa
    openai_quota.check_quota('gpt-4')

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": contract_code}]
    )

    # Registrar uso
    openai_quota.record_call('gpt-4')

    return response
```

## Configuración

### Variables de Entorno

```bash
# Limitación de tasa
export MIESC_RATE_LIMIT_CALLS=60
export MIESC_RATE_LIMIT_PERIOD=60

# Gestión de cuotas
export MIESC_DAILY_API_LIMIT=1000
export MIESC_DAILY_COST_LIMIT=100.0

# Registro
export MIESC_LOG_LEVEL=INFO
export MIESC_REDACT_EMAILS=false
export MIESC_REDACT_IPS=false
```

### Configuración de Directorios Permitidos

Por defecto, las rutas de contratos están restringidas a:
- Directorio de trabajo actual
- `examples/`
- `contracts/`
- `tests/`

Para personalizar:
```python
from src.security import validate_contract_path

allowed_dirs = [
    "/app/production_contracts",
    "/app/user_uploads"
]

safe_path = validate_contract_path(
    contract_path="user_contract.sol",
    allowed_base_dirs=allowed_dirs
)
```

## Mejores Prácticas de Seguridad

### 1. Siempre Validar Entradas

```python
# VULNERABLE
def analyze(contract_path):
    with open(contract_path, 'r') as f:  # Sin validación!
        return analyze_code(f.read())

# SEGURO
def analyze(contract_path):
    safe_path = validate_contract_path(contract_path)
    with open(safe_path, 'r') as f:
        return analyze_code(f.read())
```

### 2. Usar Limitación de Tasa para APIs Externas

```python
# VULNERABLE - Sin limitación de tasa
def call_api(data):
    return openai.ChatCompletion.create(...)

# SEGURO
@RateLimiter(max_calls=60, period=60)
def call_api(data):
    return openai.ChatCompletion.create(...)
```

### 3. Habilitar Registro Seguro

```python
# VULNERABLE - Los logs pueden contener claves API
import logging
logger = logging.getLogger(__name__)
logger.info(f"Using API key: {api_key}")

# SEGURO - Redacción automática
from src.security import setup_secure_logging
logger = setup_secure_logging(__name__)
logger.info(f"Using API key: {api_key}")  # Redactado automáticamente
```

## Testing

Ejecutar tests de seguridad:
```bash
python -m pytest tests/security/ -v
```

Probar validación de entradas:
```bash
python -c "from src.security import validate_contract_path; \
           print(validate_contract_path('examples/reentrancy.sol'))"
```

Probar registro seguro:
```bash
python src/security/secure_logging.py
```

## Cumplimiento

Este módulo de seguridad ayuda a lograr cumplimiento con:

- **ISO/IEC 27001:2022**
  - A.8.8: Gestión de vulnerabilidades técnicas
  - A.8.15: Registro
  - A.14.2.5: Principios de ingeniería de sistemas seguros

- **NIST SP 800-218 (SSDF)**
  - PW.8: Proteger todas las formas de código de acceso no autorizado
  - RV.1.1: Identificar y confirmar vulnerabilidades

- **OWASP Top 10 2021**
  - A03: Inyección (prevenido por validación de entradas)
  - A09: Registro y Monitoreo de Seguridad (registro seguro)

## Historial de Cambios

### v1.0.0 (2024-10)
- Lanzamiento inicial
- Módulo de validación de entradas
- Limitación de tasa y gestión de cuotas
- Registro seguro con redacción de credenciales

## Licencia

AGPL-3.0 (igual que el framework MIESC)
