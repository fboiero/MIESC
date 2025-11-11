# Política de Seguridad

## Versiones Soportadas

Actualmente, las siguientes versiones de MIESC reciben actualizaciones de seguridad:

| Versión | Soportada          | Notas                                    |
| ------- | ------------------ | ---------------------------------------- |
| 2.x     | :white_check_mark: | Arquitectura MCP multiagente (actual)    |
| 1.x     | :x:                | Pipeline secuencial (obsoleto)           |
| < 1.0   | :x:                | Versiones de desarrollo                  |

**Recomendación**: Siempre use la última versión de la rama `main` para obtener las correcciones de seguridad más recientes.

---

## Reportar una Vulnerabilidad

La seguridad del framework MIESC es una prioridad. Si descubre una vulnerabilidad de seguridad, por favor siga el proceso de divulgación responsable descrito a continuación.

### Proceso de Reporte

#### 1. NO Crear un Issue Público

Por favor, **NO** cree un issue público en GitHub para vulnerabilidades de seguridad. Esto podría exponer la vulnerabilidad antes de que se implemente una corrección.

#### 2. Contacto Privado

Envíe un reporte detallado a través de uno de los siguientes canales:

**Email Preferido**: fboiero@frvm.utn.edu.ar
**Asunto**: [SECURITY] Vulnerabilidad en MIESC

**Información Institucional**:
- **Institución**: Universidad Tecnológica Nacional - Facultad Regional Villa María
- **País**: Argentina
- **Departamento**: Ingeniería en Sistemas de Información

#### 3. Información a Incluir

Para facilitar la evaluación y corrección, incluya:

- **Descripción detallada** de la vulnerabilidad
- **Pasos para reproducir** el problema
- **Impacto potencial** (confidencialidad, integridad, disponibilidad)
- **Versión afectada** de MIESC
- **Entorno de prueba** (SO, Python version, dependencias)
- **Proof of Concept** (código, capturas de pantalla)
- **Recomendaciones de corrección** (si las tiene)

**Plantilla de Reporte**:
```markdown
## Vulnerabilidad en MIESC

**Fecha**: YYYY-MM-DD
**Reportado por**: [Su nombre/alias]
**Versión afectada**: 2.x
**Severidad estimada**: [Crítica/Alta/Media/Baja]

### Descripción
[Descripción detallada]

### Pasos para Reproducir
1. [Paso 1]
2. [Paso 2]
3. [Paso 3]

### Impacto
[Descripción del impacto en seguridad]

### Entorno
- SO: [Ubuntu 22.04 / macOS 14 / Windows 11]
- Python: [3.10 / 3.11 / 3.12]
- MIESC Version: [2.0.1]

### Proof of Concept
```python
# Código de demostración
```

### Corrección Sugerida
[Recomendaciones, si las tiene]
```

---

## Compromiso de Respuesta

Nos comprometemos a los siguientes tiempos de respuesta:

| Etapa                        | Tiempo             | Descripción                                |
|------------------------------|--------------------|--------------------------------------------|
| **Confirmación de recepción**| 48 horas           | Confirmaremos recepción del reporte        |
| **Evaluación inicial**       | 7 días             | Clasificación de severidad e impacto       |
| **Corrección (Crítica)**     | 14 días            | Parche para vulnerabilidades críticas      |
| **Corrección (Alta)**        | 30 días            | Parche para vulnerabilidades altas         |
| **Corrección (Media/Baja)**  | 60 días            | Parche para vulnerabilidades menores       |
| **Divulgación pública**      | Post-corrección    | Después de lanzar parche y notificar users |

### Clasificación de Severidad

**Crítica**:
- Ejecución remota de código (RCE)
- Escalada de privilegios
- Bypass completo de controles de seguridad
- Exposición masiva de datos sensibles

**Alta**:
- Inyección de código en análisis
- Manipulación de resultados de auditoría
- Bypass parcial de validaciones
- Exposición limitada de datos

**Media**:
- Divulgación de información no crítica
- Denegación de servicio (DoS) local
- Errores de configuración que reducen seguridad

**Baja**:
- Problemas de calidad de código sin impacto en seguridad
- Mejoras sugeridas en hardening
- Problemas de documentación

---

## Proceso de Corrección

### 1. Evaluación y Validación
- Reproducir la vulnerabilidad en ambiente controlado
- Evaluar impacto y alcance
- Asignar clasificación de severidad

### 2. Desarrollo de Parche
- Desarrollar corrección
- Testing exhaustivo
- Verificar que no introduce regresiones

### 3. Testing de Seguridad
- Validar que corrige la vulnerabilidad
- Verificar que no introduce nuevas vulnerabilidades
- Testing en múltiples entornos

### 4. Despliegue
- Crear release con parche
- Actualizar CHANGELOG.md
- Notificar a usuarios conocidos

### 5. Divulgación Coordinada
- Publicar advisory de seguridad
- Reconocer al investigador (si lo desea)
- Actualizar documentación

---

## Reconocimientos

Valoramos enormemente el trabajo de investigadores de seguridad que reportan vulnerabilidades de forma responsable. Con su consentimiento, reconoceremos públicamente sus contribuciones en:

- Sección de créditos en el advisory de seguridad
- Archivo SECURITY_ACKNOWLEDGMENTS.md
- Mención en release notes

**Hall of Fame**: Próximamente listaremos investigadores que hayan contribuido a mejorar la seguridad de MIESC.

---

## Alcance de Seguridad

### En Alcance

Vulnerabilidades en:
- **Core de MIESC**: Context Bus, agentes, coordinador
- **MCP Server**: Manejo de JSON-RPC, validación de inputs
- **Integración de herramientas**: Llamadas a Slither, Mythril, etc.
- **Exportación de datos**: JSON, PDF, audit trails
- **Configuración**: Variables de entorno, archivos de config
- **Dependencias críticas**: Con impacto directo en seguridad

### Fuera de Alcance

- Vulnerabilidades en herramientas de terceros (Slither, Mythril) - reportar a sus respectivos proyectos
- Problemas en clientes MCP (5ire, AIQL TUUI) - reportar a sus respectivos proyectos
- Problemas de infraestructura del usuario (configuración de servidor, permisos de archivos)
- Ataques de ingeniería social
- Ataques físicos
- DoS que requieran recursos extraordinarios

---

## Mejores Prácticas de Seguridad

### Para Usuarios

**Instalación Segura**:
```bash
# Usar entorno virtual
python -m venv venv
source venv/bin/activate

# Instalar desde repositorio oficial
git clone https://github.com/fboiero/MIESC.git
cd xaudit

# Verificar integridad (próximamente con GPG signatures)
pip install -r requirements.txt
```

**Protección de API Keys**:
```bash
# Usar .env (nunca commitear)
echo "OPENAI_API_KEY=sk-..." > .env

# Permisos restrictivos
chmod 600 .env

# Agregar a .gitignore
echo ".env" >> .gitignore
```

**Ejecución con Mínimos Privilegios**:
```bash
# NO ejecutar como root
# Usar usuario dedicado en producción
useradd -m -s /bin/bash miesc
su - miesc
```

### Para Desarrolladores

**Validación de Inputs**:
```python
# Siempre validar contract_path
if not os.path.exists(contract_path):
    raise FileNotFoundError(f"Contract not found: {contract_path}")

# Sanitizar paths
contract_path = os.path.abspath(contract_path)
if not contract_path.startswith(ALLOWED_BASE_DIR):
    raise SecurityError("Path traversal attempt detected")
```

**Manejo Seguro de Subprocesos**:
```python
# Usar lista de argumentos, NO string
subprocess.run(["slither", contract_path], capture_output=True)

# NO usar shell=True (shell injection risk)
# MALO: subprocess.run(f"slither {contract_path}", shell=True)
```

**Logging Seguro**:
```python
# NO loguear datos sensibles
logger.info("Auditing contract", extra={"path": contract_path})

# EVITAR: logger.info(f"Using API key: {api_key}")
```

---

## Compliance y Estándares

MIESC sigue las siguientes prácticas de seguridad:

- **ISO/IEC 27001:2022** - Control A.8.8 (Management of technical vulnerabilities)
- **NIST SSDF** - Práctica RV.1.1 (Identify publicly disclosed vulnerabilities)
- **OWASP Top 10** - Principios de desarrollo seguro
- **CWE Top 25** - Prevención de debilidades comunes

---

## Auditorías de Seguridad

### Auditorías Realizadas

Actualmente, MIESC no ha sido sometido a una auditoría de seguridad externa formal.

### Auditorías Planeadas

- **Q4 2025**: Auditoría de seguridad del core de MCP
- **Q1 2026**: Penetration testing

Si su organización está interesada en realizar una auditoría pro-bono de MIESC como proyecto académico, contáctenos.

---

## Actualizaciones de Seguridad

Las actualizaciones de seguridad se publican a través de:

1. **GitHub Releases**: https://github.com/fboiero/MIESC/releases
2. **Security Advisories**: https://github.com/fboiero/MIESC/security/advisories
3. **CHANGELOG.md**: Con tag `[SECURITY]`

**Suscribirse a notificaciones**:
- GitHub: Watch → Custom → Security alerts
- Email: Enviar solicitud a fboiero@frvm.utn.edu.ar

---

## Contacto

**Responsable de Seguridad**: Fernando Boiero

**Email**: fboiero@frvm.utn.edu.ar
**Institución**: Universidad Tecnológica Nacional - FRVM
**Ubicación**: Villa María, Córdoba, Argentina

**Horario de Respuesta**: Lunes a Viernes, 9:00-18:00 (UTC-3)
*Nota*: Reportes de vulnerabilidades críticas son monitoreados 24/7.

---

## Licencia

Esta política de seguridad está disponible bajo CC0 1.0 Universal (Public Domain).

---

**Versión**: 1.0
**Última Actualización**: Octubre 2025
**Próxima Revisión**: Abril 2026
