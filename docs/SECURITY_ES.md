# Política de Seguridad

**[English Version](SECURITY.md)**

**MIESC - Evaluación Inteligente Multicapa para Contratos Inteligentes**

---

## Versiones Soportadas

| Versión | Soportada          | Notas |
| ------- | ------------------ | ----- |
| 4.x.x   | :white_check_mark: | Lanzamiento actual, mantenido activamente |
| 3.x.x   | :white_check_mark: | Solo correcciones de seguridad |
| 2.x.x   | :x:                | Fin de vida |
| < 2.0   | :x:                | Fin de vida |

---

## Reportar una Vulnerabilidad

Tomamos las vulnerabilidades de seguridad en serio. Si descubres un problema de seguridad, por favor repórtalo de manera responsable.

### Contacto

**Email**: <fboiero@frvm.utn.edu.ar>

**Línea de Asunto**: `[SECURITY] MIESC - Descripción breve`

### Qué Incluir

1. **Descripción**: Explicación clara de la vulnerabilidad
2. **Impacto**: Impacto de seguridad potencial
3. **Pasos para Reproducir**: Pasos detallados de reproducción
4. **Versiones Afectadas**: Qué versiones están afectadas
5. **Corrección Sugerida**: Si tienes una (opcional)

### Línea de Tiempo de Respuesta

| Etapa | Línea de Tiempo |
|-------|-----------------|
| Reconocimiento inicial | 48 horas |
| Evaluación de severidad | 5 días hábiles |
| Desarrollo de corrección | Depende de la severidad |
| Divulgación pública | Después de que se libere la corrección |

### Niveles de Severidad

| Nivel | Tiempo de Respuesta | Ejemplos |
|-------|---------------------|----------|
| Crítico | 24-48 horas | Ejecución remota de código, brecha de datos |
| Alto | 1 semana | Escalada de privilegios, bypass de autenticación |
| Medio | 2 semanas | Divulgación de información, DoS |
| Bajo | 1 mes | Issues menores, hardening |

---

## Medidas de Seguridad

### Prácticas de Desarrollo

| Práctica | Implementación |
|----------|----------------|
| Revisión de Código | Todos los PRs requieren revisión |
| Análisis Estático | Bandit, Semgrep en cada commit |
| Escaneo de Dependencias | Snyk, GitHub Dependabot |
| Escaneo de Secretos | Hooks de pre-commit |
| Commits Firmados | Firma GPG recomendada |

### Pipeline CI/CD

```yaml
# .github/workflows/security.yml
security-scan:
  - bandit (linter de seguridad Python)
  - semgrep (SAST)
  - safety (vulnerabilidades de dependencias)
  - trivy (escaneo de contenedores)
```

### Gestión de Dependencias

- Dependencias fijadas a versiones específicas
- Actualizaciones automáticas semanales de dependencias
- Avisos de seguridad monitoreados vía GitHub

---

## Arquitectura de Seguridad

### Seguridad del Flujo de Datos

```
┌──────────────────────────────────────────────────────────┐
│                    Entorno del Usuario                    │
│                                                          │
│  ┌─────────────┐                      ┌─────────────┐   │
│  │ Código Fuente│──────────────────────▶│   MIESC    │   │
│  │   (Entrada) │                      │  (Local)    │   │
│  └─────────────┘                      └──────┬──────┘   │
│                                              │          │
│                                              ▼          │
│                                       ┌─────────────┐   │
│                                       │  Reportes   │   │
│                                       │  (Salida)   │   │
│                                       └─────────────┘   │
│                                                          │
│  ════════════════════════════════════════════════════   │
│  ║ Todo el procesamiento es local - Sin flujo externo ║  │
│  ════════════════════════════════════════════════════   │
└──────────────────────────────────────────────────────────┘
```

### Modelo de Amenazas

| Amenaza | Mitigación |
|---------|------------|
| Contratos maliciosos | Ejecución de herramientas en sandbox |
| Ataques de dependencias | Versiones fijadas, escaneo de seguridad |
| Inyección de código | Validación de entrada, sin shell=True |
| Exfiltración de datos | Solo procesamiento local |
| Cadena de suministro | Releases firmados, builds reproducibles |

---

## Guías de Uso Seguro

### Para Usuarios

1. **Verificar Descargas**

   ```bash
   # Verificar firma del release (cuando esté disponible)
   gpg --verify miesc-4.0.0.tar.gz.asc
   ```

2. **Usar Entornos Virtuales**

   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Mantener Actualizado**

   ```bash
   pip install --upgrade miesc
   ```

4. **Revisar Salidas de IA**
   - El análisis generado por IA puede contener errores
   - Siempre verifica hallazgos críticos manualmente

### Para Desarrolladores

1. **Firma tus Commits**

   ```bash
   git config --global commit.gpgsign true
   ```

2. **Ejecuta Verificaciones de Seguridad Localmente**

   ```bash
   make security-check
   # o
   bandit -r src/
   safety check
   ```

3. **Nunca Hagas Commit de Secretos**
   - Usa variables de entorno
   - Verifica que `.gitignore` incluya archivos sensibles

---

## Consideraciones de Seguridad Conocidas

### Componentes de IA

| Componente | Consideración | Mitigación |
|------------|---------------|------------|
| LLM Local (Ollama) | El modelo puede generar análisis incorrecto | Se requiere revisión humana |
| IA en Nube Opcional | Datos enviados a terceros | Solo opt-in, documentado |

### Herramientas de Terceros

| Herramienta | Nota de Seguridad |
|-------------|-------------------|
| Slither | Ejecuta compilador de Solidity |
| Mythril | Ejecución simbólica (en sandbox) |
| Echidna | Fuzzing (en sandbox) |
| Certora | Servicio en la nube (opcional) |

### Manejo de Salidas

- Los reportes pueden contener lógica sensible del contrato
- El almacenamiento seguro de resultados de análisis es responsabilidad del usuario
- Evita compartir reportes públicamente sin revisión

---

## Respuesta a Incidentes

### Si Sospechas una Brecha

1. **Aislar**: Deja de usar la versión afectada
2. **Reportar**: Contacta al email de seguridad inmediatamente
3. **Preservar**: Mantén logs y evidencia
4. **Actualizar**: Aplica parches cuando estén disponibles

### Nuestro Proceso de Respuesta

1. Triaje y evaluación de severidad
2. Desarrollo y prueba de corrección
3. Liberación de actualización de seguridad
4. Notificación a usuarios afectados (si aplica)
5. Publicación de aviso de seguridad
6. Análisis post-mortem

---

## Avisos de Seguridad

Los avisos de seguridad se publican vía:

- GitHub Security Advisories
- Notas de lanzamiento
- Notificación directa (issues críticos)

**Archivo de Avisos**: [github.com/fboiero/MIESC/security/advisories](https://github.com/fboiero/MIESC/security/advisories)

---

## Bug Bounty

Actualmente, MIESC no tiene un programa formal de bug bounty. Sin embargo, reconocemos y agradecemos a los investigadores de seguridad que divulgan vulnerabilidades de manera responsable.

**Reconocimiento**:

- Crédito en SECURITY.md
- Crédito en notas de lanzamiento
- Cartas de recomendación (bajo solicitud)

---

## Cumplimiento

El desarrollo de MIESC sigue mejores prácticas de seguridad alineadas con:

- OWASP Secure Coding Practices
- NIST SP 800-218 (Secure Software Development Framework)
- CIS Controls (donde aplique)

---

## Contacto

**Issues de Seguridad**: <fboiero@frvm.utn.edu.ar>

**Tiempo de Respuesta**: 48 horas (días hábiles)

**Clave PGP**: Disponible bajo solicitud

---

*Última Actualización: Diciembre 2024*
