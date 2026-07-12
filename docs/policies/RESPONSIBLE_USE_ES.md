# Política de Uso Responsable

**[English Version](RESPONSIBLE_USE.md)**

**MIESC - Evaluación Inteligente Multicapa para Contratos Inteligentes**
**Última actualización:** 2026-03-31

## Propósito

MIESC está diseñado para **mejorar la seguridad de los contratos inteligentes** identificando vulnerabilidades antes del despliegue. Este documento establece las pautas para el uso ético y responsable de MIESC y sus capacidades.

## Uso Previsto

MIESC está destinado a:

- **Auditorías de seguridad previas al despliegue** de contratos inteligentes
- **Monitoreo continuo de seguridad** en pipelines de desarrollo
- **Investigación académica** en seguridad de contratos inteligentes
- **Fines educativos** en la formación en ciberseguridad
- **Defensa colaborativa** mediante la divulgación responsable de vulnerabilidades
- **Verificación de cumplimiento** frente a estándares de seguridad

## Uso Aceptable

### Actividades autorizadas

- Analizar tus propios contratos inteligentes
- Analizar contratos con autorización explícita del propietario del contrato
- Investigación de seguridad sobre contratos desplegados en testnets públicas
- Estudio académico usando conjuntos de datos de benchmark establecidos (SmartBugs, SolidiFI, etc.)
- Contribuir a la seguridad de proyectos de contratos inteligentes de código abierto
- Participación en bug bounties a través de programas autorizados (Immunefi, Code4rena, etc.)

### Actividades prohibidas

- Usar MIESC para encontrar y explotar vulnerabilidades en contratos de producción sin autorización
- Usar los hallazgos para front-running, ataques sándwich o explotar de cualquier otro modo protocolos DeFi
- Usar el generador de PoC para crear exploits con fines maliciosos
- Distribuir información sobre vulnerabilidades de contratos activos sin divulgación responsable
- Usar MIESC para facilitar el robo, el fraude o el acceso no autorizado a fondos
- Eludir las medidas de seguridad de contratos desplegados

## Consideraciones de Doble Uso

MIESC es una **herramienta de seguridad de doble uso**. Como cualquier escáner de vulnerabilidades, puede usarse de forma defensiva (encontrar y corregir vulnerabilidades) u ofensiva (encontrarlas y explotarlas). Reconocemos esta dualidad inherente y la abordamos mediante:

### Salvaguardas técnicas

1. **Limitaciones del generador de PoC:** El generador de pruebas de concepto crea escenarios de prueba para verificación, no exploits armados. Los PoC generados están diseñados para ejecutarse en entornos de prueba locales de Foundry, no contra redes activas.

2. **Arquitectura local-first:** MIESC se ejecuta localmente, reduciendo el riesgo de que los datos de vulnerabilidades se filtren a partes no autorizadas.

3. **Confidencialidad de los reportes:** Los reportes generados incluyen clasificaciones de confidencialidad y se almacenan localmente bajo el control del usuario.

### Salvaguardas comunitarias

1. **Divulgación responsable:** Los usuarios que descubran vulnerabilidades en contratos desplegados deben seguir las [prácticas de divulgación responsable](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).

2. **Programas de bug bounty:** Alentamos el uso de los hallazgos de MIESC a través de programas de bug bounty establecidos, en lugar de la explotación independiente.

3. **Código de Conducta:** Todas las interacciones de la comunidad se rigen por nuestro [Código de Conducta](../CODE_OF_CONDUCT.md).

## Consideraciones sobre IA/LLM

MIESC integra capacidades de IA/LLM para un análisis mejorado. Las prácticas responsables de IA incluyen:

- **Transparencia:** los hallazgos asistidos por modelos se etiquetan claramente en los reportes
- **Reproducibilidad:** las semillas y el versionado de modelos permiten resultados reproducibles
- **Detección de alucinaciones:** la validación cruzada incorporada reduce los hallazgos asistidos por modelos sin fundamento
- **Ejecución local:** la integración por defecto con Ollama garantiza que el código permanezca en la máquina del usuario
- **Sanitización de prompts:** la sanitización de entradas previene ataques de inyección de prompts

## Reporte de Uso Indebido

Si tenés conocimiento de que MIESC se está usando con fines maliciosos:

- **Email:** fboiero@frvm.utn.edu.ar
- **Problemas de seguridad:** Ver [SECURITY.md](../SECURITY.md)

## Implicaciones de la Licencia

MIESC está licenciado bajo **AGPL-3.0**. Esta licencia requiere:

- Cualquier modificación a MIESC debe publicarse bajo la misma licencia
- Los servicios construidos sobre MIESC deben poner su código fuente a disposición
- Esto garantiza la transparencia y previene la explotación propietaria de la herramienta

## Reconocimiento

Al usar MIESC, reconocés que:

1. Usarás la herramienta con fines legítimos de mejora de la seguridad
2. Tenés autorización para analizar los contratos que escaneás
3. Seguirás las prácticas de divulgación responsable ante cualquier vulnerabilidad encontrada
4. Cumplirás con las leyes y regulaciones aplicables en tu jurisdicción
