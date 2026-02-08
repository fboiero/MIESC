# Gobernanza de MIESC

**[English Version](GOVERNANCE.md)**

**MIESC - Evaluación Inteligente Multicapa para Contratos Inteligentes**

*Versión 1.0 - Diciembre 2024*

---

## Descripción General

Este documento describe la estructura de gobernanza para el proyecto MIESC, incluyendo procesos de toma de decisiones, roles y responsabilidades, y guías de participación comunitaria.

---

## Estructura del Proyecto

### Estado Actual

MIESC se encuentra actualmente en su **fase inicial de desarrollo** como parte de una tesis de Maestría en la Universidad de la Defensa Nacional (UNDEF), Argentina. El proyecto está en transición hacia un **modelo de código abierto impulsado por la comunidad**.

### Modelo de Gobernanza

**Dictador Benevolente Por Ahora (BDFN)** → **Gobernanza Meritocrática** (planificado)

| Fase | Modelo | Línea de Tiempo |
|------|--------|-----------------|
| Actual | Mantenedor único (fase de tesis) | Hasta Q4 2025 |
| Transición | Formación de equipo core | 2026 |
| Futuro | Meritocrático con comité directivo electo | 2027+ |

---

## Roles y Responsabilidades

### Líder del Proyecto / Mantenedor

**Actual**: Fernando Boiero

**Responsabilidades**:
- Dirección estratégica y hoja de ruta
- Autoridad de decisión final en cambios mayores
- Gestión de lanzamientos
- Salud comunitaria y aplicación del código de conducta
- Comunicaciones externas y alianzas

### Contribuidores

Cualquiera que contribuya a MIESC a través de:
- Contribuciones de código (pull requests)
- Mejoras de documentación
- Reportes de bugs y triaje de issues
- Soporte comunitario y asistencia a usuarios
- Traducciones
- Pruebas y aseguramiento de calidad

**Reconocimiento**: Todos los contribuidores son reconocidos en [CONTRIBUTORS.md](./CONTRIBUTORS.md).

### Equipo Core (Futuro)

A medida que el proyecto crezca, se establecerá un equipo core con:
- Acceso de commit al repositorio principal
- Participación en decisiones de lanzamiento
- Mentoría de nuevos contribuidores

**Criterios de selección**:
- Contribuciones de calidad sostenidas
- Entendimiento demostrado de los objetivos del proyecto
- Interacciones positivas con la comunidad
- Compromiso con los valores del proyecto

---

## Toma de Decisiones

### Tipos de Decisiones

| Tipo de Decisión | Proceso | Aprobación |
|------------------|---------|------------|
| Correcciones de bugs | Revisión de pull request | Aprobación del mantenedor |
| Características menores | Pull request + discusión | Aprobación del mantenedor |
| Características mayores | Proceso RFC | Comunidad + mantenedor |
| Cambios incompatibles | RFC + período de deprecación | Consenso |
| Cambios de gobernanza | RFC + votación | Supermayoría (2/3) |

### Proceso RFC (Request for Comments)

Los cambios mayores siguen un proceso RFC:

1. **Borrador**: El autor crea RFC en el directorio `rfcs/`
2. **Discusión**: Período mínimo de 2 semanas de discusión comunitaria
3. **Revisión**: El autor aborda la retroalimentación
4. **Decisión**: El mantenedor toma la decisión final (o votación comunitaria para gobernanza)
5. **Implementación**: Los RFCs aprobados se implementan

**Plantilla RFC**: [rfcs/0000-template.md](./rfcs/0000-template.md)

### Búsqueda de Consenso

Buscamos consenso aproximado en la mayoría de las decisiones:
- Escuchar todas las perspectivas
- Abordar preocupaciones constructivamente
- Buscar soluciones que funcionen para todos
- El mantenedor desempata cuando no se alcanza consenso

---

## Participación Comunitaria

### Canales de Comunicación

| Canal | Propósito | Enlace |
|-------|-----------|--------|
| GitHub Issues | Reportes de bugs, solicitudes de características | [Issues](https://github.com/fboiero/MIESC/issues) |
| GitHub Discussions | Preguntas generales, ideas | [Discussions](https://github.com/fboiero/MIESC/discussions) |
| Pull Requests | Contribuciones de código | [PRs](https://github.com/fboiero/MIESC/pulls) |
| Email | Asuntos privados | fboiero@frvm.utn.edu.ar |

### Guías de Contribución

Ver [CONTRIBUTING_ES.md](./CONTRIBUTING_ES.md) para guías detalladas de contribución.

**Resumen rápido**:
1. Fork del repositorio
2. Crear una rama de característica
3. Escribir pruebas para nueva funcionalidad
4. Enviar un pull request
5. Responder a retroalimentación de revisión

### Revisión de Código

Todos los cambios de código requieren revisión:
- Al menos una aprobación de un mantenedor
- Las verificaciones de CI deben pasar
- Documentación actualizada si aplica
- Pruebas incluidas para nuevas características

---

## Proceso de Lanzamiento

### Versionado

MIESC sigue [Versionado Semántico](https://semver.org/):

- **MAJOR**: Cambios incompatibles
- **MINOR**: Nuevas características (compatible hacia atrás)
- **PATCH**: Correcciones de bugs (compatible hacia atrás)

### Calendario de Lanzamientos

| Tipo de Lanzamiento | Frecuencia | Ejemplo |
|---------------------|------------|---------|
| Patch | Según sea necesario | 4.0.1, 4.0.2 |
| Minor | Mensual-Trimestral | 4.1.0, 4.2.0 |
| Major | Anual | 5.0.0 |

### Checklist de Lanzamiento

1. Todas las pruebas pasando
2. Documentación actualizada
3. CHANGELOG.md actualizado
4. Versión incrementada en pyproject.toml
5. Notas de lanzamiento redactadas
6. Tag de Git creado
7. Release de GitHub publicado
8. Anuncio publicado

---

## Resolución de Conflictos

### Desacuerdos Técnicos

1. Discutir en el issue/PR relevante
2. Buscar perspectivas adicionales
3. El mantenedor toma la decisión final
4. La decisión se documenta

### Conflictos Interpersonales

1. Referirse al [Código de Conducta](./CODE_OF_CONDUCT_ES.md)
2. Reportar al mantenedor: fboiero@frvm.utn.edu.ar
3. El mantenedor investiga en privado
4. Se toma la acción apropiada

### Apelaciones

Las decisiones pueden apelarse mediante:
1. Abrir una GitHub Discussion
2. Presentar nueva información
3. Discusión comunitaria (2 semanas)
4. Decisión final por mantenedor/comité directivo

---

## Sostenibilidad

### Financiamiento

Estado actual: Proyecto académico sin financiamiento

**Fuentes de financiamiento planificadas**:
- [ ] Grants pathfinder de la Alianza de Bienes Públicos Digitales
- [ ] Grants de investigación académica
- [ ] GitHub Sponsors
- [ ] Soporte de fundaciones

### Asignación de Recursos

Cuando haya financiamiento disponible, las prioridades son:
1. Infraestructura (CI/CD, hosting)
2. Auditorías de seguridad
3. Eventos comunitarios
4. Estipendios para contribuidores

### Planificación de Sucesión

Para asegurar la continuidad del proyecto:
- Documentación de todos los procesos
- Múltiples mantenedores (futuro)
- Modelo de gobernanza abierto
- Alianzas institucionales

---

## Enmiendas

Este documento de gobernanza puede enmendarse mediante:

1. RFC proponiendo cambios
2. Período de discusión de 4 semanas
3. Aprobación por mayoría de 2/3 (cuando aplique)
4. Aprobación del mantenedor durante la fase inicial

---

## Documentos Relacionados

- [CODE_OF_CONDUCT_ES.md](./CODE_OF_CONDUCT_ES.md) - Estándares comunitarios
- [CONTRIBUTING_ES.md](./CONTRIBUTING_ES.md) - Guías de contribución
- [SECURITY_ES.md](./SECURITY_ES.md) - Política de seguridad
- [PRIVACY_ES.md](./PRIVACY_ES.md) - Política de privacidad
- [DPG-COMPLIANCE_ES.md](./DPG-COMPLIANCE_ES.md) - Cumplimiento de Bienes Públicos Digitales

---

## Contacto

**Líder del Proyecto**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Institución**: Universidad de la Defensa Nacional (UNDEF), Argentina

---

*Este modelo de gobernanza está inspirado en proyectos de código abierto establecidos incluyendo Apache, Rust y Python.*
