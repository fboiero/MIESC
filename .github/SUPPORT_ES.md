# Soporte

¿Necesitas ayuda con MIESC? Aquí tienes cómo obtener soporte.

---

## Obtener Ayuda

### Documentación

- [Guía de Inicio Rápido](docs/guides/QUICKSTART.md) - Comienza en 5 minutos
- [Documentación Completa](https://fboiero.github.io/MIESC) - Guía de usuario completa
- [Referencia API](docs/api/) - Documentación para desarrolladores
- [Referencia de Herramientas](docs/TOOLS.md) - Las 50 herramientas de seguridad

### Comunidad

- [GitHub Discussions](https://github.com/fboiero/MIESC/discussions) - Preguntas, ideas, comunidad
- [Issue Tracker](https://github.com/fboiero/MIESC/issues) - Reportes de bugs y solicitudes
- [Guía de Comunidad](docs/COMMUNITY.md) - Recursos completos y guías de la comunidad

**Chat en tiempo real (Discord/Matrix) próximamente!** Ver [Guía de Comunidad](docs/COMMUNITY.md) para actualizaciones.

---

## Tiempos de Respuesta

| Canal | Tiempo de Respuesta |
|-------|---------------------|
| Problemas de Seguridad | 48 horas |
| Reportes de Bugs | 5 días hábiles |
| Solicitud de Funciones | 2 semanas |
| Preguntas Generales | Mejor esfuerzo |

---

## Antes de Preguntar

1. Revisa la [documentación](https://fboiero.github.io/MIESC)
2. Busca en [issues existentes](https://github.com/fboiero/MIESC/issues)
3. Revisa las [FAQ](#faq) más abajo
4. Ejecuta `miesc doctor` para verificar tu instalación

---

## FAQ

### Instalación

**P: ¿Qué versión de Python necesito?**

R: Se requiere Python 3.12 o superior.

**P: ¿Por qué Mythril no funciona?**

R: Mythril tiene conflictos de dependencias con algunos paquetes. Instálalo en un entorno virtual separado o usa la imagen Docker (`miesc:full`).

### Docker

**P: ¿Por qué Docker dice "scan: not found"?**

R: Tienes una imagen antigua en caché. Ejecuta:
```bash
docker rmi ghcr.io/fboiero/miesc:latest
docker pull ghcr.io/fboiero/miesc:latest
```

**P: ¿Cómo uso MIESC con Ollama en Docker?**

R: Configura la variable de entorno `OLLAMA_HOST`:
```bash
# macOS/Windows
docker run -e OLLAMA_HOST=http://host.docker.internal:11434 ...

# Linux
docker run --network host -e OLLAMA_HOST=http://localhost:11434 ...
```

### Análisis

**P: ¿Cómo omito herramientas no disponibles?**

R: Usa `--skip-unavailable`:
```bash
miesc audit full contract.sol --skip-unavailable
```

**P: ¿Por qué obtengo falsos positivos?**

R: Habilita la interpretación LLM para reducir falsos positivos:
```bash
miesc report results.json -t premium --llm-interpret
```

---

## Reportar Problemas

### Reportes de Bugs

Al reportar bugs, incluye:

1. Versión de MIESC (`miesc --version`)
2. Versión de Python (`python --version`)
3. Sistema operativo
4. Pasos para reproducir
5. Comportamiento esperado vs actual
6. Mensajes de error y logs

Usa la [plantilla de bug](https://github.com/fboiero/MIESC/issues/new?template=bug_report.md).

### Solicitud de Funciones

Para solicitudes de funciones:

1. Revisa las [solicitudes existentes](https://github.com/fboiero/MIESC/labels/enhancement)
2. Describe el caso de uso
3. Propón una solución si es posible

Usa la [plantilla de feature](https://github.com/fboiero/MIESC/issues/new?template=feature_request.md).

### Vulnerabilidades de Seguridad

**NO reportes vulnerabilidades de seguridad en issues públicos.**

Consulta [SECURITY.md](docs/policies/SECURITY.md) para instrucciones de divulgación responsable.

---

## Soporte Comercial

Para soporte empresarial, capacitación o desarrollo personalizado:

**Contacto:** Fernando Boiero
**Email:** fboiero@frvm.utn.edu.ar
**Institución:** Universidad de la Defensa Nacional (UNDEF), Argentina

---

## Contribuir

¿Quieres ayudar a mejorar MIESC? Consulta [CONTRIBUTING.md](CONTRIBUTING.md) para las guías.

---

*[English version / Versión en inglés](SUPPORT.md)*
