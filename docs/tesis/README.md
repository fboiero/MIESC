# Documentación de Tesis - MIESC v4.0.0

**Presentada al Tribunal:** 23 de Octubre 2025
**Defensa:** 18 de Diciembre 2025

> Nota histórica: esta carpeta preserva la tesis v4.0.0 y puede contener
> métricas, lenguaje de 7 capas y resultados previos. Los claims actuales para
> revisión y publicación están en `../../paper/PAPER1_REPRODUCIBILITY.md`,
> `../../paper/PAPER2_REPRODUCIBILITY.md` y las matrices
> `../../benchmarks/results/paper*_claims_matrix.json`.
>
> Edición corregida (octubre 2026): los capítulos en español recibieron una revisión
> integral de fondo, referencias y estilo posterior a la defensa; el espejo en inglés
> (`en/`) incorpora las correcciones sustantivas pero no la pasada de estilo.

---

## Institución

- **Universidad:** Universidad de la Defensa Nacional (UNDEF)
- **Centro:** Centro Regional Universitario Córdoba - Instituto Universitario Aeronáutico (IUA)
- **Programa:** Maestría en Ciberdefensa
- **Director:** Mg. Eduardo Casanovas
- **Autor:** Ing. Fernando Boiero

---

## Estructura del Documento

### Sección Preliminar
| Archivo | Contenido |
|---------|-----------|
| `PORTADA_TESIS.md` | Portada institucional |
| `SECCION_PRELIMINAR.md` | Agradecimientos, resumen, abstract |
| `INDICE_TESIS.md` | Índice completo |
| `LISTA_DE_FIGURAS.md` | Listado de figuras |
| `LISTA_DE_TABLAS.md` | Listado de tablas |
| `LISTA_DE_ACRONIMOS.md` | Acrónimos utilizados |
| `GLOSARIO.md` | Definiciones de términos |

### Capítulos Principales
| Archivo | Capítulo | Páginas Est. |
|---------|----------|--------------|
| `CAPITULO_INTRODUCCION.md` | 1. Introducción | 15-20 |
| `CAPITULO_MARCO_TEORICO.md` | 2. Marco Teórico | 25-30 |
| `CAPITULO_ESTADO_DEL_ARTE.md` | 3. Estado del Arte | 30-35 |
| `CAPITULO_DESARROLLO.md` | 4. Desarrollo e Implementación | 60-70 |
| `CAPITULO_RESULTADOS.md` | 5. Resultados Experimentales | 35-40 |
| `CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md` | 6. Justificación IA y LLM Soberano | 40-45 |
| `CAPITULO_JUSTIFICACION_MCP.md` | 7. Justificación MCP | 40-45 |
| `CAPITULO_TRABAJOS_FUTUROS.md` | 8. Conclusiones y Trabajos Futuros | 20-25 |

### Apéndices
| Archivo | Contenido |
|---------|-----------|
| `APENDICE_CODIGO_FUENTE.md` | Extractos de código relevantes |
| `APENDICE_SALIDAS_HERRAMIENTAS.md` | Outputs de herramientas |
| `APENDICE_TECNICAS_ANALISIS.md` | Técnicas de análisis |
| `REFERENCIAS_BIBLIOGRAFICAS.md` | Bibliografía completa |

### Documentos Complementarios
| Archivo | Contenido |
|---------|-----------|
| `ARQUITECTURA_MCP_SERVER.md` | Arquitectura del servidor MCP |
| `EVOLUCION_ARQUITECTONICA.md` | Evolución de la arquitectura |
| `TABLAS_COMPARATIVAS.md` | Tablas de comparación |

### Recursos
| Directorio/Archivo | Contenido |
|--------------------|-----------|
| `figures/` | Figuras y diagramas |
| `en/` | Versiones en inglés |
| `logo_iua.png` | Logo institucional |
| `DD 047-020 Reglamento de Tesis MCD.pdf` | Reglamento de tesis |

---

## Orden de Lectura Sugerido

1. `PORTADA_TESIS.md`
2. `SECCION_PRELIMINAR.md`
3. `INDICE_TESIS.md`
4. `CAPITULO_INTRODUCCION.md`
5. `CAPITULO_MARCO_TEORICO.md`
6. `CAPITULO_ESTADO_DEL_ARTE.md`
7. `CAPITULO_DESARROLLO.md`
8. `CAPITULO_RESULTADOS.md`
9. `CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md`
10. `CAPITULO_JUSTIFICACION_MCP.md`
11. `CAPITULO_TRABAJOS_FUTUROS.md`
12. `REFERENCIAS_BIBLIOGRAFICAS.md`
13. Apéndices (A, B, C...)

---

## Alcance de la Tesis (v4.0.0)

### Incluido en la Tesis
- Arquitectura de 7 capas
- 25 herramientas integradas
- Sistema de normalización SWC/CWE/OWASP
- LLM Soberano con Ollama
- MCP Server
- Resultados: 100% cobertura / 48% type-aware (72% con capa LLM), dedup 68%, $0 costo

### NO Incluido (Trabajo Posterior v4.1.0+)
- Capas 8-9 (DeFi/Dependencies)
- WebSocket API
- Exporters multi-formato
- Prometheus Metrics
- GitHub Actions CI/CD

Ver `../evidence/THESIS_VS_POSTWORK_SEPARATION.md` para detalles completos.

---

*Maestría en Ciberdefensa - UNDEF/IUA - 2025*
