# Documentacion de Tesis - MIESC v4.0.0

**Presentada al Tribunal:** 23 de Octubre 2025
**Defensa:** 18 de Diciembre 2025

---

## Institucion

- **Universidad:** Universidad de la Defensa Nacional (UNDEF)
- **Centro:** Centro Regional Universitario Cordoba - Instituto Universitario Aeronautico (IUA)
- **Programa:** Maestria en Ciberdefensa
- **Director:** Mg. Eduardo Casanovas
- **Autor:** Ing. Fernando Boiero

---

## Estructura del Documento

### Seccion Preliminar
| Archivo | Contenido |
|---------|-----------|
| `PORTADA_TESIS.md` | Portada institucional |
| `SECCION_PRELIMINAR.md` | Agradecimientos, resumen, abstract |
| `INDICE_TESIS.md` | Indice completo |
| `LISTA_DE_FIGURAS.md` | Listado de figuras |
| `LISTA_DE_TABLAS.md` | Listado de tablas |
| `LISTA_DE_ACRONIMOS.md` | Acronimos utilizados |
| `GLOSARIO.md` | Definiciones de terminos |

### Capitulos Principales
| Archivo | Capitulo | Paginas Est. |
|---------|----------|--------------|
| `CAPITULO_INTRODUCCION.md` | 1. Introduccion | 15-20 |
| `CAPITULO_MARCO_TEORICO.md` | 2. Marco Teorico | 25-30 |
| `CAPITULO_ESTADO_DEL_ARTE.md` | 3. Estado del Arte | 30-35 |
| `CAPITULO_DESARROLLO.md` | 4. Desarrollo e Implementacion | 60-70 |
| `CAPITULO_RESULTADOS.md` | 5. Resultados Experimentales | 35-40 |
| `CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md` | 6. Justificacion IA y LLM Soberano | 40-45 |
| `CAPITULO_JUSTIFICACION_MCP.md` | 7. Justificacion MCP | 40-45 |
| `CAPITULO_TRABAJOS_FUTUROS.md` | 8. Conclusiones y Trabajos Futuros | 20-25 |

### Apendices
| Archivo | Contenido |
|---------|-----------|
| `APENDICE_CODIGO_FUENTE.md` | Extractos de codigo relevantes |
| `APENDICE_SALIDAS_HERRAMIENTAS.md` | Outputs de herramientas |
| `APENDICE_TECNICAS_ANALISIS.md` | Tecnicas de analisis |
| `REFERENCIAS_BIBLIOGRAFICAS.md` | Bibliografia completa |

### Documentos Complementarios
| Archivo | Contenido |
|---------|-----------|
| `ARQUITECTURA_MCP_SERVER.md` | Arquitectura del servidor MCP |
| `EVOLUCION_ARQUITECTONICA.md` | Evolucion de la arquitectura |
| `TABLAS_COMPARATIVAS.md` | Tablas de comparacion |

### Recursos
| Directorio/Archivo | Contenido |
|--------------------|-----------|
| `figures/` | Figuras y diagramas |
| `en/` | Versiones en ingles |
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
13. Apendices (A, B, C...)

---

## Alcance de la Tesis (v4.0.0)

### Incluido en la Tesis
- Arquitectura de 7 capas
- 25 herramientas integradas
- Sistema de normalizacion SWC/CWE/OWASP
- LLM Soberano con Ollama
- MCP Server
- Resultados: 100% recall, +40.8% mejora, $0 costo

### NO Incluido (Trabajo Posterior v4.1.0+)
- Capas 8-9 (DeFi/Dependencies)
- WebSocket API
- Exporters multi-formato
- Prometheus Metrics
- GitHub Actions CI/CD

Ver `../evidence/THESIS_VS_POSTWORK_SEPARATION.md` para detalles completos.

---

*Maestria en Ciberdefensa - UNDEF/IUA - 2025*
