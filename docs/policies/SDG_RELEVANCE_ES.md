# Relevancia para los Objetivos de Desarrollo Sostenible (ODS)

**[English Version](SDG_RELEVANCE.md)**

**MIESC - Evaluación Inteligente Multicapa para Contratos Inteligentes**

Este documento mapea las contribuciones de MIESC a los Objetivos de Desarrollo Sostenible (ODS) de las Naciones Unidas, según lo requerido por el [Estándar de Bienes Públicos Digitales](https://digitalpublicgoods.net/standard/).

---

## Alineación Primaria con los ODS

### ODS 9: Industria, Innovación e Infraestructura

**Meta 9.1:** Desarrollar infraestructuras fiables, sostenibles, resilientes y de calidad para apoyar el desarrollo económico y el bienestar humano.

**Contribución de MIESC:**
- La infraestructura blockchain es cada vez más crítica para los servicios financieros, las cadenas de suministro y los sistemas de gobernanza a nivel mundial
- MIESC fortalece esta infraestructura detectando vulnerabilidades antes del despliegue
- El enfoque de defensa en profundidad de 9 capas del framework proporciona una cobertura de seguridad integral que las herramientas individuales no pueden alcanzar
- La disponibilidad de código abierto garantiza que todos los desarrolladores de blockchain tengan acceso a análisis de seguridad de nivel empresarial, no solo los proyectos con buen financiamiento

**Evidencia** (cada afirmación apunta a su artefacto fuente):
- 95.8% de recall en SmartBugs-curated (137/143 contratos) — ver
  `benchmarks/results/paper1_claims_matrix.json`. La línea base del 43.2% de la mejor
  herramienta individual (Slither) es reportada por Durieux et al., "Empirical Review of
  Automated Analysis Tools on 47,587 Ethereum Smart Contracts," ICSE 2020.
- 92.5% de recall en una extracción local de alta severidad de EVMBench (ensamble
  multi-proveedor) — ver `benchmarks/results/paper1_claims_matrix.json`.
- 81.8% de recall en 11 exploits DeFi confirmados del mundo real (USD 1.59 mil millones en pérdidas combinadas, 95%
  Wilson CI [52%, 95%]) — producido por el harness de evaluación de exploits
  `benchmarks/evaluate_exploits.py`; reporte narrativo en
  `benchmarks/results/v5.1.6_deep_audit_rekt_report.md`.
- Hallazgos mapeados a 12 estándares internacionales de seguridad (ISO 27001, NIST CSF, etc.)

### ODS 16: Paz, Justicia e Instituciones Sólidas

**Meta 16.5:** Reducir considerablemente la corrupción y el soborno en todas sus formas.

**Meta 16.6:** Crear instituciones eficaces, responsables y transparentes a todos los niveles.

**Contribución de MIESC:**
- Los contratos inteligentes permiten sistemas de gobernanza y financieros transparentes e inalterables
- Las vulnerabilidades en estos contratos socavan la confianza y habilitan la explotación
- El mapeo de cumplimiento de MIESC (ISO 27001, NIST, OWASP) ayuda a las organizaciones a cumplir con los requisitos regulatorios
- La transparencia de la herramienta (código abierto, resultados reproducibles) habilita prácticas de seguridad responsables
- Los reportes de auditoría profesionales proporcionan evidencia para el cumplimiento regulatorio

**Evidencia:**
- Mapeo de cumplimiento a 12 estándares internacionales
- La salida automatizada en SARIF se integra con los flujos de trabajo de seguridad institucionales
- Los reportes incluyen puntuación CVSS alineada con los estándares de la industria

### ODS 17: Alianzas para Lograr los Objetivos

**Meta 17.6:** Mejorar la cooperación regional e internacional Norte-Sur, Sur-Sur y triangular en materia de ciencia, tecnología e innovación y el acceso a estas.

**Meta 17.8:** Poner en pleno funcionamiento el banco de tecnología y el mecanismo de apoyo a la creación de capacidad en materia de ciencia, tecnología e innovación para los países menos adelantados.

**Contribución de MIESC:**
- Framework de código abierto disponible gratuitamente para desarrolladores de todo el mundo
- La documentación bilingüe (inglés/español) mejora la accesibilidad para los desarrolladores latinoamericanos
- La arquitectura local-first (LLM Ollama) permite su uso sin dependencias de la nube ni costosas suscripciones a APIs
- El sistema de plugins habilita contribuciones de investigación de seguridad impulsadas por la comunidad
- La base académica apoya la transferencia de conocimiento y la creación de capacidades

**Evidencia:**
- Publicado como código abierto bajo AGPL-3.0
- Documentación bilingüe (EN/ES) en todos los documentos de gobernanza y de cara al usuario
- Las imágenes Docker permiten el despliegue sin una instalación compleja de herramientas
- Investigación de tesis de maestría realizada en Argentina (cooperación Sur-Sur)

---

## Alineación Secundaria con los ODS

### ODS 8: Trabajo Decente y Crecimiento Económico

**Meta 8.10:** Fortalecer la capacidad de las instituciones financieras nacionales para fomentar y ampliar el acceso a los servicios bancarios, financieros y de seguros para todos.

**Contribución:** Los protocolos DeFi (Finanzas Descentralizadas) amplían el acceso financiero. El perfil de seguridad específico de DeFi de MIESC garantiza que estos protocolos sean seguros para los usuarios, particularmente en regiones con banca tradicional limitada.

### ODS 10: Reducción de las Desigualdades

**Meta 10.c:** Reducir a menos del 3% los costos de transacción de las remesas de los migrantes.

**Contribución:** Los sistemas de remesas basados en blockchain dependen de contratos inteligentes seguros. MIESC ayuda a garantizar que estos sistemas sean seguros para las poblaciones vulnerables que dependen de ellos.

---

## Métricas de Impacto

| Métrica | Valor |
|---------|-------|
| Herramientas de seguridad integradas | 50 |
| Cadenas blockchain soportadas | 7 (EVM en producción + 6 alfa) |
| Patrones de vulnerabilidad en la base de conocimiento | 59 |
| Estándares internacionales mapeados | 12 |
| Idiomas soportados (docs) | 2 (inglés, español) |
| Licencia | AGPL-3.0 (copyleft, garantiza el acceso abierto) |
| Independencia de plataforma | Python 3.12+, Docker, cualquier SO |
| Dependencia de la nube | Ninguna requerida (local-first) |

---

## Referencias

- [Objetivos de Desarrollo Sostenible de la ONU](https://sdgs.un.org/goals)
- [Estándar de Bienes Públicos Digitales](https://digitalpublicgoods.net/standard/)
- [Blockchain para los ODS (ONU)](https://www.un.org/en/digital-financing-taskforce)
