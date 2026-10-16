# Preparación para Defensa de Tesis - MIESC

**Fecha de Defensa:** 18 de Diciembre 2025
**Hora:** [Por confirmar]
**Lugar:** [Por confirmar]
**Duración estimada:** 45-60 min presentación + 30-45 min preguntas

---

## 1. Checklist Pre-Defensa

### Una Semana Antes (11-17 Dic)
- [ ] Confirmar hora y lugar de defensa
- [ ] Verificar que slides (Marp) exportan correctamente a PDF
- [ ] Practicar presentación completa (3 veces mínimo)
- [ ] Preparar demo en vivo (backup: video grabado)
- [ ] Revisar preguntas anticipadas
- [ ] Confirmar asistencia del director (Mg. Casanovas)

### Un Día Antes (17 Dic)
- [ ] Laptop cargada y funcionando
- [ ] Backup de slides en USB
- [ ] Demo probada y funcionando
- [ ] Ollama corriendo con modelo cargado
- [ ] Agua para la presentación
- [ ] Vestimenta formal preparada

### Día de la Defensa (18 Dic)
- [ ] Llegar 30 min antes
- [ ] Probar proyector/conexión
- [ ] Verificar audio si hay demo
- [ ] Tener slides abiertas y listas
- [ ] Respirar y relajarse

---

## 2. Estructura de la Presentación (45 min)

| Sección | Tiempo | Slides |
|---------|--------|--------|
| Título y datos | 1 min | 1-2 |
| Contexto y motivación | 5 min | 3-7 |
| Problema de investigación | 4 min | 8-10 |
| Marco teórico | 4 min | 11-13 |
| Solución (MIESC) | 12 min | 14-25 |
| Resultados experimentales | 10 min | 26-35 |
| Demo en vivo | 5 min | 36-38 |
| Conclusiones | 3 min | 39-41 |
| Trabajos futuros | 2 min | 42-44 |
| Cierre | 1 min | 45 |

**Total:** ~45 minutos

---

## 3. Puntos Clave por Sección

### Contexto y Motivación
- **Cifra impactante:** $7.8+ MIL MILLONES perdidos en smart contracts
- **Casos emblemáticos:** The DAO, Wormhole, Ronin Bridge
- **Problema dual:** Fragmentación de herramientas + Soberanía de datos

### Problema de Investigación
- **P1:** No existe framework integrador
- **P2:** Salidas incompatibles entre herramientas
- **P3:** APIs comerciales comprometen confidencialidad
- **P4:** No existe Defense-in-Depth para smart contracts

### Solución MIESC
- **Arquitectura:** 7 capas de defensa en profundidad
- **Herramientas:** 25 integradas vía patrón Adapter
- **Normalización:** Mapeo automático SWC/CWE/OWASP
- **IA Soberana:** Ollama local, código NUNCA sale de la máquina
- **MCP:** Primera herramienta con Model Context Protocol

### Resultados Clave (MEMORIZAR)
| Métrica | Valor |
|---------|-------|
| Cobertura de recall | 29/29 (100%) |
| Recall type-aware (estático+patrón) | 14/29 (48%) |
| Recall type-aware (+capa LLM `--deep`) | 21/29 (72%) |
| Precisión | ~7.5% (perfil recall-first; ~32% con filtrado FP) |
| Deduplicación | 68% (385&rarr;123) |
| Costo operativo | $0 |
| Herramientas integradas | 25/25 (100%) |

### Contribuciones Principales
1. Primera arquitectura Defense-in-Depth para smart contracts
2. Patrón ToolAdapter para integración unificada
3. Normalización triple SWC/CWE/OWASP
4. IA soberana con Ollama
5. Primer MCP Server para auditoría
6. Cumple estándares Digital Public Good

---

## 4. Preguntas Anticipadas y Respuestas

### Sobre la Arquitectura

**P: Por que 7 capas y no más o menos?**
> Las 7 capas corresponden a técnicas de análisis complementarias y ortogonales: estático, dinámico, simbólico, invariantes, formal, property-based, e IA. Cada capa detecta clases diferentes de vulnerabilidades con minima superposición.

**P: Cual es el cuello de botella del sistema?**
> La ejecución simbólica (Capa 3) es el cuello de botella, tomando 1-5 minutos por contrato. MIESC mitiga esto con ejecución paralela de capas independientes.

**P: Como manejan la explosión de estados en ejecución simbólica?**
> Usamos Mythril y Halmos que implementan bounded model checking con límites de profundidad configurables. Además, el fuzzing (Capa 2) complementa cubriendo paths que la ejecución simbólica no alcanza.

### Sobre la IA Soberana

**P: Por que Ollama y no una API comercial?**
> Tres razones: (1) Soberanía de datos - el código nunca sale de la máquina, (2) Cumplimiento regulatorio - GDPR, datos sensibles, (3) Costo $0 vs $0.03-$0.10 por análisis.

**P: Que modelos LLM usan?**
> Principalmente deepseek-coder y codellama para análisis de código. Son modelos open-source optimizados para código que corren localmente.

**P: Como garantizan la calidad del LLM local vs APIs comerciales?**
> Implementamos RAG (Retrieval Augmented Generation) con base de conocimiento de vulnerabilidades, más un Verificator que valida los hallazgos contra patrones conocidos. Esto mejoró la precisión de 75% a 88%.

### Sobre los Resultados

**P: El corpus de 4 contratos no es muy pequeño?**
> Sí, es una limitación reconocida. Sin embargo, los 4 contratos (614 LOC) cubren 9 o más categorías SWC y 29 vulnerabilidades documentadas. El enfoque fue validar la arquitectura, no hacer benchmark exhaustivo. Trabajo futuro incluye validación con SmartBugs (143 contratos).

**P: Que significa la cobertura de 100%?**
> Es cobertura de línea: MIESC produce algún hallazgo cerca de las 29/29 vulnerabilidades documentadas (perfil recall-first). El criterio significativo es la detección type-aware —que el hallazgo sea del tipo/SWC correcto—: 48% con capas estático+patrón, y 72% al agregar la capa LLM frontier. En escenarios reales con vulnerabilidades desconocidas, ambos números seran menores.

**P: Que pasa con vulnerabilidades de lógica de negocio?**
> Es una limitación. Vulnerabilidades como flash loan attacks o MEV exploitation requieren conocimiento del contexto de negocio que las herramientas automáticas no capturan completamente. SmartLLM ayuda pero no es perfecto.

### Sobre Comparativas

**P: Como se compara MIESC con herramientas comerciales como Certora o OpenZeppelin?**
> MIESC es complementario, no competidor. Integra Certora Prover como una de las 25 herramientas. La diferencia es que MIESC orquesta múltiples herramientas con IA soberana, mientras que soluciones comerciales son single-tool o requieren APIs cloud.

**P: Por que no usar simplemente Slither que es la más popular?**
> Slither por si sola ya es muy fuerte (96% de cobertura, 58% type-aware en nuestro corpus). Ser honestos: combinar tools estáticos NO la supera. El valor de MIESC aparece al agregar la capa de razonamiento LLM, que sube la detección type-aware del 48% al 72%. Además, MIESC integra ejecución simbólica y fuzzing que Slither no cubre.

### Sobre Aplicabilidad

**P: MIESC puede usarse en producción hoy?**
> Si. Tiene más de 6.000 tests automatizados con cobertura verificada en CI, API REST documentada, y Docker deployment. Ya está postulado como Digital Public Good (GID0092948).

**P: Cual es el tiempo promedio de auditoría?**
> ~2 minutos para un contrato típico (<500 LOC). Contratos más grandes pueden tomar 5-10 minutos dependiendo de la complejidad.

**P: Que nivel de expertise se necesita para usar MIESC?**
> Nivel básico para ejecutar auditorías. El CLI es simple: `miesc audit contract.sol`. Para interpretar resultados y remediar, se necesita conocimiento de Solidity y seguridad.

### Sobre Trabajos Futuros

**P: Cuales son las prioridades para v5.0?**
> (1) Soporte multi-chain (Solana, Cairo), (2) Integración VSCode, (3) Automated patching con LLM, (4) Runtime monitoring post-deployment.

**P: Como planean validar con un corpus más grande?**
> Integración con SmartBugs benchmark (143 contratos, 208 vulnerabilidades) está en progreso. También colaboración con auditors profesionales para validación en mainnet.

---

## 5. Respuestas a Críticas Potenciales

### "El corpus es muy pequeño"
> Reconozco la limitación. El objetivo fue proof-of-concept de la arquitectura. La validación exhaustiva con SmartBugs es trabajo futuro ya iniciado post-tesis.

### "Las métricas de IA son subjetivas"
> Correcto para evaluaciones cualitativas. Por eso las métricas principales (recall, precisión, F1) son objetivas y medibles contra ground truth conocido.

### "Depende de que las herramientas esten instaladas"
> MIESC verifica disponibilidad y degrada graciosamente. Si Mythril no está disponible, las otras 24 herramientas siguen funcionando. Docker image incluye todas las dependencias.

### "Ollama es más lento que APIs cloud"
> Sí, ~2x más lento. Pero el trade-off es soberanía total de datos. Para organizaciones con requisitos de confidencialidad, esto es aceptable.

---

## 6. Demo en Vivo - Script

### Preparación (antes de defensa)
```bash
# Verificar Ollama
ollama list
# Debe mostrar deepseek-coder o codellama

# Verificar MIESC
cd /path/to/MIESC
python -c "from miesc.core.orchestrator import MIESCOrchestrator; print('OK')"
```

### Durante la Demo
```bash
# Mostrar el contrato vulnerable
cat contracts/audit/VulnerableBank.sol

# Ejecutar auditoria rapida
python demo_thesis_defense.py --quick --auto

# Mostrar resultados
# Destacar: reentrancy detectada por multiples capas
```

### Backup: Video Pregrabado
Si la demo falla, tener video de 2-3 min mostrando:
1. Ejecución del comando
2. Output de cada capa
3. Reporte final con vulnerabilidad detectada

---

## 7. Frases Clave para Recordar

### Apertura
> "En los ultimos 8 años, más de 7.8 mil millones de dólares se han perdido por vulnerabilidades en smart contracts. Hoy presento MIESC, un framework que aplica defensa en profundidad para prevenir estos ataques."

### Sobre IA Soberana
> "En ciberdefensa, enviar código fuente a servidores externos es inaceptable. MIESC garantiza que el código NUNCA sale de tu máquina."

### Sobre Resultados
> "MIESC cubre el 100% de las vulnerabilidades documentadas del corpus y eleva la detección type-aware del 48% al 72% al incorporar la capa de razonamiento LLM, con costo operativo cero."

### Cierre
> "MIESC demuestra que la defensa en profundidad, aplicada correctamente con IA soberana, puede transformar la seguridad de smart contracts de fragmentada a integral."

---

## 8. Logística

### Contactos
- **Director:** Mg. Eduardo Casanovas
- **Email autor:** fboiero@frvm.utn.edu.ar

### Materiales a Llevar
1. Laptop con MIESC instalado
2. USB con backup de slides (PDF)
3. Copia impresa de slides (por si acaso)
4. Documento de separación tesis/post-tesis

### Post-Defensa
- Agradecer al tribunal
- Preguntar sobre correcciones si las hay
- Confirmar proximos pasos para aprobación

---

*Documento de preparación - Defensa 18 de Diciembre 2025*
*Maestría en Ciberdefensa - UNDEF/IUA*
