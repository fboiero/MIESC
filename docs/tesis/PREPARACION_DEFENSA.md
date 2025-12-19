# Preparacion para Defensa de Tesis - MIESC

**Fecha de Defensa:** 18 de Diciembre 2025
**Hora:** [Por confirmar]
**Lugar:** [Por confirmar]
**Duracion estimada:** 45-60 min presentacion + 30-45 min preguntas

---

## 1. Checklist Pre-Defensa

### Una Semana Antes (11-17 Dic)
- [ ] Confirmar hora y lugar de defensa
- [ ] Verificar que slides (Marp) exportan correctamente a PDF
- [ ] Practicar presentacion completa (3 veces minimo)
- [ ] Preparar demo en vivo (backup: video grabado)
- [ ] Revisar preguntas anticipadas
- [ ] Confirmar asistencia del director (Mg. Casanovas)

### Un Dia Antes (17 Dic)
- [ ] Laptop cargada y funcionando
- [ ] Backup de slides en USB
- [ ] Demo probada y funcionando
- [ ] Ollama corriendo con modelo cargado
- [ ] Agua para la presentacion
- [ ] Vestimenta formal preparada

### Dia de la Defensa (18 Dic)
- [ ] Llegar 30 min antes
- [ ] Probar proyector/conexion
- [ ] Verificar audio si hay demo
- [ ] Tener slides abiertas y listas
- [ ] Respirar y relajarse

---

## 2. Estructura de la Presentacion (45 min)

| Seccion | Tiempo | Slides |
|---------|--------|--------|
| Titulo y datos | 1 min | 1-2 |
| Contexto y motivacion | 5 min | 3-7 |
| Problema de investigacion | 4 min | 8-10 |
| Marco teorico | 4 min | 11-13 |
| Solucion (MIESC) | 12 min | 14-25 |
| Resultados experimentales | 10 min | 26-35 |
| Demo en vivo | 5 min | 36-38 |
| Conclusiones | 3 min | 39-41 |
| Trabajos futuros | 2 min | 42-44 |
| Cierre | 1 min | 45 |

**Total:** ~45 minutos

---

## 3. Puntos Clave por Seccion

### Contexto y Motivacion
- **Cifra impactante:** $7.8+ MIL MILLONES perdidos en smart contracts
- **Casos emblematicos:** The DAO, Wormhole, Ronin Bridge
- **Problema dual:** Fragmentacion de herramientas + Soberania de datos

### Problema de Investigacion
- **P1:** No existe framework integrador
- **P2:** Salidas incompatibles entre herramientas
- **P3:** APIs comerciales comprometen confidencialidad
- **P4:** No existe Defense-in-Depth para smart contracts

### Solucion MIESC
- **Arquitectura:** 7 capas de defensa en profundidad
- **Herramientas:** 25 integradas via patron Adapter
- **Normalizacion:** Mapeo automatico SWC/CWE/OWASP
- **IA Soberana:** Ollama local, codigo NUNCA sale de la maquina
- **MCP:** Primera herramienta con Model Context Protocol

### Resultados Clave (MEMORIZAR)
| Metrica | Valor |
|---------|-------|
| Recall | 100% |
| Mejora vs mejor individual | +40.8% |
| Precision | 94.5% |
| F1-Score | 0.936 |
| Deduplicacion | 66% |
| Costo operativo | $0 |
| Herramientas integradas | 25/25 (100%) |

### Contribuciones Principales
1. Primera arquitectura Defense-in-Depth para smart contracts
2. Patron ToolAdapter para integracion unificada
3. Normalizacion triple SWC/CWE/OWASP
4. IA soberana con Ollama
5. Primer MCP Server para auditoria
6. Cumple estandares Digital Public Good

---

## 4. Preguntas Anticipadas y Respuestas

### Sobre la Arquitectura

**P: Por que 7 capas y no mas o menos?**
> Las 7 capas corresponden a tecnicas de analisis complementarias y ortogonales: estatico, dinamico, simbolico, invariantes, formal, property-based, e IA. Cada capa detecta clases diferentes de vulnerabilidades con minima superposicion.

**P: Cual es el cuello de botella del sistema?**
> La ejecucion simbolica (Capa 3) es el cuello de botella, tomando 1-5 minutos por contrato. MIESC mitiga esto con ejecucion paralela de capas independientes.

**P: Como manejan la explosion de estados en ejecucion simbolica?**
> Usamos Mythril y Halmos que implementan bounded model checking con limites de profundidad configurables. Ademas, el fuzzing (Capa 2) complementa cubriendo paths que la ejecucion simbolica no alcanza.

### Sobre la IA Soberana

**P: Por que Ollama y no una API comercial?**
> Tres razones: (1) Soberania de datos - el codigo nunca sale de la maquina, (2) Cumplimiento regulatorio - GDPR, datos sensibles, (3) Costo $0 vs $0.03-$0.10 por analisis.

**P: Que modelos LLM usan?**
> Principalmente deepseek-coder y codellama para analisis de codigo. Son modelos open-source optimizados para codigo que corren localmente.

**P: Como garantizan la calidad del LLM local vs APIs comerciales?**
> Implementamos RAG (Retrieval Augmented Generation) con base de conocimiento de vulnerabilidades, mas un Verificator que valida los hallazgos contra patrones conocidos. Esto mejoro la precision de 75% a 88%.

### Sobre los Resultados

**P: El corpus de 4 contratos no es muy pequeno?**
> Si, es una limitacion reconocida. Sin embargo, los 4 contratos cubren 7 categorias SWC y 14 vulnerabilidades conocidas. El enfoque fue validar la arquitectura, no hacer benchmark exhaustivo. Trabajo futuro incluye validacion con SmartBugs (143 contratos).

**P: Como midieron el recall de 100%?**
> Contra vulnerabilidades conocidas y documentadas en el corpus de prueba. MIESC detecto las 14/14 vulnerabilidades conocidas. En escenarios reales con vulnerabilidades desconocidas, el recall sera menor.

**P: Que pasa con vulnerabilidades de logica de negocio?**
> Es una limitacion. Vulnerabilidades como flash loan attacks o MEV exploitation requieren conocimiento del contexto de negocio que las herramientas automaticas no capturan completamente. SmartLLM ayuda pero no es perfecto.

### Sobre Comparativas

**P: Como se compara MIESC con herramientas comerciales como Certora o OpenZeppelin?**
> MIESC es complementario, no competidor. Integra Certora Prover como una de las 25 herramientas. La diferencia es que MIESC orquesta multiples herramientas con IA soberana, mientras que soluciones comerciales son single-tool o requieren APIs cloud.

**P: Por que no usar simplemente Slither que es la mas popular?**
> Slither solo detecta ~66% de vulnerabilidades conocidas. La combinacion de herramientas en MIESC alcanza 100% recall. Ademas, Slither no detecta vulnerabilidades que requieren ejecucion simbolica o fuzzing.

### Sobre Aplicabilidad

**P: MIESC puede usarse en produccion hoy?**
> Si. Tiene 1,277 tests pasando, 59% coverage, API REST documentada, y Docker deployment. Ya esta postulado como Digital Public Good (GID0092948).

**P: Cual es el tiempo promedio de auditoria?**
> ~2 minutos para un contrato tipico (<500 LOC). Contratos mas grandes pueden tomar 5-10 minutos dependiendo de la complejidad.

**P: Que nivel de expertise se necesita para usar MIESC?**
> Nivel basico para ejecutar auditorias. El CLI es simple: `miesc audit contract.sol`. Para interpretar resultados y remediar, se necesita conocimiento de Solidity y seguridad.

### Sobre Trabajos Futuros

**P: Cuales son las prioridades para v5.0?**
> (1) Soporte multi-chain (Solana, Cairo), (2) Integracion VSCode, (3) Automated patching con LLM, (4) Runtime monitoring post-deployment.

**P: Como planean validar con un corpus mas grande?**
> Integracion con SmartBugs benchmark (143 contratos, 208 vulnerabilidades) esta en progreso. Tambien colaboracion con auditors profesionales para validacion en mainnet.

---

## 5. Respuestas a Criticas Potenciales

### "El corpus es muy pequeno"
> Reconozco la limitacion. El objetivo fue proof-of-concept de la arquitectura. La validacion exhaustiva con SmartBugs es trabajo futuro ya iniciado post-tesis.

### "Las metricas de IA son subjetivas"
> Correcto para evaluaciones cualitativas. Por eso las metricas principales (recall, precision, F1) son objetivas y medibles contra ground truth conocido.

### "Depende de que las herramientas esten instaladas"
> MIESC verifica disponibilidad y degrada graciosamente. Si Mythril no esta disponible, las otras 24 herramientas siguen funcionando. Docker image incluye todas las dependencias.

### "Ollama es mas lento que APIs cloud"
> Si, ~2x mas lento. Pero el trade-off es soberania total de datos. Para organizaciones con requisitos de confidencialidad, esto es aceptable.

---

## 6. Demo en Vivo - Script

### Preparacion (antes de defensa)
```bash
# Verificar Ollama
ollama list
# Debe mostrar deepseek-coder o codellama

# Verificar MIESC
cd /path/to/MIESC
python -c "from src.miesc_orchestrator import *; print('OK')"
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
1. Ejecucion del comando
2. Output de cada capa
3. Reporte final con vulnerabilidad detectada

---

## 7. Frases Clave para Recordar

### Apertura
> "En los ultimos 8 anos, mas de 7.8 mil millones de dolares se han perdido por vulnerabilidades en smart contracts. Hoy presento MIESC, un framework que aplica defensa en profundidad para prevenir estos ataques."

### Sobre IA Soberana
> "En ciberdefensa, enviar codigo fuente a servidores externos es inaceptable. MIESC garantiza que el codigo NUNCA sale de tu maquina."

### Sobre Resultados
> "MIESC logro 100% recall y mejora del 40.8% sobre la mejor herramienta individual, con costo operativo cero."

### Cierre
> "MIESC demuestra que la defensa en profundidad, aplicada correctamente con IA soberana, puede transformar la seguridad de smart contracts de fragmentada a integral."

---

## 8. Logistica

### Contactos
- **Director:** Mg. Eduardo Casanovas
- **Email autor:** fboiero@frvm.utn.edu.ar

### Materiales a Llevar
1. Laptop con MIESC instalado
2. USB con backup de slides (PDF)
3. Copia impresa de slides (por si acaso)
4. Documento de separacion tesis/post-tesis

### Post-Defensa
- Agradecer al tribunal
- Preguntar sobre correcciones si las hay
- Confirmar proximos pasos para aprobacion

---

*Documento de preparacion - Defensa 18 de Diciembre 2025*
*Maestria en Ciberdefensa - UNDEF/IUA*
