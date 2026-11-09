# Script de Presentación - Defensa de Tesis MIESC

**Fecha de Defensa:** 18 de Diciembre 2025
**Duración estimada:** 45-50 minutos de presentación + 30-45 minutos de preguntas
**Total de slides:** 54

---

## Instrucciones Generales

- **Ritmo:** Aproximadamente 1 minuto por slide (algunas más rápidas, otras más lentas)
- **Pausas:** Hacer pausas naturales entre secciones
- **Contacto visual:** Mirar al tribunal, no solo a la pantalla
- **Figuras:** Cuando aparezca una figura, dar tiempo al tribunal para observarla

---

## SLIDE 1: Título (1 min)

**Decir:**
> "Buenos días/tardes. Mi nombre es Fernando Boiero y hoy voy a defender mi tesis titulada MIESC: Multi-layer Intelligent Evaluation for Smart Contracts, un enfoque de ciberdefensa para la seguridad de contratos inteligentes."

---

## SLIDE 2: Datos de la Tesis (30 seg)

**Decir:**
> "Esta tesis fue desarrollada para la Maestría en Ciberdefensa de la Universidad de la Defensa Nacional, a través del Instituto Universitario Aeronáutico de Córdoba, bajo la dirección del Magister Eduardo Casanovas."

---

## SLIDE 3: Agenda (1 min)

**Decir:**
> "La presentación está estructurada en diez secciones. Comenzaremos con el contexto y motivación, seguido del planteamiento del problema, marco teórico, la solución propuesta, resultados experimentales, una demostración en vivo, conclusiones, y finalmente trabajo posterior y líneas futuras. Al final abriremos espacio para preguntas."

---

## SLIDE 4: Sección - Contexto y Motivación (transición)

**Decir:**
> "Comencemos con el contexto que motivo esta investigación."

---

## SLIDE 5: La Amenaza es Real (1.5 min)

**Decir:**
> "En los ultimos ocho años, más de siete mil ochocientos millones de dólares se han perdido debido a vulnerabilidades en smart contracts. Esta tabla muestra los incidentes más emblemáticos: desde The DAO en 2016, que perdió 60 millones por una vulnerabilidad de reentrancy, hasta Euler Finance en 2023, con 197 millones perdidos por un ataque de flash loan. Estos no son casos aislados: son sintomas de un problema sistémico en la seguridad de smart contracts."

---

## SLIDE 6: Taxonomía de Amenazas (1 min)

**Decir:**
> "Esta figura muestra la taxonomía de amenazas a smart contracts. Observen que las vulnerabilidades se clasifican en múltiples categorías: desde errores aritméticos hasta problemas de control de acceso y manipulación de flujo. La diversidad de vectores de ataque hace que ninguna herramienta individual pueda detectarlos todos."

---

## SLIDE 7: El Problema - Fragmentación (1 min)

**Decir:**
> "El primer problema es la fragmentación. Existen múltiples enfoques de análisis: estático, fuzzers, ejecución simbólica, verificación formal, e inteligencia artificial. Pero cada herramienta tiene salidas incompatibles, nomenclaturas diferentes, y cobertura parcial. Ninguna herramienta individual detecta más del 70% de las vulnerabilidades conocidas."

---

## SLIDE 8: El Problema - Soberanía de Datos (1 min)

**Decir:**
> "El segundo problema es la soberanía de datos. Las herramientas con inteligencia artificial comercial requieren enviar código fuente a servidores externos. En el contexto de ciberdefensa, esto es inaceptable. El código puede contener propiedad intelectual, lógica de negocio sensible, o estar sujeto a regulaciones como GDPR. Enviar código a APIs externas compromete la confidencialidad."

---

## SLIDE 9: Sección - Planteamiento del Problema (transición)

**Decir:**
> "Pasemos al planteamiento formal del problema."

---

## SLIDE 10: Problemas Específicos (1.5 min)

**Decir:**
> "Hemos identificado cuatro problemas específicos. Primero: no existe un framework que integre coherentemente las principales herramientas. Segundo: las salidas usan formatos incompatibles. Tercero: las soluciones con IA dependen de servicios externos. Y cuarto: no existe una arquitectura que aplique defensa en profundidad a smart contracts."

---

## SLIDE 11: Objetivos (1 min)

**Decir:**
> "Nuestro objetivo general es desarrollar un framework de código abierto que integre múltiples herramientas en una arquitectura de defensa en profundidad, con inteligencia artificial soberana. Los objetivos específicos incluyen: integrar 25 herramientas en 7 capas, normalizar a taxonomías estándar, implementar IA 100% local, cumplir estándares de Digital Public Good, e integrar con asistentes vía MCP."

---

## SLIDE 12: Sección - Marco Teórico (transición)

**Decir:**
> "Veamos el fundamento teórico."

---

## SLIDE 13: Fundamentos Teóricos (1 min)

**Decir:**
> "MIESC se fundamenta en el principio de Defensa en Profundidad de Saltzer y Schroeder: múltiples capas independientes donde la falla de una no compromete la seguridad total. También nos basamos en el trabajo de Durieux sobre análisis multi-herramienta, que demuestra que la combinación mejora significativamente la detección. Y utilizamos las taxonomías SWC, CWE y OWASP Smart Contract Top 10."

---

## SLIDE 14: Sección - Solución Propuesta (transición)

**Decir:**
> "Ahora presento MIESC, nuestra solución."

---

## SLIDE 15: MIESC - Visión General (1 min)

**Decir:**
> "MIESC integra 25 herramientas en 7 capas de defensa. Con un perfil recall-first cubre el 100% de las vulnerabilidades documentadas del corpus, y su detección type-aware sube del 48% al 72% al incorporar la capa de razonamiento LLM, todo con costo operativo cero gracias a la IA soberana con Ollama."

---

## SLIDE 16: Arquitectura Defense-in-Depth (1.5 min)

**Decir:**
> "Esta figura muestra la arquitectura de 7 capas de MIESC. Las capas se ejecutan en paralelo cuando es posible: análisis estático, fuzzing, ejecución simbólica, testing de invariantes, verificación formal, property testing, y finalmente análisis con IA. Cada capa detecta clases diferentes de vulnerabilidades con minima superposición."

---

## SLIDE 17: Patrón Adapter (1 min)

**Decir:**
> "Para integrar herramientas heterogéneas, implementamos el patrón Adapter. Este diagrama muestra como cada herramienta se conecta a través de una interfaz unificada. El patrón permite agregar nuevas herramientas sin modificar el core del sistema."

---

## SLIDE 18: Capa 1 - Análisis Estático (45 seg)

**Decir:**
> "La primera capa ejecuta análisis estático con Slither, Solhint, Securify2 y Semgrep. Proporciona más de 90 detectores, análisis de flujo de datos, y detección de patrones inseguros. El tiempo de ejecución es de aproximadamente 5 segundos por contrato."

---

## SLIDE 19: Capa 2 - Testing Dinámico (45 seg)

**Decir:**
> "La segunda capa realiza fuzzing con Echidna, Medusa, Foundry Fuzz y DogeFuzz. Genera inputs automáticamente para detectar invariantes violados. En la versión 4.0, integramos DogeFuzz, que es hasta tres veces más rápido que alternativas."

---

## SLIDE 20: Capa 3 - Ejecución Simbólica (45 seg)

**Decir:**
> "La tercera capa usa ejecución simbólica con Mythril, Manticore, Halmos y Oyente. Explora exhaustivamente los paths de ejecución para detectar overflows y verificar assertions. Esta es la capa más costosa computacionalmente, tomando de 1 a 5 minutos."

---

## SLIDE 21: Capas 4-5 - Verificación Formal (45 seg)

**Decir:**
> "Las capas 4 y 5 realizan verificación formal con SMTChecker, Certora, Scribble y Halmos. Proporcionan pruebas matemáticas de propiedades de correctitud. Integramos PropertyGPT, que logra 80% de recall en propiedades ground-truth."

---

## SLIDE 22: Capas 6-7 - Análisis con IA (1 min)

**Decir:**
> "Las capas 6 y 7 utilizan inteligencia artificial con SmartLLM, GPTScan, LLMSmartAudit y ThreatModel. Realizan correlación de hallazgos, análisis semántico y modelado de amenazas. Implementamos RAG y Verificator, mejorando la precisión de 75% a 88%."

---

## SLIDE 23: Arquitectura RAG (1 min)

**Decir:**
> "Esta figura muestra la arquitectura RAG implementada en SmartLLM. El modelo LLM se aumenta con una base de conocimiento de vulnerabilidades conocidas. Esto permite respuestas más precisas y contextualizadas."

---

## SLIDE 24: Flujo de Normalización (1 min)

**Decir:**
> "Este diagrama muestra el flujo de normalización. Los hallazgos de diferentes herramientas se mapean automáticamente a SWC, CWE y OWASP, permitiendo correlación y deduplicación. Esto reduce significativamente el ruido en los reportes."

---

## SLIDE 25: Patrón Adapter - Código (45 seg)

**Decir:**
> "Aquí vemos la interfaz abstracta ToolAdapter. Cada herramienta implementa tres métodos: analyze para ejecutar el análisis, is_available para verificar disponibilidad, y get_metadata para introspection. Tenemos 25 adapters siguiendo este patrón."

---

## SLIDE 26: IA Soberana con Ollama (1.5 min)

**Decir:**
> "MIESC garantiza que el código NUNCA sale de tu máquina. Mientras que APIs comerciales envian código a servidores externos con costos de hasta 10 centavos por análisis, MIESC usa Ollama con modelos como deepseek-coder localmente, con costo cero y cumpliendo el estándar Digital Public Good."

---

## SLIDE 27: Arquitectura IA Soberana (45 seg)

**Decir:**
> "Esta figura ilustra la diferencia. En la izquierda, el modelo tradicional donde el código se envia a APIs comerciales. En la derecha, nuestro enfoque: todo el procesamiento ocurre localmente."

---

## SLIDE 28: Integración MCP - Código (45 seg)

**Decir:**
> "MIESC es la primera herramienta de auditoría con soporte para Model Context Protocol. Esto permite integración nativa con asistentes como Claude, exponiendo endpoints para auditorías, correlación, compliance y reportes."

---

## SLIDE 29: Arquitectura MCP (45 seg)

**Decir:**
> "Este diagrama muestra como Claude Desktop o cualquier cliente MCP puede invocar las herramientas de MIESC a través del protocolo estándar."

---

## SLIDE 30: Sección - Resultados Experimentales (transición)

**Decir:**
> "Pasemos a la validación experimental."

---

## SLIDE 31: Metodología de Evaluación (1 min)

**Decir:**
> "Realizamos una evaluación comparativa con benchmark controlado. Las preguntas de investigación fueron: RQ1 - integración exitosa de 25 herramientas; RQ2 - mejora de detección; RQ3 - reducción de duplicados; y RQ4 - viabilidad para producción. El corpus incluyó 4 contratos con 29 vulnerabilidades documentadas (614 LOC) en 9 o más categorías SWC."

---

## SLIDE 32: RQ1 - Integración (1 min)

**Decir:**
> "RQ1: Logramos integración del 100% de las herramientas planificadas. Las 25 herramientas están operativas en las 7 capas, desde análisis estático hasta IA."

---

## SLIDE 33: RQ2 - Mejora de Detección (1 min)

**Decir:**
> "RQ2: medimos Slither de forma aislada sobre el mismo corpus. Combinar herramientas estáticas y de patrón NO superó a Slither sola: cobertura equivalente (100% vs 96%) pero menor detección de tipo (48% vs 58%) y ~6x más falsos positivos. La mejora real proviene de agregar la capa de razonamiento LLM, que eleva el recall type-aware del 48% al 72%, superando a Slither."

---

## SLIDE 34: RQ3 - Reducción de Duplicados (1 min)

**Decir:**
> "RQ3: De 385 hallazgos brutos, MIESC identifica 123 únicos, eliminando 262 duplicados - una reducción del 68%. La precisión de normalización es del 97.1%."

---

## SLIDE 35: RQ4 - Viabilidad en Producción (1 min)

**Decir:**
> "RQ4: MIESC es viable para producción. Procesa un contrato en aproximadamente 2 minutos, con costo cero, más de 6.000 tests automatizados y calidad verificada en integración continua. Ya está postulado como Digital Public Good con ID GID0092948."

---

## SLIDE 36: Comparativa de Rendimiento (1 min)

**Decir:**
> "Este gráfico compara MIESC contra herramientas individuales en precisión, recall y F1. Observen como MIESC supera a todas en cada métrica."

---

## SLIDE 37: Distribución por Severidad (45 seg)

**Decir:**
> "Esta figura muestra la distribución de hallazgos por severidad y capa. Las vulnerabilidades críticas son detectadas principalmente en las capas de ejecución simbólica e IA."

---

## SLIDE 38: Timeline de Ejecución (45 seg)

**Decir:**
> "Este timeline muestra como MIESC ejecuta las capas en paralelo para optimizar tiempos. Las capas independientes corren simultáneamente."

---

## SLIDE 39: Sección - Demo en Vivo (transición)

**Decir:**
> "Ahora voy a mostrar una demostración en vivo de MIESC."

---

## SLIDE 40: Demo - Código Vulnerable (1 min)

**Decir:**
> "Este es un contrato vulnerable con el clásico patrón de reentrancy. Observen que la llamada externa se realiza ANTES de actualizar el estado. Esto permite que un atacante re-entre la función antes de que el balance se ponga en cero."

> **[EJECUTAR DEMO - Ver sección DEMO EN VIVO al final]**

---

## SLIDE 41: Sección - Conclusiones (transición)

**Decir:**
> "Pasemos a las conclusiones."

---

## SLIDE 42: Objetivos Alcanzados (1 min)

**Decir:**
> "Todos los objetivos fueron alcanzados. Integramos 25 herramientas, implementamos 7 capas de defensa, normalizamos al 97.1%, eliminamos dependencias comerciales, elevamos la detección type-aware del 48% al 72% con la capa LLM y logramos un 68% de reducción de duplicados."

---

## SLIDE 43: Contribuciones Principales (1.5 min)

**Decir:**
> "Las contribuciones principales son cinco. Primero: la primera arquitectura de defensa en profundidad para smart contracts. Segundo: el protocolo ToolAdapter para integración unificada. Tercero: normalización triple a SWC, CWE y OWASP. Cuarto: IA soberana eliminando dependencias comerciales. Y quinto: el primer MCP Server para auditoría de smart contracts."

---

## SLIDE 44: Limitaciones (1 min)

**Decir:**
> "Reconocemos limitaciones. Tecnicamente: la escalabilidad en contratos muy grandes, la dependencia de la calidad del modelo LLM, y la dificultad para detectar vulnerabilidades de lógica de negocio como flash loans. Metodologicamente: el corpus de prueba es limitado, falta validación en mainnet, y algunas métricas de IA son subjetivas."

---

## SLIDE 45: Sección - Trabajo Post-Tesis (transición)

**Decir:**
> "Quiero ser transparente sobre que se desarrollo DESPUÉS de entregar la tesis el 23 de octubre."

---

## SLIDE 46: Trabajo Post-Tesis - Overview (1 min)

**Decir:**
> "IMPORTANTE: Lo siguiente NO forma parte de la tesis entregada. Se presenta solo para contexto. Después de la entrega, desarrollamos dos capas adicionales: Capa 8 para seguridad DeFi y Capa 9 para seguridad de dependencias. También implementamos algunos de los trabajos futuros propuestos en la tesis."

---

## SLIDE 47: Funcionalidades Post-Tesis (45 seg)

**Decir:**
> "Las funcionalidades post-tesis incluyen exportadores multi-formato, métricas Prometheus, WebSocket en tiempo real, especificación OpenAPI, y la aplicación al programa Digital Public Good."

---

## SLIDE 48: Evolución de Métricas (45 seg)

**Decir:**
> "Esta tabla muestra la evolución desde la versión documentada en la tesis (v4.0, 7 capas) hasta la línea v5.x posterior. Pasamos de 7 a 9 capas, de 100 a más de 6.000 tests, y de 30,000 a 51,000 líneas de código."

---

## SLIDE 49: Sección - Trabajos Futuros (transición)

**Decir:**
> "Finalmente, las líneas de investigación futuras propuestas en la tesis."

---

## SLIDE 50: Líneas de Investigación Futuras (1 min)

**Decir:**
> "Proponemos cinco líneas principales. Soporte multi-chain para Solana, Cairo y Soroban. Fine-tuning de modelos LLM especializados. Monitoreo en runtime post-deployment. Generación automática de parches. E integración con IDEs como VSCode."

---

## SLIDE 51: Gracias (transición)

**Decir:**
> "Muchas gracias por su atención. Estoy a disposicion para responder preguntas."

---

## SLIDE 52: Referencias Principales (para consulta)

**Solo si preguntan:**
> "Las referencias principales incluyen los trabajos de Atzei sobre ataques a Ethereum, Durieux sobre análisis automatizado, Saltzer y Schroeder sobre protección de información, y las especificaciones MCP de Anthropic y DPGA."

---

## SLIDE 53: Contacto (para consulta)

**Solo si preguntan:**
> "Pueden contactarme por email en fboiero@frvm.utn.edu.ar. El código está disponible en GitHub bajo licencia AGPL-3.0."

---

## SLIDE 54: Cierre (transición final)

**Decir:**
> "MIESC demuestra que la defensa en profundidad, aplicada correctamente con IA soberana, puede transformar la seguridad de smart contracts de fragmentada a integral. Defense-in-Depth for the Blockchain Era."

---

## DEMO EN VIVO - Script Detallado

### Antes de la demo (verificar en laptop)

```bash
# Verificar que Ollama esta corriendo
ollama list

# Verificar MIESC
cd /path/to/MIESC
python -c "from miesc.core.orchestrator import MIESCOrchestrator; print('OK')"
```

### Durante la demo

**Decir:**
> "Voy a ejecutar MIESC contra un contrato vulnerable."

```bash
# Mostrar el contrato
cat contracts/audit/VulnerableBank.sol
```

**Decir:**
> "Observen la función withdraw. La llamada externa se hace antes de actualizar el estado - un patrón clásico de reentrancy."

```bash
# Ejecutar auditoria
python demo_thesis_defense.py --quick --auto
```

**Decir:**
> "MIESC ejecuta las 7 capas en paralelo. Primero análisis estático con Slither, luego fuzzing, ejecución simbólica... Observen como cada capa reporta sus hallazgos. Finalmente, la capa de IA correlaciona y deduplica los resultados."

**Mostrar resultado:**
> "El reporte final identifica correctamente la vulnerabilidad de reentrancy como SWC-107, con severidad CRITICAL. Múltiples herramientas la detectaron, pero MIESC las correlaciono en un único hallazgo."

### Backup: Si la demo falla

**Decir:**
> "Lamentablemente, tengo un problema técnico. Voy a mostrar un video pregrabado de la ejecución."

> **[MOSTRAR VIDEO DE BACKUP]**

---

## VIDEO DEMO - Instrucciones para Grabar

### Que debe mostrar el video (2-3 minutos):

1. **Terminal limpia** con prompt visible
2. **Mostrar el contrato vulnerable** (`cat contracts/audit/VulnerableBank.sol`)
3. **Ejecutar auditoría** (python demo_thesis_defense.py)
4. **Output de cada capa** - pausar brevemente en cada una
5. **Reporte final** con vulnerabilidad detectada
6. **Mostrar mapeo SWC/CWE/OWASP**

### Como grabar:

**Opción 1 - QuickTime (macOS):**
1. Abrir QuickTime Player
2. Archivo > Nueva grabacion de pantalla
3. Seleccionar área de la terminal
4. Grabar la ejecución
5. Exportar a MP4

**Opción 2 - OBS Studio (multiplataforma):**
1. Descargar OBS de obsproject.com
2. Configurar fuente como captura de ventana
3. Grabar
4. Exportar

**Opción 3 - asciinema (terminal):**
```bash
# Instalar
brew install asciinema

# Grabar
asciinema rec demo_defensa.cast

# Ejecutar demo...

# Detener con Ctrl+D
# Convertir a GIF con asciinema-agg
```

### Nombre del archivo:
`MIESC_Demo_Defensa_18Dic2025.mp4`

### Donde guardarlo:
- En la laptop (carpeta de presentación)
- En USB de backup
- Subido a Google Drive/Dropbox como respaldo

---

## TIEMPOS POR SECCIÓN

| Sección | Slides | Tiempo |
|---------|--------|--------|
| Título y datos | 1-2 | 1.5 min |
| Contexto | 3-8 | 6 min |
| Problema | 9-11 | 3.5 min |
| Marco teórico | 12-13 | 2 min |
| Solución MIESC | 14-29 | 12 min |
| Resultados | 30-38 | 8 min |
| Demo | 39-40 | 5 min |
| Conclusiones | 41-44 | 4 min |
| Post-tesis | 45-48 | 3 min |
| Trabajos futuros | 49-50 | 2 min |
| Cierre | 51-54 | 1 min |
| **TOTAL** | 54 | **48 min** |

---

*Script de presentación para defensa de tesis - 18 de Diciembre 2025*
*MIESC v4.0.0 - Maestría en Ciberdefensa, UNDEF/IUA*
