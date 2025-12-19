# Script de Presentacion - Defensa de Tesis MIESC

**Fecha de Defensa:** 18 de Diciembre 2025
**Duracion estimada:** 45-50 minutos de presentacion + 30-45 minutos de preguntas
**Total de slides:** 54

---

## Instrucciones Generales

- **Ritmo:** Aproximadamente 1 minuto por slide (algunas mas rapidas, otras mas lentas)
- **Pausas:** Hacer pausas naturales entre secciones
- **Contacto visual:** Mirar al tribunal, no solo a la pantalla
- **Figuras:** Cuando aparezca una figura, dar tiempo al tribunal para observarla

---

## SLIDE 1: Titulo (1 min)

**Decir:**
> "Buenos dias/tardes. Mi nombre es Fernando Boiero y hoy voy a defender mi tesis titulada MIESC: Multi-layer Intelligent Evaluation for Smart Contracts, un enfoque de ciberdefensa para la seguridad de contratos inteligentes."

---

## SLIDE 2: Datos de la Tesis (30 seg)

**Decir:**
> "Esta tesis fue desarrollada para la Maestria en Ciberdefensa de la Universidad de la Defensa Nacional, a traves del Instituto Universitario Aeronautico de Cordoba, bajo la direccion del Magister Eduardo Casanovas."

---

## SLIDE 3: Agenda (1 min)

**Decir:**
> "La presentacion esta estructurada en diez secciones. Comenzaremos con el contexto y motivacion, seguido del planteamiento del problema, marco teorico, la solucion propuesta, resultados experimentales, una demostracion en vivo, conclusiones, y finalmente trabajo posterior y lineas futuras. Al final abriremos espacio para preguntas."

---

## SLIDE 4: Seccion - Contexto y Motivacion (transicion)

**Decir:**
> "Comencemos con el contexto que motivo esta investigacion."

---

## SLIDE 5: La Amenaza es Real (1.5 min)

**Decir:**
> "En los ultimos ocho anos, mas de siete mil ochocientos millones de dolares se han perdido debido a vulnerabilidades en smart contracts. Esta tabla muestra los incidentes mas emblematicos: desde The DAO en 2016, que perdio 60 millones por una vulnerabilidad de reentrancy, hasta Euler Finance en 2023, con 197 millones perdidos por un ataque de flash loan. Estos no son casos aislados: son sintomas de un problema sistemico en la seguridad de smart contracts."

---

## SLIDE 6: Taxonomia de Amenazas (1 min)

**Decir:**
> "Esta figura muestra la taxonomia de amenazas a smart contracts. Observen que las vulnerabilidades se clasifican en multiples categorias: desde errores aritmeticos hasta problemas de control de acceso y manipulacion de flujo. La diversidad de vectores de ataque hace que ninguna herramienta individual pueda detectarlos todos."

---

## SLIDE 7: El Problema - Fragmentacion (1 min)

**Decir:**
> "El primer problema es la fragmentacion. Existen multiples enfoques de analisis: estatico, fuzzers, ejecucion simbolica, verificacion formal, e inteligencia artificial. Pero cada herramienta tiene salidas incompatibles, nomenclaturas diferentes, y cobertura parcial. Ninguna herramienta individual detecta mas del 70% de las vulnerabilidades conocidas."

---

## SLIDE 8: El Problema - Soberania de Datos (1 min)

**Decir:**
> "El segundo problema es la soberania de datos. Las herramientas con inteligencia artificial comercial requieren enviar codigo fuente a servidores externos. En el contexto de ciberdefensa, esto es inaceptable. El codigo puede contener propiedad intelectual, logica de negocio sensible, o estar sujeto a regulaciones como GDPR. Enviar codigo a APIs externas compromete la confidencialidad."

---

## SLIDE 9: Seccion - Planteamiento del Problema (transicion)

**Decir:**
> "Pasemos al planteamiento formal del problema."

---

## SLIDE 10: Problemas Especificos (1.5 min)

**Decir:**
> "Hemos identificado cuatro problemas especificos. Primero: no existe un framework que integre coherentemente las principales herramientas. Segundo: las salidas usan formatos incompatibles. Tercero: las soluciones con IA dependen de servicios externos. Y cuarto: no existe una arquitectura que aplique defensa en profundidad a smart contracts."

---

## SLIDE 11: Objetivos (1 min)

**Decir:**
> "Nuestro objetivo general es desarrollar un framework de codigo abierto que integre multiples herramientas en una arquitectura de defensa en profundidad, con inteligencia artificial soberana. Los objetivos especificos incluyen: integrar 25 herramientas en 7 capas, normalizar a taxonomias estandar, implementar IA 100% local, cumplir estandares de Digital Public Good, e integrar con asistentes via MCP."

---

## SLIDE 12: Seccion - Marco Teorico (transicion)

**Decir:**
> "Veamos el fundamento teorico."

---

## SLIDE 13: Fundamentos Teoricos (1 min)

**Decir:**
> "MIESC se fundamenta en el principio de Defensa en Profundidad de Saltzer y Schroeder: multiples capas independientes donde la falla de una no compromete la seguridad total. Tambien nos basamos en el trabajo de Durieux sobre analisis multi-herramienta, que demuestra que la combinacion mejora significativamente la deteccion. Y utilizamos las taxonomias SWC, CWE y OWASP Smart Contract Top 10."

---

## SLIDE 14: Seccion - Solucion Propuesta (transicion)

**Decir:**
> "Ahora presento MIESC, nuestra solucion."

---

## SLIDE 15: MIESC - Vision General (1 min)

**Decir:**
> "MIESC integra 25 herramientas en 7 capas de defensa. Logra 100% de recall en vulnerabilidades conocidas, una mejora del 40.8% sobre la mejor herramienta individual, con costo operativo cero gracias a la IA soberana con Ollama."

---

## SLIDE 16: Arquitectura Defense-in-Depth (1.5 min)

**Decir:**
> "Esta figura muestra la arquitectura de 7 capas de MIESC. Las capas se ejecutan en paralelo cuando es posible: analisis estatico, fuzzing, ejecucion simbolica, testing de invariantes, verificacion formal, property testing, y finalmente analisis con IA. Cada capa detecta clases diferentes de vulnerabilidades con minima superposicion."

---

## SLIDE 17: Patron Adapter (1 min)

**Decir:**
> "Para integrar herramientas heterogeneas, implementamos el patron Adapter. Este diagrama muestra como cada herramienta se conecta a traves de una interfaz unificada. El patron permite agregar nuevas herramientas sin modificar el core del sistema."

---

## SLIDE 18: Capa 1 - Analisis Estatico (45 seg)

**Decir:**
> "La primera capa ejecuta analisis estatico con Slither, Solhint, Securify2 y Semgrep. Proporciona mas de 90 detectores, analisis de flujo de datos, y deteccion de patrones inseguros. El tiempo de ejecucion es de aproximadamente 5 segundos por contrato."

---

## SLIDE 19: Capa 2 - Testing Dinamico (45 seg)

**Decir:**
> "La segunda capa realiza fuzzing con Echidna, Medusa, Foundry Fuzz y DogeFuzz. Genera inputs automaticamente para detectar invariantes violados. En la version 4.0, integramos DogeFuzz, que es hasta tres veces mas rapido que alternativas."

---

## SLIDE 20: Capa 3 - Ejecucion Simbolica (45 seg)

**Decir:**
> "La tercera capa usa ejecucion simbolica con Mythril, Manticore, Halmos y Oyente. Explora exhaustivamente los paths de ejecucion para detectar overflows y verificar assertions. Esta es la capa mas costosa computacionalmente, tomando de 1 a 5 minutos."

---

## SLIDE 21: Capas 4-5 - Verificacion Formal (45 seg)

**Decir:**
> "Las capas 4 y 5 realizan verificacion formal con SMTChecker, Certora, Scribble y Halmos. Proporcionan pruebas matematicas de propiedades de correctitud. Integramos PropertyGPT, que logra 80% de recall en propiedades ground-truth."

---

## SLIDE 22: Capas 6-7 - Analisis con IA (1 min)

**Decir:**
> "Las capas 6 y 7 utilizan inteligencia artificial con SmartLLM, GPTScan, LLMSmartAudit y ThreatModel. Realizan correlacion de hallazgos, analisis semantico y modelado de amenazas. Implementamos RAG y Verificator, mejorando la precision de 75% a 88%."

---

## SLIDE 23: Arquitectura RAG (1 min)

**Decir:**
> "Esta figura muestra la arquitectura RAG implementada en SmartLLM. El modelo LLM se aumenta con una base de conocimiento de vulnerabilidades conocidas. Esto permite respuestas mas precisas y contextualizadas."

---

## SLIDE 24: Flujo de Normalizacion (1 min)

**Decir:**
> "Este diagrama muestra el flujo de normalizacion. Los hallazgos de diferentes herramientas se mapean automaticamente a SWC, CWE y OWASP, permitiendo correlacion y deduplicacion. Esto reduce significativamente el ruido en los reportes."

---

## SLIDE 25: Patron Adapter - Codigo (45 seg)

**Decir:**
> "Aqui vemos la interfaz abstracta ToolAdapter. Cada herramienta implementa tres metodos: analyze para ejecutar el analisis, is_available para verificar disponibilidad, y get_metadata para introspection. Tenemos 25 adapters siguiendo este patron."

---

## SLIDE 26: IA Soberana con Ollama (1.5 min)

**Decir:**
> "MIESC garantiza que el codigo NUNCA sale de tu maquina. Mientras que APIs comerciales envian codigo a servidores externos con costos de hasta 10 centavos por analisis, MIESC usa Ollama con modelos como deepseek-coder localmente, con costo cero y cumpliendo el estandar Digital Public Good."

---

## SLIDE 27: Arquitectura IA Soberana (45 seg)

**Decir:**
> "Esta figura ilustra la diferencia. En la izquierda, el modelo tradicional donde el codigo se envia a APIs comerciales. En la derecha, nuestro enfoque: todo el procesamiento ocurre localmente."

---

## SLIDE 28: Integracion MCP - Codigo (45 seg)

**Decir:**
> "MIESC es la primera herramienta de auditoria con soporte para Model Context Protocol. Esto permite integracion nativa con asistentes como Claude, exponiendo endpoints para auditorias, correlacion, compliance y reportes."

---

## SLIDE 29: Arquitectura MCP (45 seg)

**Decir:**
> "Este diagrama muestra como Claude Desktop o cualquier cliente MCP puede invocar las herramientas de MIESC a traves del protocolo estandar."

---

## SLIDE 30: Seccion - Resultados Experimentales (transicion)

**Decir:**
> "Pasemos a la validacion experimental."

---

## SLIDE 31: Metodologia de Evaluacion (1 min)

**Decir:**
> "Realizamos una evaluacion comparativa con benchmark controlado. Las preguntas de investigacion fueron: RQ1 - integracion exitosa de 25 herramientas; RQ2 - mejora de deteccion; RQ3 - reduccion de duplicados; y RQ4 - viabilidad para produccion. El corpus incluyo 4 contratos con 14 vulnerabilidades conocidas en 7 categorias SWC."

---

## SLIDE 32: RQ1 - Integracion (1 min)

**Decir:**
> "RQ1: Logramos integracion del 100% de las herramientas planificadas. Las 25 herramientas estan operativas en las 7 capas, desde analisis estatico hasta IA."

---

## SLIDE 33: RQ2 - Mejora de Deteccion (1 min)

**Decir:**
> "RQ2: MIESC logra 94.5% de precision, 92.8% de recall, y F1-Score de 0.936, representando una mejora del 40.8% sobre la mejor herramienta individual. Slither individual tiene F1 de 0.70, mientras MIESC alcanza 0.93."

---

## SLIDE 34: RQ3 - Reduccion de Duplicados (1 min)

**Decir:**
> "RQ3: De 147 hallazgos brutos, MIESC identifica 50 unicos, eliminando 97 duplicados - una reduccion del 66%. La precision de normalizacion es del 97.1%."

---

## SLIDE 35: RQ4 - Viabilidad en Produccion (1 min)

**Decir:**
> "RQ4: MIESC es viable para produccion. Procesa un contrato en aproximadamente 2 minutos, con costo cero, 1,277 tests pasando, y un indice de compliance del 91.4%. Ya esta postulado como Digital Public Good con ID GID0092948."

---

## SLIDE 36: Comparativa de Rendimiento (1 min)

**Decir:**
> "Este grafico compara MIESC contra herramientas individuales en precision, recall y F1. Observen como MIESC supera a todas en cada metrica."

---

## SLIDE 37: Distribucion por Severidad (45 seg)

**Decir:**
> "Esta figura muestra la distribucion de hallazgos por severidad y capa. Las vulnerabilidades criticas son detectadas principalmente en las capas de ejecucion simbolica e IA."

---

## SLIDE 38: Timeline de Ejecucion (45 seg)

**Decir:**
> "Este timeline muestra como MIESC ejecuta las capas en paralelo para optimizar tiempos. Las capas independientes corren simultaneamente."

---

## SLIDE 39: Seccion - Demo en Vivo (transicion)

**Decir:**
> "Ahora voy a mostrar una demostracion en vivo de MIESC."

---

## SLIDE 40: Demo - Codigo Vulnerable (1 min)

**Decir:**
> "Este es un contrato vulnerable con el clasico patron de reentrancy. Observen que la llamada externa se realiza ANTES de actualizar el estado. Esto permite que un atacante re-entre la funcion antes de que el balance se ponga en cero."

> **[EJECUTAR DEMO - Ver seccion DEMO EN VIVO al final]**

---

## SLIDE 41: Seccion - Conclusiones (transicion)

**Decir:**
> "Pasemos a las conclusiones."

---

## SLIDE 42: Objetivos Alcanzados (1 min)

**Decir:**
> "Todos los objetivos fueron alcanzados o superados. Integramos 25 herramientas, implementamos 7 capas de defensa, normalizamos al 97.1%, eliminamos dependencias comerciales, y logramos mejoras del 40.8% en deteccion y 66% en reduccion de duplicados."

---

## SLIDE 43: Contribuciones Principales (1.5 min)

**Decir:**
> "Las contribuciones principales son cinco. Primero: la primera arquitectura de defensa en profundidad para smart contracts. Segundo: el protocolo ToolAdapter para integracion unificada. Tercero: normalizacion triple a SWC, CWE y OWASP. Cuarto: IA soberana eliminando dependencias comerciales. Y quinto: el primer MCP Server para auditoria de smart contracts."

---

## SLIDE 44: Limitaciones (1 min)

**Decir:**
> "Reconocemos limitaciones. Tecnicamente: la escalabilidad en contratos muy grandes, la dependencia de la calidad del modelo LLM, y la dificultad para detectar vulnerabilidades de logica de negocio como flash loans. Metodologicamente: el corpus de prueba es limitado, falta validacion en mainnet, y algunas metricas de IA son subjetivas."

---

## SLIDE 45: Seccion - Trabajo Post-Tesis (transicion)

**Decir:**
> "Quiero ser transparente sobre que se desarrollo DESPUES de entregar la tesis el 23 de octubre."

---

## SLIDE 46: Trabajo Post-Tesis - Overview (1 min)

**Decir:**
> "IMPORTANTE: Lo siguiente NO forma parte de la tesis entregada. Se presenta solo para contexto. Despues de la entrega, desarrollamos dos capas adicionales: Capa 8 para seguridad DeFi y Capa 9 para seguridad de dependencias. Tambien implementamos algunos de los trabajos futuros propuestos en la tesis."

---

## SLIDE 47: Funcionalidades Post-Tesis (45 seg)

**Decir:**
> "Las funcionalidades post-tesis incluyen exportadores multi-formato, metricas Prometheus, WebSocket en tiempo real, especificacion OpenAPI, y la aplicacion al programa Digital Public Good."

---

## SLIDE 48: Evolucion de Metricas (45 seg)

**Decir:**
> "Esta tabla muestra la evolucion desde la tesis v4.0 hasta la version actual v4.2. Pasamos de 7 a 9 capas, de 100 a 1,277 tests, y de 30,000 a 51,000 lineas de codigo."

---

## SLIDE 49: Seccion - Trabajos Futuros (transicion)

**Decir:**
> "Finalmente, las lineas de investigacion futuras propuestas en la tesis."

---

## SLIDE 50: Lineas de Investigacion Futuras (1 min)

**Decir:**
> "Proponemos cinco lineas principales. Soporte multi-chain para Solana, Cairo y Soroban. Fine-tuning de modelos LLM especializados. Monitoreo en runtime post-deployment. Generacion automatica de parches. E integracion con IDEs como VSCode."

---

## SLIDE 51: Gracias (transicion)

**Decir:**
> "Muchas gracias por su atencion. Estoy a disposicion para responder preguntas."

---

## SLIDE 52: Referencias Principales (para consulta)

**Solo si preguntan:**
> "Las referencias principales incluyen los trabajos de Atzei sobre ataques a Ethereum, Durieux sobre analisis automatizado, Saltzer y Schroeder sobre proteccion de informacion, y las especificaciones MCP de Anthropic y DPGA."

---

## SLIDE 53: Contacto (para consulta)

**Solo si preguntan:**
> "Pueden contactarme por email en fboiero@frvm.utn.edu.ar. El codigo esta disponible en GitHub bajo licencia AGPL-3.0."

---

## SLIDE 54: Cierre (transicion final)

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
python -c "from src.miesc_orchestrator import *; print('OK')"
```

### Durante la demo

**Decir:**
> "Voy a ejecutar MIESC contra un contrato vulnerable."

```bash
# Mostrar el contrato
cat contracts/audit/VulnerableBank.sol
```

**Decir:**
> "Observen la funcion withdraw. La llamada externa se hace antes de actualizar el estado - un patron clasico de reentrancy."

```bash
# Ejecutar auditoria
python demo_thesis_defense.py --quick --auto
```

**Decir:**
> "MIESC ejecuta las 7 capas en paralelo. Primero analisis estatico con Slither, luego fuzzing, ejecucion simbolica... Observen como cada capa reporta sus hallazgos. Finalmente, la capa de IA correlaciona y deduplica los resultados."

**Mostrar resultado:**
> "El reporte final identifica correctamente la vulnerabilidad de reentrancy como SWC-107, con severidad CRITICAL. Multiples herramientas la detectaron, pero MIESC las correlaciono en un unico hallazgo."

### Backup: Si la demo falla

**Decir:**
> "Lamentablemente, tengo un problema tecnico. Voy a mostrar un video pregrabado de la ejecucion."

> **[MOSTRAR VIDEO DE BACKUP]**

---

## VIDEO DEMO - Instrucciones para Grabar

### Que debe mostrar el video (2-3 minutos):

1. **Terminal limpia** con prompt visible
2. **Mostrar el contrato vulnerable** (`cat contracts/audit/VulnerableBank.sol`)
3. **Ejecutar auditoria** (python demo_thesis_defense.py)
4. **Output de cada capa** - pausar brevemente en cada una
5. **Reporte final** con vulnerabilidad detectada
6. **Mostrar mapeo SWC/CWE/OWASP**

### Como grabar:

**Opcion 1 - QuickTime (macOS):**
1. Abrir QuickTime Player
2. Archivo > Nueva grabacion de pantalla
3. Seleccionar area de la terminal
4. Grabar la ejecucion
5. Exportar a MP4

**Opcion 2 - OBS Studio (multiplataforma):**
1. Descargar OBS de obsproject.com
2. Configurar fuente como captura de ventana
3. Grabar
4. Exportar

**Opcion 3 - asciinema (terminal):**
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
- En la laptop (carpeta de presentacion)
- En USB de backup
- Subido a Google Drive/Dropbox como respaldo

---

## TIEMPOS POR SECCION

| Seccion | Slides | Tiempo |
|---------|--------|--------|
| Titulo y datos | 1-2 | 1.5 min |
| Contexto | 3-8 | 6 min |
| Problema | 9-11 | 3.5 min |
| Marco teorico | 12-13 | 2 min |
| Solucion MIESC | 14-29 | 12 min |
| Resultados | 30-38 | 8 min |
| Demo | 39-40 | 5 min |
| Conclusiones | 41-44 | 4 min |
| Post-tesis | 45-48 | 3 min |
| Trabajos futuros | 49-50 | 2 min |
| Cierre | 51-54 | 1 min |
| **TOTAL** | 54 | **48 min** |

---

*Script de presentacion para defensa de tesis - 18 de Diciembre 2025*
*MIESC v4.0.0 - Maestria en Ciberdefensa, UNDEF/IUA*
