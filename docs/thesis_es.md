# Tesis de Maestria

<div align="center">

![Tesis](https://img.shields.io/badge/Tesis-Maestria-blue?style=for-the-badge)
![Ano](https://img.shields.io/badge/Ano-2024--2025-green?style=for-the-badge)
![Estado](https://img.shields.io/badge/Estado-En%20Progreso-orange?style=for-the-badge)

**Marco Integrado de Evaluacion de Seguridad para Contratos Inteligentes:**
**Un Enfoque de Defensa en Profundidad para la Ciberdefensa**

*Maestria en Ciberdefensa*

[English](thesis.md) | **Espanol**

[Volver al Inicio](index_es.md)

</div>

---

## Informacion de la Tesis

| Campo | Valor |
|-------|-------|
| **Titulo** | Marco Integrado de Evaluacion de Seguridad para Contratos Inteligentes: Un Enfoque de Defensa en Profundidad para la Ciberdefensa |
| **Autor** | Fernando Boiero |
| **Director** | M.Sc. Eduardo Casanovas |
| **Institucion** | Universidad de la Defensa Nacional (UNDEF) - IUA Cordoba |
| **Programa** | Maestria en Ciberdefensa |
| **Defensa Prevista** | Q4 2025 |

---

## Resumen

Esta tesis presenta **MIESC (Multi-layer Intelligent Evaluation for Smart Contracts)**, un framework de seguridad de nivel productivo que implementa una **arquitectura de Defensa en Profundidad de 7 capas** para la deteccion integral de vulnerabilidades en contratos inteligentes.

El framework integra **25 herramientas de seguridad especializadas** con **correlacion potenciada por IA** usando LLMs soberanos (Ollama) y **deteccion basada en ML** (Redes Neuronales de Grafos DA-GNN), logrando **94.5% de precision**, **92.8% de recall** y un **F1-score de 0.93**.

Innovaciones clave incluyen:
- Sistema de triple normalizacion (SWC/CWE/OWASP) con 97.1% de precision
- Integracion del Protocolo MCP para interoperabilidad con asistentes de IA
- Backend de IA soberana asegurando que los datos nunca salen de la maquina del usuario
- Rescate de herramientas legacy para herramientas de seguridad deprecadas pero valiosas

---

## Capitulos

### Parte I: Fundamentos

| Capitulo | Titulo | Descripcion |
|----------|--------|-------------|
| 1 | [Introduccion](tesis/CAPITULO_INTRODUCCION.md) | Planteamiento del problema, objetivos y estructura de la tesis |
| 2 | [Marco Teorico](tesis/CAPITULO_MARCO_TEORICO.md) | Blockchain, contratos inteligentes y fundamentos de seguridad |
| 3 | [Estado del Arte](tesis/CAPITULO_ESTADO_DEL_ARTE.md) | Herramientas existentes, frameworks e investigacion |

### Parte II: Implementacion

| Capitulo | Titulo | Descripcion |
|----------|--------|-------------|
| 4 | [Desarrollo](tesis/CAPITULO_DESARROLLO.md) | Arquitectura de MIESC, agentes y detalles de implementacion |
| 5 | [Resultados Experimentales](tesis/CAPITULO_RESULTADOS.md) | Benchmarks, metricas y analisis comparativo |

### Parte III: Justificacion

| Capitulo | Titulo | Descripcion |
|----------|--------|-------------|
| 6 | [Justificacion de IA y LLM Soberano](tesis/CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md) | Soberania de datos, integracion con Ollama, cumplimiento DPGA |
| 7 | [Justificacion del Protocolo MCP](tesis/CAPITULO_JUSTIFICACION_MCP.md) | Model Context Protocol, manejadores de herramientas, interoperabilidad |

### Parte IV: Conclusiones

| Capitulo | Titulo | Descripcion |
|----------|--------|-------------|
| 8 | [Trabajos Futuros](tesis/CAPITULO_TRABAJOS_FUTUROS.md) | Direcciones de investigacion, mejoras planificadas |

---

## Metricas Clave

### Rendimiento del Framework (v4.0.0)

| Metrica | Valor |
|---------|-------|
| **Precision** | 94.5% |
| **Recall** | 92.8% |
| **F1-Score** | 0.93 |
| **Tasa de Falsos Positivos** | 5.5% |
| **Cobertura de Deteccion** | 96% |
| **Herramientas Integradas** | 25 |
| **Capas de Defensa** | 7 |
| **Indice de Cumplimiento** | 91.4% |

### Deteccion ML (DA-GNN)

| Metrica | Valor |
|---------|-------|
| **Precision** | 95.7% |
| **Tasa de Falsos Positivos** | 4.3% |
| **Representacion de Grafos** | CFG + DFG |

---

## Contribuciones de Investigacion

1. **Arquitectura de Defensa en Profundidad de 7 Capas** - Enfoque multicapa novedoso combinando capas estaticas, dinamicas, simbolicas, formales, IA, ML y auditoria

2. **Integracion de 25 Herramientas** - Protocolo ToolAdapter unificado para interoperabilidad fluida

3. **Sistema de Triple Normalizacion** - Mapeo SWC/CWE/OWASP con 97.1% de precision

4. **Backend de IA Soberana** - Integracion con Ollama asegurando soberania de datos y $0 de costo operativo

5. **Servidor MCP** - Model Context Protocol para integracion con asistentes de IA

6. **Rescate de Herramientas Legacy** - Compatibilidad de Manticore con Python 3.11, contenedorizacion Docker de Oyente

---

## Cita

```bibtex
@mastersthesis{boiero2025miesc,
  author = {Boiero, Fernando},
  title = {{MIESC}: Evaluacion Inteligente Multicapa para Contratos Inteligentes},
  school = {Universidad de la Defensa Nacional (UNDEF)},
  year = {2025},
  type = {Tesis de Maestria},
  address = {Cordoba, Argentina},
  note = {Maestria en Ciberdefensa}
}
```

---

<div align="center">

[Ver Documentacion Completa](index_es.md) | [Repositorio GitHub](https://github.com/fboiero/MIESC)

---

**MIESC v4.0.0** | Tesis de Maestria en Ciberdefensa | UNDEF - IUA Cordoba

2024-2025 Fernando Boiero

</div>
