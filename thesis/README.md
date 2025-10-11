# XAUDIT FRAMEWORK - MASTER'S THESIS / TESIS DE MAESTRÍA

**Bilingual Documentation / Documentación Bilingüe**

---

## 🇪🇸 ESPAÑOL

### Título
**DESARROLLO DE UN MARCO DE TRABAJO PARA LA EVALUACIÓN DE SEGURIDAD EN CONTRATOS INTELIGENTES SOBRE LA MÁQUINA VIRTUAL DE ETHEREUM UTILIZANDO INTELIGENCIA ARTIFICIAL**

**Tesis de Maestría en Ciberdefensa**
- **Universidad:** Universidad Tecnológica Nacional - Facultad Regional Villa María (UTN-FRVM)
- **Autor:** Fernando Boiero
- **Año:** 2025
- **Director:** [Pendiente]

### 📚 Estructura de la Tesis

La documentación completa en español se encuentra en el directorio [`es/`](./es/):

#### Capítulos Principales
1. **[Introducción](./es/capitulo1_introduccion.md)** - Contexto, problemática, hipótesis y objetivos
2. **[Marco de Ciberdefensa](./es/capitulo2_ciberdefensa.md)** - Referenciales normativos (ISO 27001, ISO 42001, NIST, OWASP)
3. **[Marco Teórico Técnico](./es/capitulo3_marco_teorico.md)** - Arquitectura EVM, estándares ERC, vulnerabilidades
4. **[Estado del Arte](./es/capitulo4_estado_arte.md)** - Herramientas de auditoría (Slither, Echidna, Medusa, Foundry, Certora)
5. **[Metodología Propuesta](./es/capitulo5_metodologia.md)** - Framework Xaudit, pipeline híbrido, arquitectura
6. **[Implementación y Experimentos](./es/capitulo6_implementacion.md)** - Dataset, configuración, métricas
7. **[Resultados y Análisis](./es/capitulo7_resultados.md)** - Evaluación experimental, comparativas
8. **[Conclusiones](./es/capitulo8_conclusiones.md)** - Validación de hipótesis, trabajo futuro

#### Anexos
- **[Anexo A](./es/anexo_a_contratos.md)** - Contratos vulnerables analizados
- **[Anexo B](./es/anexo_b_cicd.md)** - Configuración de pipelines CI/CD
- **[Anexo C](./es/anexo_c_propiedades.md)** - Propiedades Scribble y Echidna
- **[Anexo D](./es/anexo_d_datos.md)** - Resultados experimentales (JSON/CSV)
- **[Anexo E](./es/anexo_e_codigo_ia.md)** - Módulo de inteligencia artificial

---

## 🇬🇧 ENGLISH

### Title
**DEVELOPMENT OF A FRAMEWORK FOR SECURITY EVALUATION OF SMART CONTRACTS ON THE ETHEREUM VIRTUAL MACHINE USING ARTIFICIAL INTELLIGENCE**

**Master's Thesis in Cyber Defense**
- **University:** National Technological University - Villa María Regional Faculty (UTN-FRVM)
- **Author:** Fernando Boiero
- **Year:** 2025
- **Advisor:** [Pending]

### 📚 Thesis Structure

The complete English documentation is located in the [`en/`](./en/) directory:

#### Main Chapters
1. **[Introduction](./en/chapter1_introduction.md)** - Context, problem statement, hypothesis, objectives
2. **[Cyber Defense Framework](./en/chapter2_cyberdefense.md)** - Normative references (ISO 27001, ISO 42001, NIST, OWASP)
3. **[Technical Theoretical Framework](./en/chapter3_theoretical.md)** - EVM architecture, ERC standards, vulnerabilities
4. **[State of the Art](./en/chapter4_state_of_art.md)** - Auditing tools (Slither, Echidna, Medusa, Foundry, Certora)
5. **[Proposed Methodology](./en/chapter5_methodology.md)** - Xaudit framework, hybrid pipeline, architecture
6. **[Implementation and Experiments](./en/chapter6_implementation.md)** - Dataset, configuration, metrics
7. **[Results and Analysis](./en/chapter7_results.md)** - Experimental evaluation, comparisons
8. **[Conclusions](./en/chapter8_conclusions.md)** - Hypothesis validation, future work

#### Appendices
- **[Appendix A](./en/appendix_a_contracts.md)** - Analyzed vulnerable contracts
- **[Appendix B](./en/appendix_b_cicd.md)** - CI/CD pipeline configuration
- **[Appendix C](./en/appendix_c_properties.md)** - Scribble and Echidna properties
- **[Appendix D](./en/appendix_d_data.md)** - Experimental results (JSON/CSV)
- **[Appendix E](./en/appendix_e_ai_code.md)** - Artificial intelligence module

---

## 🎯 Objetivos / Objectives

### Español
Desarrollar un marco de trabajo automatizado para la evaluación de seguridad de contratos inteligentes que integre:
- Análisis estático (Slither)
- Fuzzing property-based (Echidna) y coverage-guided (Medusa)
- Testing diferencial (Foundry)
- Verificación formal (Certora)
- Inteligencia artificial para triage y clasificación

### English
Develop an automated framework for smart contract security evaluation that integrates:
- Static analysis (Slither)
- Property-based fuzzing (Echidna) and coverage-guided (Medusa)
- Differential testing (Foundry)
- Formal verification (Certora)
- Artificial intelligence for triage and classification

---

## 📊 Contribuciones / Contributions

### Español
1. **Framework híbrido** - Primera integración completa de análisis estático, dinámico, formal e IA
2. **Dataset anotado** - 30+ contratos vulnerables con clasificación SWC
3. **Pipeline automatizado** - CI/CD reproducible con métricas estandarizadas
4. **Módulo de IA** - Clasificación automática con OpenAI/Llama local
5. **Open-source** - Herramienta disponible para la comunidad

### English
1. **Hybrid framework** - First complete integration of static, dynamic, formal analysis and AI
2. **Annotated dataset** - 30+ vulnerable contracts with SWC classification
3. **Automated pipeline** - Reproducible CI/CD with standardized metrics
4. **AI module** - Automatic classification with OpenAI/local Llama
5. **Open-source** - Tool available to the community

---

## 🔬 Metodología / Methodology

### Español
- **Paradigma:** Experimental cuantitativo
- **Referenciales:** ISO/IEC 27001, ISO/IEC 42001, NIST SSDF, OWASP
- **Métricas:** Precision, Recall, F1-Score, tiempo de análisis, cobertura de código

### English
- **Paradigm:** Quantitative experimental
- **References:** ISO/IEC 27001, ISO/IEC 42001, NIST SSDF, OWASP
- **Metrics:** Precision, Recall, F1-Score, analysis time, code coverage

---

## 📖 Cómo Citar / How to Cite

### Español
```bibtex
@mastersthesis{boiero2025xaudit,
  author  = {Fernando Boiero},
  title   = {Desarrollo de un Marco de Trabajo para la Evaluación de Seguridad
             en Contratos Inteligentes sobre la Máquina Virtual de Ethereum
             Utilizando Inteligencia Artificial},
  school  = {Universidad Tecnológica Nacional - FRVM},
  year    = {2025},
  type    = {Tesis de Maestría en Ciberdefensa},
  url     = {https://github.com/fboiero/xaudit}
}
```

### English
```bibtex
@mastersthesis{boiero2025xaudit,
  author  = {Fernando Boiero},
  title   = {Development of a Framework for Security Evaluation of Smart Contracts
             on the Ethereum Virtual Machine Using Artificial Intelligence},
  school  = {National Technological University - FRVM},
  year    = {2025},
  type    = {Master's Thesis in Cyber Defense},
  url     = {https://github.com/fboiero/xaudit}
}
```

---

## 📁 Organización del Repositorio / Repository Organization

```
xaudit/
├── src/                          # Código fuente / Source code
│   ├── contracts/                # Contratos de prueba / Test contracts
│   ├── tests/                    # Tests Foundry / Foundry tests
│   └── utils/                    # Scripts de utilidad / Utility scripts
├── analysis/                     # Herramientas de análisis / Analysis tools
│   ├── slither/                  # Configuración Slither
│   ├── echidna/                  # Configuración Echidna
│   ├── medusa/                   # Configuración Medusa
│   ├── certora/                  # Specs de verificación / Verification specs
│   └── scripts/                  # Scripts de automatización / Automation scripts
├── thesis/                       # Documentación de tesis / Thesis documentation
│   ├── es/                       # Versión en español / Spanish version
│   └── en/                       # Versión en inglés / English version
└── README.md                     # Este archivo / This file
```

---

## 🛠️ Instalación / Installation

Ver [README principal del proyecto](../README.md) / See [main project README](../README.md)

---

## 📧 Contacto / Contact

**Fernando Boiero**
- Universidad Tecnológica Nacional - FRVM
- Email: [Pendiente]
- GitHub: [@fboiero](https://github.com/fboiero)

---

## 📄 Licencia / License

Este trabajo académico está protegido por derechos de autor. El código fuente del framework Xaudit está disponible bajo licencia MIT.

This academic work is protected by copyright. The Xaudit framework source code is available under the MIT license.

---

**Universidad Tecnológica Nacional - Facultad Regional Villa María**
**Maestría en Ciberdefensa / Master's in Cyber Defense**
**2025**
