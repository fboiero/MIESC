# MIESC - AI Tools Comparison Results

Este directorio contiene los resultados empíricos de la comparación entre herramientas AI para auditoría de smart contracts, utilizados para la defensa de tesis.

## 📊 Dataset Público

### Contratos Analizados

1. **vulnerable_bank.sol**: Contrato con 4 vulnerabilidades conocidas
   - Reentrancy (High)
   - Missing Access Control (High)
   - Unchecked Call Return Value (Medium)
   - Timestamp Dependence (Low)

2. **voting.sol**: Contrato limpio para testing básico
   - Sin vulnerabilidades críticas
   - Usado como baseline

### Herramientas Comparadas

#### 1. MIESC StaticAgent (Baseline)
- **Tecnología**: Slither + Solhint + Surya
- **Enfoque**: Análisis estático exhaustivo
- **Cobertura**: 12+ detectores
- **Tiempo promedio**: 0.9s

#### 2. GPTScan (ICSE 2024)
- **Tecnología**: Slither + GPT-4
- **Enfoque**: Análisis estático + lógica con LLM
- **Especialización**: Token contracts, logic bugs
- **Tiempo promedio**: 0.4s
- **Paper**: https://gptscan.github.io/

#### 3. MIESC AIAgent (Layer 6 Triage)
- **Tecnología**: GPT-4 para triage de falsos positivos
- **Enfoque**: Reducción de FP, análisis de causa raíz
- **FP Rate**: < 10% (objetivo)
- **Tiempo promedio**: < 0.01s (post-processing)

## 📁 Archivos

### JSON Results
```
ai_tools_comparison_*.json  # Resultados detallados por contrato
```

**Estructura JSON**:
```json
{
  "contract": "vulnerable_bank.sol",
  "timestamp": "2025-10-12T...",
  "results": {
    "static": {
      "findings": [...],
      "count": 12,
      "severity_count": {"High": 2, "Medium": 2, ...},
      "execution_time": 1.09
    },
    "gptscan": {...},
    "ai_triage": {...}
  }
}
```

### Visualizaciones

```
visualizations/
├── 01_findings_comparison.png       # Comparación de total de findings
├── 02_severity_distribution.png     # Distribución por severidad
├── 03_execution_time.png            # Tiempos de ejecución
├── 04_precision_comparison.png      # Precisión (% High+Medium)
└── 05_summary_table.png             # Tabla resumen
```

## 📈 Resultados Clave

### vulnerable_bank.sol

| Tool           | Findings | High | Medium | Time (s) |
|----------------|----------|------|--------|----------|
| StaticAgent    | 12       | 2    | 2      | 1.10     |
| GPTScan        | 1        | 1    | 0      | 0.40     |
| AIAgent        | 24*      | 4    | 4      | 0.00     |

*Nota: AIAgent muestra duplicados sin triage GPT habilitado.

### voting.sol (Clean Contract)

| Tool           | Findings | High | Medium | Time (s) |
|----------------|----------|------|--------|----------|
| StaticAgent    | 3        | 0    | 0      | 0.75     |
| GPTScan        | 0        | 0    | 0      | 0.44     |
| AIAgent        | 6*       | 0    | 0      | 0.00     |

## 🔬 Metodología

### Ejecución
```bash
# Generar resultados
python demo_ai_tools_comparison.py examples/<contract>.sol

# Generar visualizaciones
python visualize_comparison.py
```

### Ambiente
- Python 3.9+
- Slither 0.10.4
- OpenAI GPT-4 (opcional, sin API key usa modo static-only)
- Matplotlib 3.9.4

### Métricas

**Precisión**: (High + Medium) / Total Findings * 100%
- Mide el enfoque en vulnerabilidades críticas

**FP Rate**: False Positives / Total Findings * 100%
- Mide la tasa de falsos positivos detectados por AI triage

**Speedup**: Baseline Time / Tool Time
- Mide mejora en tiempo de ejecución

## 📖 Referencias

### Papers Implementados

1. **GPTScan** (ICSE 2024)
   - "GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis"
   - https://gptscan.github.io/
   - Precisión reportada: >90% en token contracts

2. **LLM-SmartAudit** (ArXiv 2410.09381)
   - "LLM-SmartAudit: Multi-agent Conversational Framework for Smart Contract Auditing"
   - https://arxiv.org/abs/2410.09381
   - Enfoque: 3 agentes conversacionales

### Framework Base

**MIESC v2.0** - Marco Integrado de Evaluación de Seguridad
- Arquitectura: MCP (Model Context Protocol) multiagente
- Layers: 6 capas (Static → Dynamic → Symbolic → Formal → AI → Policy)
- Estándares: ISO 27001, NIST SSDF, OWASP SC Top 10

## 🎓 Uso para Tesis

### Defensa de Tesis

**Objetivo**: Demostrar la integración de herramientas AI en MIESC

**Contribuciones**:
1. **Extensibilidad**: Standard para integrar herramientas AI (BaseAgent)
2. **Interoperabilidad**: Formato unificado (SWC/OWASP/CWE mapping)
3. **Benchmarking**: Dataset público con resultados empíricos

**Visualizaciones**: 5 charts listos para presentación (PNG 300 DPI)

### Reproducibilidad

Todos los scripts, agentes y contratos están en:
- Repository: https://github.com/fboiero/xaudit
- Branch: main
- Commit: Ver git log para último commit de AI tools

## 📄 Licencia

GPL-3.0 License - Ver [LICENSE](../LICENSE)

## 👤 Autor

**Fernando Boiero**
- Email: fboiero@frvm.utn.edu.ar
- Institución: Universidad Tecnológica Nacional - FRVM
- GitHub: [@fboiero](https://github.com/fboiero)

---

**Última Actualización**: Octubre 2025
**Versión Dataset**: v1.0
**Status**: ✅ Ready for Thesis Defense
