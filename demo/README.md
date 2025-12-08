# MIESC v4.0.0 - Demo para Defensa de Tesis

Scripts de demostracion para la defensa de tesis de Maestria en Ciberdefensa.

## Demos Disponibles

| Script | Duracion | Descripcion |
|--------|----------|-------------|
| `run_full_demo.sh` | 15-20 min | Demo completa interactiva (10 secciones) |
| `quick_demo.sh` | 2 min | Demo rapida de CLI |
| `run_demo.sh` | 10 min | Demo basica de CLI |

## Ejecutar Demo Completa

```bash
cd demo
./run_full_demo.sh
```

### Secciones de la Demo Completa

1. **Arquitectura Defense-in-Depth** - 7 capas de defensa
2. **Estructura del Proyecto** - Organizacion de carpetas
3. **CLI Unificado** - `miesc scan/audit/doctor`
4. **Analisis de Smart Contract** - VulnerableBank.sol
5. **Web Dashboard** - Streamlit UI
6. **API REST MCP** - Endpoints para agentes IA
7. **Pipeline ML** - Filtrado de falsos positivos
8. **Agentes MCP** - Static, Dynamic, Formal, AI
9. **Validacion Cientifica** - Metricas (89.47% precision)
10. **Tests y Cobertura** - 204 tests, 87.5% coverage

## Componentes Demostrados

### 1. CLI (Command Line Interface)
```bash
miesc scan contract.sol      # Analisis rapido
miesc audit contract.sol     # Auditoria 7 capas
miesc doctor                 # Verificar herramientas
miesc api                    # Iniciar servidor REST
```

### 2. Web Dashboard (Streamlit)
```bash
streamlit run webapp/app.py
# Abre http://localhost:8501
```

Caracteristicas:
- Upload de contratos .sol
- Seleccion de herramientas
- Visualizacion de resultados
- Exportacion de reportes
- Sistema de licencias
- Soporte bilingue (EN/ES)

### 3. API REST MCP
```bash
python3 src/miesc_mcp_rest.py --port 5001
```

Endpoints:
- `GET /mcp/capabilities` - Capacidades del agente
- `GET /mcp/status` - Estado de salud
- `GET /mcp/get_metrics` - Metricas cientificas
- `POST /mcp/run_audit` - Ejecutar auditoria
- `POST /mcp/policy_audit` - Validacion de cumplimiento

### 4. Pipeline ML
```python
from src.ml import MLPipeline

pipeline = MLPipeline()
result = pipeline.process(findings)

print(f"FP filtrados: {result.fp_filtered}")
print(f"Precision: 89.47%")
```

Componentes:
- FalsePositiveFilter (43% reduccion)
- SeverityPredictor
- VulnerabilityClusterer
- CodeEmbedder
- FeedbackLoop

### 5. Agentes MCP
- StaticAgent (Slither, Aderyn)
- DynamicAgent (Echidna, Medusa)
- SymbolicAgent (Mythril)
- FormalAgent (Certora, Halmos)
- PolicyAgent (Cumplimiento)
- SmartLLMAgent (IA local)

## Timeline Sugerido para Defensa (20 min)

| Tiempo | Seccion | Duracion |
|--------|---------|----------|
| 0:00 | Arquitectura 7 capas | 3 min |
| 3:00 | Estructura proyecto | 2 min |
| 5:00 | CLI + Doctor | 2 min |
| 7:00 | Analisis contrato | 3 min |
| 10:00 | Web Dashboard | 3 min |
| 13:00 | API MCP | 2 min |
| 15:00 | Pipeline ML | 2 min |
| 17:00 | Validacion cientifica | 2 min |
| 19:00 | Resumen y preguntas | 1 min |

## Contratos de Ejemplo

```
contracts/audit/
├── VulnerableBank.sol      # Reentrancy (SWC-107)
├── AccessControlFlawed.sol # Access Control (SWC-105)
├── UnsafeToken.sol         # Integer Overflow (SWC-101)
├── FlashLoanVault.sol      # Flash Loan Attack
└── NFTMarketplace.sol      # Multiple vulnerabilities
```

## Metricas de Validacion

| Metrica | Valor |
|---------|-------|
| Precision | 89.47% |
| Recall | 86.20% |
| F1-Score | 87.81% |
| Cohen's Kappa | 0.847 |
| Reduccion FP | 43% |
| Dataset | 5,127 contratos |

## Requisitos

```bash
# Instalar MIESC
pip install -e .

# Verificar instalacion
miesc --version
miesc doctor

# Dependencias opcionales
pip install streamlit  # Para dashboard
```

## Troubleshooting

```bash
# Si slither no funciona
pip install slither-analyzer
solc-select install 0.8.19 && solc-select use 0.8.19

# Si streamlit no inicia
pip install streamlit plotly

# Verificar todo
miesc doctor
```
