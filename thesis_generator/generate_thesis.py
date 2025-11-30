#!/usr/bin/env python3
"""
MIESC Thesis Generator - Generador Unificado de Tesis
=====================================================

Script unificado para generar la tesis MIESC en formato ODT
cumpliendo con el Reglamento de Tesis MCD (DD 047-020).

Características:
1. Genera 10 figuras profesionales (PNG, 300 DPI)
2. Genera documento ODT con formato reglamentario:
   - Carátula según Anexo 1 del Reglamento
   - Estilos de encabezado con jerarquía para índice automático
   - Numeración de figuras con índice de ilustraciones
   - Formato de página A4 con márgenes reglamentarios
   - Fuente Arial 12pt, interlineado 1.5

Reglamento de Tesis MCD (DD 047-020):
- Artículo 24: Formato de página y tipografía
- Anexo 1: Formato de carátula

Uso:
    python generate_thesis.py [--figures-only] [--doc-only]

Opciones:
    --figures-only  Solo genera las figuras, no el documento
    --doc-only      Solo genera el documento (asume que las figuras existen)
"""

import os
import sys
import re
import argparse
from pathlib import Path
from datetime import datetime

# ============================================================================
# CONFIGURACION
# ============================================================================

# Directorio base del proyecto MIESC
BASE_DIR = Path(__file__).parent.parent.absolute()
THESIS_GEN_DIR = Path(__file__).parent.absolute()
DOCS_DIR = BASE_DIR / "docs" / "tesis"
FIGURES_DIR = THESIS_GEN_DIR / "figuras"
OUTPUT_DIR = THESIS_GEN_DIR / "output"

# Crear directorio de salida si no existe
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# Orden de los capitulos
CHAPTER_ORDER = [
    "SECCION_PRELIMINAR.md",
    "CAPITULO_INTRODUCCION.md",
    "CAPITULO_MARCO_TEORICO.md",
    "CAPITULO_ESTADO_DEL_ARTE.md",
    "CAPITULO_DESARROLLO.md",
    "CAPITULO_RESULTADOS.md",
    "CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md",
    "CAPITULO_JUSTIFICACION_MCP.md",
    "CAPITULO_TRABAJOS_FUTUROS.md",
    "GLOSARIO.md",
]

# Mapeo de figuras a capitulos
FIGURE_PLACEMENTS = {
    "CAPITULO_DESARROLLO.md": [
        ("fig_01_defense_in_depth.png", "Figura 4.1: Arquitectura Defense-in-Depth de 7 Capas de MIESC"),
        ("fig_02_adapter_pattern.png", "Figura 4.2: Patron Adapter para Integracion de Herramientas"),
        ("fig_03_normalization_flow.png", "Figura 4.3: Flujo de Normalizacion y Deduplicacion de Hallazgos"),
    ],
    "CAPITULO_RESULTADOS.md": [
        ("fig_05_severity_distribution.png", "Figura 5.1: Distribucion de Hallazgos por Severidad y Capa"),
        ("fig_07_comparison.png", "Figura 5.2: Comparativa de Rendimiento MIESC vs Herramientas Individuales"),
        ("fig_09_execution_timeline.png", "Figura 5.3: Timeline de Ejecucion Paralela por Capas"),
    ],
    "CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md": [
        ("fig_06_sovereign_ai.png", "Figura 6.1: Arquitectura de IA Soberana con Ollama"),
        ("fig_10_rag_architecture.png", "Figura 6.2: Arquitectura RAG para SmartLLM"),
    ],
    "CAPITULO_JUSTIFICACION_MCP.md": [
        ("fig_04_mcp_architecture.png", "Figura 7.1: Arquitectura del Servidor MCP"),
    ],
    "CAPITULO_MARCO_TEORICO.md": [
        ("fig_08_threat_taxonomy.png", "Figura 2.1: Taxonomia de Amenazas a Smart Contracts"),
    ],
}

# Colores profesionales para las figuras
COLORS = {
    'layer1': '#E3F2FD',
    'layer2': '#E8F5E9',
    'layer3': '#FFF3E0',
    'layer4': '#F3E5F5',
    'layer5': '#FCE4EC',
    'layer6': '#E0F7FA',
    'layer7': '#FFF8E1',
    'border': '#37474F',
    'text': '#212121',
    'arrow': '#455A64',
    'critical': '#D32F2F',
    'high': '#F57C00',
    'medium': '#FBC02D',
    'low': '#388E3C',
    'info': '#1976D2',
}


# ============================================================================
# GENERACION DE FIGURAS
# ============================================================================

def generate_figures():
    """Genera todas las figuras profesionales."""
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.patches import FancyBboxPatch
    import numpy as np
    import graphviz

    # Configurar matplotlib
    plt.rcParams['figure.dpi'] = 150
    plt.rcParams['savefig.dpi'] = 300
    plt.rcParams['font.family'] = 'sans-serif'
    plt.rcParams['font.sans-serif'] = ['Arial', 'Helvetica', 'DejaVu Sans']

    print("\n" + "=" * 60)
    print("GENERACION DE FIGURAS PROFESIONALES")
    print("=" * 60)

    figures_generated = []

    # Figura 1: Defense-in-Depth
    print("\n[1/10] Arquitectura Defense-in-Depth...")
    fig, ax = plt.subplots(figsize=(14, 10))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 10)
    ax.axis('off')

    layers = [
        ("Capa 7: Analisis con IA", "GPTScan, SmartLLM, ThreatModel, GasGauge, UpgradeGuard, BestPractices", COLORS['layer7'], 8.5),
        ("Capa 6: Property Testing", "PropertyGPT, Aderyn, Wake", COLORS['layer6'], 7.3),
        ("Capa 5: Verificacion Formal", "SMTChecker, Certora Prover", COLORS['layer5'], 6.1),
        ("Capa 4: Invariant Testing", "Scribble, Halmos", COLORS['layer4'], 4.9),
        ("Capa 3: Ejecucion Simbolica", "Mythril, Manticore, Oyente", COLORS['layer3'], 3.7),
        ("Capa 2: Fuzzing (Testing Dinamico)", "Echidna, Foundry Fuzz, Medusa, Vertigo", COLORS['layer2'], 2.5),
        ("Capa 1: Analisis Estatico", "Slither, Solhint, Securify2, Semgrep", COLORS['layer1'], 1.3),
    ]

    ax.text(7, 9.7, "MIESC: Arquitectura Defense-in-Depth de 7 Capas",
            fontsize=16, fontweight='bold', ha='center', color=COLORS['text'])
    ax.text(7, 9.3, "Framework Multi-capa para Auditoria de Smart Contracts",
            fontsize=11, ha='center', color='#666666', style='italic')

    for i, (title, tools, color, y) in enumerate(layers):
        rect = FancyBboxPatch((0.5, y), 13, 1.0,
                              boxstyle="round,pad=0.02,rounding_size=0.1",
                              facecolor=color, edgecolor=COLORS['border'], linewidth=2)
        ax.add_patch(rect)
        ax.text(1.0, y + 0.65, title, fontsize=11, fontweight='bold', va='center', color=COLORS['text'])
        ax.text(1.0, y + 0.25, f"Herramientas: {tools}", fontsize=9, va='center', color='#555555')
        ax.text(13.0, y + 0.5, f"{7-i}", fontsize=14, fontweight='bold', va='center', ha='center', color=COLORS['border'])

    ax.annotate('', xy=(7, 1.0), xytext=(7, 0.3), arrowprops=dict(arrowstyle='->', color=COLORS['arrow'], lw=2))
    ax.text(7, 0.1, "Contrato Solidity (.sol)", fontsize=10, ha='center', color=COLORS['text'], fontweight='bold')
    ax.text(0.5, 0.1, "MIESC v4.0.0 - Fernando Boiero - Tesis Maestria Ciberdefensa UNDEF", fontsize=8, color='#888888')

    plt.tight_layout()
    filepath = FIGURES_DIR / "fig_01_defense_in_depth.png"
    plt.savefig(filepath, bbox_inches='tight', facecolor='white', edgecolor='none')
    plt.close()
    figures_generated.append(filepath)
    print(f"  + {filepath.name}")

    # Figura 2: Adapter Pattern
    print("[2/10] Patron Adapter...")
    dot = graphviz.Digraph(comment='Adapter Pattern', format='png')
    dot.attr(rankdir='TB', dpi='300', bgcolor='white')
    dot.attr('node', fontname='Arial', fontsize='11')

    with dot.subgraph(name='cluster_protocol') as c:
        c.attr(label='Protocolo Base', style='rounded', color='#1565C0')
        c.node('ToolProtocol', 'ToolProtocol\n(Interface)\n\nanalyze()\nis_available()\nget_metadata()',
               shape='box', style='filled,rounded', fillcolor='#E3F2FD')

    with dot.subgraph(name='cluster_adapters') as c:
        c.attr(label='Adaptadores Concretos (25 herramientas)', style='rounded', color='#2E7D32')
        for name, label, color in [('SlitherAdapter', 'SlitherAdapter\n(Capa 1)', '#E8F5E9'),
                                    ('MythrilAdapter', 'MythrilAdapter\n(Capa 3)', '#FFF3E0'),
                                    ('EchidnaAdapter', 'EchidnaAdapter\n(Capa 2)', '#E8F5E9'),
                                    ('GPTScanAdapter', 'GPTScanAdapter\n(Capa 7)', '#FFF8E1')]:
            c.node(name, label, shape='box', style='filled,rounded', fillcolor=color)

    with dot.subgraph(name='cluster_tools') as c:
        c.attr(label='Herramientas Externas (CLI/API)', style='rounded,dashed', color='#666666')
        for tool in ['slither', 'myth', 'echidna', 'ollama']:
            c.node(tool, tool, shape='cylinder', style='filled', fillcolor='#F5F5F5')

    for adapter in ['SlitherAdapter', 'MythrilAdapter', 'EchidnaAdapter', 'GPTScanAdapter']:
        dot.edge(adapter, 'ToolProtocol', style='dashed', arrowhead='onormal', label='implements')

    dot.edge('SlitherAdapter', 'slither', label='subprocess')
    dot.edge('MythrilAdapter', 'myth', label='subprocess')
    dot.edge('EchidnaAdapter', 'echidna', label='subprocess')
    dot.edge('GPTScanAdapter', 'ollama', label='HTTP API')

    filepath = FIGURES_DIR / "fig_02_adapter_pattern"
    dot.render(filepath, cleanup=True)
    figures_generated.append(Path(str(filepath) + '.png'))
    print(f"  + fig_02_adapter_pattern.png")

    # Figura 3: Normalization Flow
    print("[3/10] Flujo de Normalizacion...")
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 8)
    ax.axis('off')

    ax.text(7, 7.7, "Flujo de Normalizacion de Hallazgos", fontsize=14, fontweight='bold', ha='center')

    boxes = [
        ((0.5, 5.5), 3, 1.5, '#E3F2FD', "Hallazgos Brutos", "47 findings\n(heterogeneos)"),
        ((4.5, 5.5), 2.5, 1.5, '#FFF3E0', "Parser", "JSON/Text\nExtraction"),
        ((8, 5.5), 2.5, 1.5, '#E8F5E9', "Taxonomy Mapper", "SWC -> CWE\n-> OWASP"),
        ((11.5, 5.5), 2, 1.5, '#F3E5F5', "Normalizado", "Formato\nunificado"),
    ]

    for (x, y), w, h, color, title, subtitle in boxes:
        rect = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02",
                              facecolor=color, edgecolor=COLORS['border'], linewidth=2)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h*0.7, title, fontsize=10, fontweight='bold', ha='center')
        ax.text(x + w/2, y + h*0.3, subtitle, fontsize=9, ha='center', color='#666')

    # Flechas horizontales
    for x in [3.7, 7.2, 10.7]:
        ax.annotate('', xy=(x+0.6, 6.25), xytext=(x, 6.25),
                   arrowprops=dict(arrowstyle='->', color=COLORS['arrow'], lw=2))

    # Deduplicacion
    ax.annotate('', xy=(9.25, 4.8), xytext=(9.25, 5.3),
               arrowprops=dict(arrowstyle='->', color=COLORS['arrow'], lw=2))

    rect = FancyBboxPatch((7, 3.3), 4.5, 1.3, boxstyle="round,pad=0.02",
                          facecolor='#FCE4EC', edgecolor=COLORS['border'], linewidth=2)
    ax.add_patch(rect)
    ax.text(9.25, 4.2, "Algoritmo de Deduplicacion", fontsize=10, fontweight='bold', ha='center')
    ax.text(9.25, 3.7, "Hash(ubicacion) + Similitud semantica + Clustering", fontsize=9, ha='center', color='#666')

    ax.annotate('', xy=(9.25, 2.5), xytext=(9.25, 3.1),
               arrowprops=dict(arrowstyle='->', color=COLORS['arrow'], lw=2))

    rect = FancyBboxPatch((7.5, 1.3), 3.5, 1.0, boxstyle="round,pad=0.02",
                          facecolor='#E0F7FA', edgecolor=COLORS['border'], linewidth=2)
    ax.add_patch(rect)
    ax.text(9.25, 2.0, "16 Hallazgos Unicos", fontsize=11, fontweight='bold', ha='center')
    ax.text(9.25, 1.55, "66% reduccion", fontsize=9, ha='center', color='#388E3C', fontweight='bold')

    plt.tight_layout()
    filepath = FIGURES_DIR / "fig_03_normalization_flow.png"
    plt.savefig(filepath, bbox_inches='tight', facecolor='white')
    plt.close()
    figures_generated.append(filepath)
    print(f"  + {filepath.name}")

    # Figura 4: MCP Architecture
    print("[4/10] Arquitectura MCP...")
    dot = graphviz.Digraph(comment='MCP Architecture', format='png')
    dot.attr(rankdir='LR', dpi='300', bgcolor='white', splines='ortho')
    dot.attr('node', fontname='Arial', fontsize='11')

    dot.node('user', 'Usuario', shape='ellipse', style='filled', fillcolor='#E3F2FD')

    with dot.subgraph(name='cluster_claude') as c:
        c.attr(label='Claude Desktop / API', style='rounded', color='#6B5B95')
        c.node('claude', 'Claude\nAssistant', shape='box', style='filled,rounded', fillcolor='#EDE7F6')

    with dot.subgraph(name='cluster_mcp') as c:
        c.attr(label='MIESC MCP Server', style='rounded', color='#2E7D32')
        c.node('mcp_tools', 'Tools\n\nanalyze_contract\nget_vulnerabilities\nsuggest_fixes',
               shape='box', style='filled,rounded', fillcolor='#E8F5E9')
        c.node('mcp_resources', 'Resources\n\ncontract://\nfindings://\nreports://',
               shape='box', style='filled,rounded', fillcolor='#E8F5E9')

    with dot.subgraph(name='cluster_miesc') as c:
        c.attr(label='MIESC Core', style='rounded', color='#1565C0')
        c.node('orchestrator', 'Orchestrator\n(7 capas)', shape='box', style='filled,rounded', fillcolor='#E3F2FD')
        c.node('ollama', 'Ollama\n(LLM Local)', shape='cylinder', style='filled', fillcolor='#FFF8E1')

    dot.edge('user', 'claude', label='Prompt')
    dot.edge('claude', 'mcp_tools', label='JSON-RPC 2.0', style='bold', color='#2E7D32')
    dot.edge('claude', 'mcp_resources', label='Recursos', style='dashed')
    dot.edge('mcp_tools', 'orchestrator', label='invoke')
    dot.edge('orchestrator', 'ollama', label='analisis IA')

    filepath = FIGURES_DIR / "fig_04_mcp_architecture"
    dot.render(filepath, cleanup=True)
    figures_generated.append(Path(str(filepath) + '.png'))
    print(f"  + fig_04_mcp_architecture.png")

    # Figura 5: Severity Distribution
    print("[5/10] Distribucion de Severidades...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    severities = ['Critical', 'High', 'Medium', 'Low']
    values = [2, 5, 6, 3]
    colors_pie = [COLORS['critical'], COLORS['high'], COLORS['medium'], COLORS['low']]
    ax1.pie(values, explode=(0.1, 0.05, 0, 0), labels=severities, colors=colors_pie,
            autopct='%1.1f%%', shadow=True, startangle=90, textprops={'fontsize': 11})
    ax1.set_title('Distribucion por Severidad\n(16 hallazgos unicos)', fontsize=12, fontweight='bold')

    layers_names = ['Capa 1\nEstatico', 'Capa 2\nFuzzing', 'Capa 3\nSimbolico',
                    'Capa 4\nInvariants', 'Capa 5\nFormal', 'Capa 6\nProperty', 'Capa 7\nIA']
    unique = [8, 2, 3, 1, 1, 0, 1]
    raw = [12, 5, 8, 3, 6, 4, 9]

    x = np.arange(len(layers_names))
    width = 0.35
    bars1 = ax2.bar(x - width/2, raw, width, label='Hallazgos Brutos', color='#90CAF9')
    bars2 = ax2.bar(x + width/2, unique, width, label='Unicos (contribucion)', color='#2196F3')

    ax2.set_ylabel('Numero de Hallazgos', fontsize=11)
    ax2.set_title('Contribucion por Capa', fontsize=12, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(layers_names, fontsize=9)
    ax2.legend(loc='upper right')
    ax2.grid(axis='y', alpha=0.3)

    for bar in bars2:
        height = bar.get_height()
        ax2.annotate(f'{height}', xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.tight_layout()
    filepath = FIGURES_DIR / "fig_05_severity_distribution.png"
    plt.savefig(filepath, bbox_inches='tight', facecolor='white')
    plt.close()
    figures_generated.append(filepath)
    print(f"  + {filepath.name}")

    # Figura 6: Sovereign AI
    print("[6/10] IA Soberana...")
    dot = graphviz.Digraph(comment='Sovereign AI', format='png')
    dot.attr(rankdir='TB', dpi='300', bgcolor='white')
    dot.attr('node', fontname='Arial', fontsize='11')

    dot.node('contract', 'Contrato\nSolidity', shape='note', style='filled', fillcolor='#E3F2FD')

    with dot.subgraph(name='cluster_local') as c:
        c.attr(label='Procesamiento 100% Local', style='rounded,bold',
               color='#2E7D32', bgcolor='#F1F8E9')
        c.node('adapter', 'LLM Adapter', shape='box', style='filled,rounded', fillcolor='#C8E6C9')
        c.node('prompt', 'Prompt\nEngineering', shape='box', style='filled,rounded', fillcolor='#C8E6C9')
        c.node('ollama', 'Ollama Server\n\nLlama 3.2 (8B)\nCodeLlama (7B)\nMistral (7B)',
               shape='box', style='filled,rounded', fillcolor='#FFF8E1')
        c.node('parser', 'Response\nParser', shape='box', style='filled,rounded', fillcolor='#C8E6C9')

    dot.node('findings', 'Hallazgos\nIA', shape='folder', style='filled', fillcolor='#E3F2FD')
    dot.node('cloud', 'APIs Externas\n(OpenAI, Claude)\nNO UTILIZADO',
             shape='cloud', style='filled,dashed', fillcolor='#FFCDD2', fontcolor='#C62828')

    dot.edge('contract', 'adapter', label='codigo')
    dot.edge('adapter', 'prompt', label='contexto')
    dot.edge('prompt', 'ollama', label='HTTP localhost')
    dot.edge('ollama', 'parser', label='respuesta')
    dot.edge('parser', 'findings', label='estructurado')
    dot.edge('adapter', 'cloud', style='invis')

    filepath = FIGURES_DIR / "fig_06_sovereign_ai"
    dot.render(filepath, cleanup=True)
    figures_generated.append(Path(str(filepath) + '.png'))
    print(f"  + fig_06_sovereign_ai.png")

    # Figura 7: Comparison Chart
    print("[7/10] Comparativa de Rendimiento...")
    fig, ax = plt.subplots(figsize=(10, 6))

    tools = ['MIESC\n(7 capas)', 'Slither', 'Mythril', 'Echidna']
    precision = [0.875, 0.77, 0.89, 1.00]
    recall = [1.00, 0.71, 0.57, 0.36]
    f1 = [0.93, 0.74, 0.70, 0.53]

    x = np.arange(len(tools))
    width = 0.25

    bars1 = ax.bar(x - width, precision, width, label='Precision', color='#42A5F5')
    bars2 = ax.bar(x, recall, width, label='Recall', color='#66BB6A')
    bars3 = ax.bar(x + width, f1, width, label='F1-Score', color='#FFA726')

    ax.set_ylabel('Puntuacion (0-1)', fontsize=11)
    ax.set_xlabel('Herramienta', fontsize=11)
    ax.set_title('Comparativa de Rendimiento: MIESC vs Herramientas Individuales', fontsize=12, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(tools, fontsize=10)
    ax.legend(loc='upper right')
    ax.set_ylim(0, 1.15)
    ax.grid(axis='y', alpha=0.3)

    ax.axvspan(-0.5, 0.5, alpha=0.1, color='green')
    ax.text(0, 1.08, '+40.8% recall', ha='center', fontsize=10, fontweight='bold', color='#2E7D32')

    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.2f}', xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    filepath = FIGURES_DIR / "fig_07_comparison.png"
    plt.savefig(filepath, bbox_inches='tight', facecolor='white')
    plt.close()
    figures_generated.append(filepath)
    print(f"  + {filepath.name}")

    # Figura 8: Threat Taxonomy
    print("[8/10] Taxonomia de Amenazas...")
    dot = graphviz.Digraph(comment='Threat Taxonomy', format='png')
    dot.attr(rankdir='TB', dpi='300', bgcolor='white')
    dot.attr('node', fontname='Arial', fontsize='10')

    dot.node('root', 'Amenazas a\nSmart Contracts', shape='box',
             style='filled,bold', fillcolor='#37474F', fontcolor='white')

    with dot.subgraph(name='cluster_external') as c:
        c.attr(label='Amenazas Externas', style='rounded', color='#D32F2F')
        c.node('apt', 'Actores Estatales\n(APT)', shape='box', style='filled', fillcolor='#FFCDD2')
        c.node('crime', 'Crimen\nOrganizado', shape='box', style='filled', fillcolor='#FFCDD2')
        c.node('hacktivism', 'Hacktivistas', shape='box', style='filled', fillcolor='#FFCDD2')

    with dot.subgraph(name='cluster_internal') as c:
        c.attr(label='Amenazas Internas', style='rounded', color='#F57C00')
        c.node('maldev', 'Desarrollador\nMalicioso', shape='box', style='filled', fillcolor='#FFE0B2')
        c.node('errors', 'Errores de\nDesarrollo', shape='box', style='filled', fillcolor='#FFE0B2')
        c.node('config', 'Configuracion\nErronea', shape='box', style='filled', fillcolor='#FFE0B2')

    for node in ['apt', 'crime', 'hacktivism', 'maldev', 'errors', 'config']:
        dot.edge('root', node)

    for node, label in [('espionage', 'Espionaje economico'), ('sabotage', 'Sabotaje'),
                        ('theft', 'Robo de fondos'), ('rugpull', 'Rug pulls'),
                        ('vulns', 'Vulnerabilidades'), ('perms', 'Permisos excesivos')]:
        dot.node(node, label, shape='ellipse', fontsize='9')

    dot.edge('apt', 'espionage', style='dashed')
    dot.edge('apt', 'sabotage', style='dashed')
    dot.edge('crime', 'theft', style='dashed')
    dot.edge('maldev', 'rugpull', style='dashed')
    dot.edge('errors', 'vulns', style='dashed')
    dot.edge('config', 'perms', style='dashed')

    filepath = FIGURES_DIR / "fig_08_threat_taxonomy"
    dot.render(filepath, cleanup=True)
    figures_generated.append(Path(str(filepath) + '.png'))
    print(f"  + fig_08_threat_taxonomy.png")

    # Figura 9: Execution Timeline
    print("[9/10] Timeline de Ejecucion...")
    fig, ax = plt.subplots(figsize=(12, 6))

    tools_data = [
        ('Slither', 1, 0, 3.2, COLORS['layer1']),
        ('Solhint', 1, 0, 1.5, COLORS['layer1']),
        ('Securify2', 1, 0, 2.8, COLORS['layer1']),
        ('Echidna', 2, 3.5, 18.7, COLORS['layer2']),
        ('Foundry', 2, 3.5, 12.0, COLORS['layer2']),
        ('Medusa', 2, 3.5, 15.2, COLORS['layer2']),
        ('Mythril', 3, 22, 52.4, COLORS['layer3']),
        ('Manticore', 3, 22, 45.0, COLORS['layer3']),
        ('SMTChecker', 5, 52, 9.8, COLORS['layer5']),
        ('Certora', 5, 52, 8.5, COLORS['layer5']),
        ('GPTScan', 7, 62, 15.0, COLORS['layer7']),
        ('SmartLLM', 7, 62, 12.0, COLORS['layer7']),
    ]

    for i, (name, layer, start, duration, color) in enumerate(tools_data):
        ax.barh(i, duration, left=start, height=0.6, color=color,
                edgecolor=COLORS['border'], linewidth=1)
        ax.text(start + duration/2, i, name, ha='center', va='center', fontsize=9, fontweight='bold')

    ax.set_xlabel('Tiempo (segundos)', fontsize=11)
    ax.set_ylabel('Herramientas', fontsize=11)
    ax.set_title('Ejecucion Paralela de Herramientas por Capa', fontsize=12, fontweight='bold')
    ax.set_yticks(range(len(tools_data)))
    ax.set_yticklabels(['' for _ in tools_data])
    ax.grid(axis='x', alpha=0.3)

    legend_elements = [
        mpatches.Patch(facecolor=COLORS['layer1'], label='Capa 1: Estatico'),
        mpatches.Patch(facecolor=COLORS['layer2'], label='Capa 2: Fuzzing'),
        mpatches.Patch(facecolor=COLORS['layer3'], label='Capa 3: Simbolico'),
        mpatches.Patch(facecolor=COLORS['layer5'], label='Capa 5: Formal'),
        mpatches.Patch(facecolor=COLORS['layer7'], label='Capa 7: IA'),
    ]
    ax.legend(handles=legend_elements, loc='lower right', fontsize=9)

    ax.axvline(x=77, color='#D32F2F', linestyle='--', linewidth=2)
    ax.text(78, len(tools_data)-1, 'Total: 77s\n(paralelo)', fontsize=9,
            color='#D32F2F', fontweight='bold')

    plt.tight_layout()
    filepath = FIGURES_DIR / "fig_09_execution_timeline.png"
    plt.savefig(filepath, bbox_inches='tight', facecolor='white')
    plt.close()
    figures_generated.append(filepath)
    print(f"  + {filepath.name}")

    # Figura 10: RAG Architecture
    print("[10/10] Arquitectura RAG...")
    dot = graphviz.Digraph(comment='RAG Architecture', format='png')
    dot.attr(rankdir='LR', dpi='300', bgcolor='white')
    dot.attr('node', fontname='Arial', fontsize='10')

    dot.node('contract', 'Contrato\nSolidity', shape='note', style='filled', fillcolor='#E3F2FD')
    dot.node('embed', 'Generacion de\nEmbeddings', shape='box', style='filled,rounded', fillcolor='#FFF3E0')
    dot.node('vectordb', 'Vector Database\n\nSWC Knowledge Base\n37 categorias\nEjemplos de codigo',
             shape='cylinder', style='filled', fillcolor='#E8F5E9')
    dot.node('retrieval', 'Busqueda\nSemantica', shape='box', style='filled,rounded', fillcolor='#F3E5F5')
    dot.node('context', 'Contexto\nRelevante', shape='parallelogram', style='filled', fillcolor='#FCE4EC')
    dot.node('llm', 'Ollama LLM\n\nLlama 3.2', shape='box', style='filled,rounded,bold', fillcolor='#FFF8E1')
    dot.node('output', 'Analisis\nEstructurado', shape='note', style='filled', fillcolor='#E0F7FA')

    dot.edge('contract', 'embed', label='codigo')
    dot.edge('embed', 'vectordb', label='vectores')
    dot.edge('vectordb', 'retrieval', label='indice')
    dot.edge('retrieval', 'context', label='top-k')
    dot.edge('contract', 'llm', label='prompt')
    dot.edge('context', 'llm', label='RAG')
    dot.edge('llm', 'output', label='respuesta')

    filepath = FIGURES_DIR / "fig_10_rag_architecture"
    dot.render(filepath, cleanup=True)
    figures_generated.append(Path(str(filepath) + '.png'))
    print(f"  + fig_10_rag_architecture.png")

    print(f"\n+ {len(figures_generated)} figuras generadas en: {FIGURES_DIR}")
    return figures_generated


# ============================================================================
# GENERACION DE DOCUMENTO ODT - FORMATO REGLAMENTO TESIS MCD (DD 047-020)
# ============================================================================

def generate_odt_document():
    """
    Genera el documento ODT con formato según Reglamento de Tesis MCD.

    Artículo 24 - Formato:
    - Hoja A4 (21cm x 29.7cm), orientación vertical
    - Márgenes: Izquierdo 3cm, Superior 2cm, Derecho 2cm, Inferior 2cm
    - Tipografía: Arial, Calibri o similar, tamaño 12
    - Interlineado: 1.5
    - Numeración: Arábiga, centrada al pie, desde página 2

    Anexo 1 - Carátula:
    - Logos IUA y UNDEF
    - MAESTRÍA EN CIBERDEFENSA (Tamaño 20)
    - TESIS DE POSGRADO (Tamaño 18)
    - Título (Tamaño 16)
    - Subtítulo (Tamaño 14)
    - Autor (Tamaño 14)
    - Director (Tamaño 13)
    - Lugar y fecha (Tamaño 12)
    """
    from odf.opendocument import OpenDocumentText
    from odf.style import Style, TextProperties, ParagraphProperties, PageLayout, PageLayoutProperties, MasterPage, HeaderStyle, FooterStyle
    from odf.text import P, H, Span
    from odf.draw import Frame, Image
    from odf.table import Table, TableColumn, TableRow, TableCell
    from odf import teletype

    print("\n" + "=" * 60)
    print("GENERACION DE DOCUMENTO ODT")
    print("Formato: Reglamento de Tesis MCD (DD 047-020)")
    print("=" * 60)

    # Verificar figuras
    print("\n[1/6] Verificando figuras...")
    figures_found = list(FIGURES_DIR.glob("*.png"))
    print(f"  Figuras encontradas: {len(figures_found)}")
    if len(figures_found) < 10:
        print("  ! Faltan figuras. Ejecute primero: python generate_thesis.py --figures-only")

    # Crear documento
    print("\n[2/6] Creando documento ODT con formato reglamentario...")
    doc = OpenDocumentText()

    # =========================================================================
    # CONFIGURACION DE PAGINA (Art. 24)
    # =========================================================================
    # A4: 21cm x 29.7cm, Márgenes: Izq 3cm, Sup 2cm, Der 2cm, Inf 2cm
    page_layout = PageLayout(name="PageLayout")
    page_layout.addElement(PageLayoutProperties(
        pagewidth="21cm",
        pageheight="29.7cm",
        printorientation="portrait",
        marginleft="3cm",
        margintop="2cm",
        marginright="2cm",
        marginbottom="2cm"
    ))
    doc.automaticstyles.addElement(page_layout)

    # Master page para numeración
    master_page = MasterPage(name="Standard", pagelayoutname="PageLayout")
    doc.masterstyles.addElement(master_page)

    # =========================================================================
    # ESTILOS DE PARRAFO CON JERARQUIA PARA INDICE AUTOMATICO
    # =========================================================================
    # Según Art. 24: Arial/Calibri tamaño 12, interlineado 1.5

    paragraph_styles = [
        # (nombre, tamaño, negrita, cursiva, alineación, margen_sup, margen_inf, salto_pagina, outline_level)
        ("Normal", "12pt", False, False, "justify", "0cm", "0.35cm", None, None),

        # Estilos de carátula según Anexo 1
        ("CoverMaestria", "20pt", True, False, "center", "0cm", "0.5cm", None, None),
        ("CoverTesis", "18pt", True, False, "center", "0cm", "0.5cm", None, None),
        ("CoverTitle", "16pt", True, False, "center", "0cm", "0.5cm", None, None),
        ("CoverSubtitle", "14pt", False, True, "center", "0cm", "0.5cm", None, None),
        ("CoverAuthor", "14pt", False, False, "center", "0cm", "0.3cm", None, None),
        ("CoverDirector", "13pt", False, False, "center", "0cm", "0.3cm", None, None),
        ("CoverPlace", "12pt", False, False, "center", "0cm", "0.3cm", None, None),

        # Encabezados con outline level para índice automático (TOC)
        # Heading 1: Capítulos principales - outline level 1
        ("Heading1", "16pt", True, False, "left", "1.5cm", "0.8cm", "page", 1),
        # Heading 2: Secciones - outline level 2
        ("Heading2", "14pt", True, False, "left", "1cm", "0.5cm", None, 2),
        # Heading 3: Subsecciones - outline level 3
        ("Heading3", "12pt", True, False, "left", "0.8cm", "0.4cm", None, 3),
        # Heading 4: Sub-subsecciones - outline level 4
        ("Heading4", "12pt", True, True, "left", "0.5cm", "0.3cm", None, 4),

        # Otros estilos
        ("Code", "10pt", False, False, "left", "0.3cm", "0.3cm", None, None),
        ("Quote", "11pt", False, True, "justify", "0.5cm", "0.5cm", None, None),
        ("ListParagraph", "12pt", False, False, "justify", "0cm", "0.2cm", None, None),

        # Estilo para pie de figura (índice de ilustraciones)
        ("FigureCaption", "10pt", False, True, "center", "0.3cm", "0.8cm", None, None),

        # Estilo para título de tabla
        ("TableTitle", "10pt", True, False, "center", "0.8cm", "0.3cm", None, None),

        ("Center", "12pt", False, False, "center", "0cm", "0.3cm", None, None),
        ("TOCInstruction", "11pt", False, True, "center", "1cm", "1cm", None, None),
    ]

    for name, fontsize, bold, italic, align, margin_top, margin_bottom, break_before, outline_level in paragraph_styles:
        style = Style(name=name, family="paragraph")

        # Propiedades de texto - Arial según reglamento
        text_props = {
            "fontname": "Courier New" if name == "Code" else "Arial",
            "fontsize": fontsize
        }
        if bold:
            text_props["fontweight"] = "bold"
        if italic:
            text_props["fontstyle"] = "italic"
        style.addElement(TextProperties(**text_props))

        # Propiedades de párrafo
        # Interlineado 1.5 = 18pt para fuente 12pt (12 * 1.5 = 18)
        para_props = {}
        if align:
            para_props["textalign"] = align
        if margin_top:
            para_props["margintop"] = margin_top
        if margin_bottom:
            para_props["marginbottom"] = margin_bottom
        if break_before:
            para_props["breakbefore"] = break_before
        style.addElement(ParagraphProperties(**para_props))

        # Agregar al documento
        if outline_level:
            # Los estilos con outline level van a styles (no automaticstyles) para TOC
            style.setAttribute("defaultoutlinelevel", str(outline_level))
        doc.styles.addElement(style)

    # =========================================================================
    # ESTILOS DE TEXTO
    # =========================================================================
    bold_style = Style(name="Bold", family="text")
    bold_style.addElement(TextProperties(fontweight="bold", fontname="Arial"))
    doc.styles.addElement(bold_style)

    italic_style = Style(name="Italic", family="text")
    italic_style.addElement(TextProperties(fontstyle="italic", fontname="Arial"))
    doc.styles.addElement(italic_style)

    code_style = Style(name="CodeInline", family="text")
    code_style.addElement(TextProperties(fontname="Courier New", fontsize="10pt"))
    doc.styles.addElement(code_style)

    # Contador global de figuras (para numeración secuencial)
    figure_counter = [0]  # Usar lista para permitir modificación en closure

    # =========================================================================
    # CARATULA SEGUN ANEXO 1 DEL REGLAMENTO
    # =========================================================================
    print("[3/6] Generando caratula segun Anexo 1...")

    # Logos IUA y UNDEF
    logo_path = DOCS_DIR / "logo_iua.png"
    if logo_path.exists():
        doc.text.addElement(P(stylename="Normal", text=""))
        href = doc.addPicture(str(logo_path))
        frame = Frame(width="12cm", height="4cm", anchortype="paragraph")
        frame.addElement(Image(href=href))
        p_logo = P(stylename="Center")
        p_logo.addElement(frame)
        doc.text.addElement(p_logo)
        print("    + Logo IUA/UNDEF agregado")
    else:
        # Espaciado si no hay logo
        for _ in range(2):
            doc.text.addElement(P(stylename="Normal", text=""))
        p = P(stylename="Center")
        teletype.addTextToElement(p, "[Logos IUA y UNDEF - Insertar manualmente]")
        doc.text.addElement(p)

    for _ in range(2):
        doc.text.addElement(P(stylename="Normal", text=""))

    # MAESTRÍA EN CIBERDEFENSA (Tamaño 20)
    p = P(stylename="CoverMaestria")
    teletype.addTextToElement(p, "MAESTRIA EN CIBERDEFENSA")
    doc.text.addElement(p)

    for _ in range(2):
        doc.text.addElement(P(stylename="Normal", text=""))

    # TESIS DE POSGRADO (Tamaño 18)
    p = P(stylename="CoverTesis")
    teletype.addTextToElement(p, "TESIS DE POSGRADO")
    doc.text.addElement(p)

    for _ in range(3):
        doc.text.addElement(P(stylename="Normal", text=""))

    # Título (Tamaño 16)
    p = P(stylename="CoverTitle")
    teletype.addTextToElement(p, "MIESC: MARCO INTEGRADO PARA EVALUACION")
    doc.text.addElement(p)
    p = P(stylename="CoverTitle")
    teletype.addTextToElement(p, "DE SEGURIDAD EN CONTRATOS INTELIGENTES")
    doc.text.addElement(p)

    doc.text.addElement(P(stylename="Normal", text=""))

    # Subtítulo (Tamaño 14, cursiva)
    p = P(stylename="CoverSubtitle")
    teletype.addTextToElement(p, "Framework Multi-capa de 7 Capas con 25 Herramientas de Analisis,")
    doc.text.addElement(p)
    p = P(stylename="CoverSubtitle")
    teletype.addTextToElement(p, "IA Soberana y Model Context Protocol")
    doc.text.addElement(p)

    for _ in range(4):
        doc.text.addElement(P(stylename="Normal", text=""))

    # Autor (Tamaño 14)
    p = P(stylename="CoverAuthor")
    teletype.addTextToElement(p, "Autor: Ing. Fernando Boiero")
    doc.text.addElement(p)

    for _ in range(2):
        doc.text.addElement(P(stylename="Normal", text=""))

    # Director (Tamaño 13)
    p = P(stylename="CoverDirector")
    teletype.addTextToElement(p, "Director de Tesis: Mg. Eduardo Casanovas")
    doc.text.addElement(p)

    for _ in range(4):
        doc.text.addElement(P(stylename="Normal", text=""))

    # Lugar y fecha (Tamaño 12)
    p = P(stylename="CoverPlace")
    teletype.addTextToElement(p, "Cordoba, Provincia de Cordoba, Diciembre 2025")
    doc.text.addElement(p)

    # =========================================================================
    # INDICE DE CONTENIDOS (Compatible con Google Docs)
    # =========================================================================
    print("[4/6] Agregando seccion de indices...")

    # Página de índice
    h = H(outlinelevel=1, stylename="Heading1")
    teletype.addTextToElement(h, "INDICE")
    doc.text.addElement(h)

    p = P(stylename="TOCInstruction")
    teletype.addTextToElement(p, "Google Docs: Insertar > Indice")
    doc.text.addElement(p)
    p = P(stylename="TOCInstruction")
    teletype.addTextToElement(p, "LibreOffice: Insertar > Indices y Tablas > Indice General")
    doc.text.addElement(p)

    doc.text.addElement(P(stylename="Normal", text=""))

    # Índice de ilustraciones - Generado estáticamente para compatibilidad con Google Docs
    h = H(outlinelevel=1, stylename="Heading1")
    teletype.addTextToElement(h, "INDICE DE ILUSTRACIONES")
    doc.text.addElement(h)

    # Lista de figuras predefinida (se actualizará con números de página manualmente)
    figure_index_entries = [
        ("Figura 1", "Taxonomia de Amenazas a Smart Contracts"),
        ("Figura 2", "Arquitectura Defense-in-Depth de 7 Capas de MIESC"),
        ("Figura 3", "Patron Adapter para Integracion de Herramientas"),
        ("Figura 4", "Flujo de Normalizacion y Deduplicacion de Hallazgos"),
        ("Figura 5", "Distribucion de Hallazgos por Severidad y Capa"),
        ("Figura 6", "Comparativa de Rendimiento MIESC vs Herramientas Individuales"),
        ("Figura 7", "Timeline de Ejecucion Paralela por Capas"),
        ("Figura 8", "Arquitectura de IA Soberana con Ollama"),
        ("Figura 9", "Arquitectura RAG para SmartLLM"),
        ("Figura 10", "Arquitectura del Servidor MCP"),
    ]

    for fig_num, fig_title in figure_index_entries:
        p = P(stylename="Normal")
        teletype.addTextToElement(p, f"{fig_num}: {fig_title}")
        doc.text.addElement(p)

    doc.text.addElement(P(stylename="Normal", text=""))

    # =========================================================================
    # PROCESAR CAPITULOS
    # =========================================================================
    print("[5/6] Procesando capitulos...")

    def process_inline_text(text):
        """Procesa formato inline de Markdown."""
        text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)  # Links
        text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)  # Negrita
        text = re.sub(r'\*([^*]+)\*', r'\1', text)  # Cursiva
        text = re.sub(r'`([^`]+)`', r'\1', text)  # Código inline
        return text

    def add_figure_with_caption(doc, figure_name, caption_text, figure_counter):
        """
        Agrega una figura con pie de figura numerado.
        Según Art. 24: Los gráficos llevarán su título debajo.
        Compatible con Google Docs y LibreOffice.
        """
        figure_path = FIGURES_DIR / figure_name
        if not figure_path.exists():
            print(f"    ! Figura no encontrada: {figure_name}")
            return doc

        # Incrementar contador
        figure_counter[0] += 1
        fig_num = figure_counter[0]

        # Espacio antes de la figura
        doc.text.addElement(P(stylename="Normal", text=""))

        # Agregar imagen
        href = doc.addPicture(str(figure_path))
        frame = Frame(width="15cm", height="10cm", anchortype="paragraph")
        frame.addElement(Image(href=href))
        p_img = P(stylename="Center")
        p_img.addElement(frame)
        doc.text.addElement(p_img)

        # Pie de figura con numeración simple (compatible con Google Docs)
        # Formato: "Figura N: Descripción"
        p_caption = P(stylename="FigureCaption")
        teletype.addTextToElement(p_caption, f"Figura {fig_num}: {caption_text}")
        doc.text.addElement(p_caption)

        print(f"    + Figura {fig_num} agregada: {figure_name}")
        return doc

    # Mapeo de figuras actualizado sin prefijo "Figura X.X:"
    FIGURE_CAPTIONS = {
        "fig_01_defense_in_depth.png": "Arquitectura Defense-in-Depth de 7 Capas de MIESC",
        "fig_02_adapter_pattern.png": "Patron Adapter para Integracion de Herramientas",
        "fig_03_normalization_flow.png": "Flujo de Normalizacion y Deduplicacion de Hallazgos",
        "fig_04_mcp_architecture.png": "Arquitectura del Servidor MCP",
        "fig_05_severity_distribution.png": "Distribucion de Hallazgos por Severidad y Capa",
        "fig_06_sovereign_ai.png": "Arquitectura de IA Soberana con Ollama",
        "fig_07_comparison.png": "Comparativa de Rendimiento MIESC vs Herramientas Individuales",
        "fig_08_threat_taxonomy.png": "Taxonomia de Amenazas a Smart Contracts",
        "fig_09_execution_timeline.png": "Timeline de Ejecucion Paralela por Capas",
        "fig_10_rag_architecture.png": "Arquitectura RAG para SmartLLM",
    }

    for chapter_file in CHAPTER_ORDER:
        filepath = DOCS_DIR / chapter_file
        if not filepath.exists():
            print(f"  ! No encontrado: {chapter_file}")
            continue

        print(f"  - Procesando: {chapter_file}")
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        lines = content.split('\n')
        chapter_figures = list(FIGURE_PLACEMENTS.get(chapter_file, []))
        in_code_block = False
        code_content = []
        in_table = False
        table_rows = []

        for line in lines:
            # Bloques de codigo
            if line.strip().startswith('```'):
                if not in_code_block:
                    in_code_block = True
                    code_content = []
                else:
                    in_code_block = False
                    if code_content:
                        p = P(stylename="Code")
                        teletype.addTextToElement(p, '\n'.join(code_content))
                        doc.text.addElement(p)
                    code_content = []
                continue

            if in_code_block:
                code_content.append(line)
                continue

            # Tablas
            if '|' in line and line.strip().startswith('|'):
                if not in_table:
                    in_table = True
                    table_rows = []
                if re.match(r'^[\|\-\s:]+$', line.strip()):
                    continue
                cells = [cell.strip() for cell in line.split('|')[1:-1]]
                if cells:
                    table_rows.append(cells)
                continue
            elif in_table:
                in_table = False
                if table_rows:
                    table = Table()
                    num_cols = len(table_rows[0])
                    for _ in range(num_cols):
                        table.addElement(TableColumn())
                    for row_idx, row_data in enumerate(table_rows):
                        tr = TableRow()
                        for col_idx, cell_data in enumerate(row_data):
                            if col_idx < num_cols:
                                tc = TableCell()
                                p = P(stylename="Normal")
                                if row_idx == 0:
                                    span = Span(stylename="Bold")
                                    teletype.addTextToElement(span, cell_data)
                                    p.addElement(span)
                                else:
                                    teletype.addTextToElement(p, cell_data)
                                tc.addElement(p)
                                tr.addElement(tc)
                        table.addElement(tr)
                    doc.text.addElement(table)
                    doc.text.addElement(P(stylename="Normal", text=""))
                table_rows = []

            if not line.strip() or line.strip() == '---':
                continue

            # Encabezados con outline level para TOC
            if line.startswith('# '):
                text = line[2:].strip()
                if chapter_file != "SECCION_PRELIMINAR.md":
                    # Heading 1 con outline level 1 para índice
                    h = H(outlinelevel=1, stylename="Heading1")
                    teletype.addTextToElement(h, text.upper())  # Mayúsculas para capítulos
                    doc.text.addElement(h)
                else:
                    p = P(stylename="CoverTitle")
                    teletype.addTextToElement(p, text)
                    doc.text.addElement(p)
                continue

            if line.startswith('## '):
                text = line[3:].strip()
                # Heading 2 con outline level 2 para índice
                h = H(outlinelevel=2, stylename="Heading2")
                teletype.addTextToElement(h, text)
                doc.text.addElement(h)

                # Agregar figuras relevantes después del encabezado
                if chapter_figures:
                    keywords = ['arquitectura', 'resultado', 'implementacion', 'patron',
                               'analisis', 'normalizacion', 'amenaza', 'taxonomia', 'soberan', 'mcp', 'rag']
                    for fig_name, old_caption in chapter_figures[:]:
                        if any(k in text.lower() for k in keywords):
                            # Usar caption del mapeo actualizado
                            caption = FIGURE_CAPTIONS.get(fig_name, old_caption.split(': ', 1)[-1] if ': ' in old_caption else old_caption)
                            doc = add_figure_with_caption(doc, fig_name, caption, figure_counter)
                            chapter_figures.remove((fig_name, old_caption))
                            break
                continue

            if line.startswith('### '):
                # Heading 3 con outline level 3 para índice
                h = H(outlinelevel=3, stylename="Heading3")
                teletype.addTextToElement(h, line[4:].strip())
                doc.text.addElement(h)
                continue

            if line.startswith('#### '):
                # Heading 4 con outline level 4 para índice
                h = H(outlinelevel=4, stylename="Heading4")
                teletype.addTextToElement(h, line[5:].strip())
                doc.text.addElement(h)
                continue

            if line.startswith('> '):
                p = P(stylename="Quote")
                teletype.addTextToElement(p, f'"{line[2:].strip()}"')
                doc.text.addElement(p)
                continue

            if line.strip().startswith('- ') or line.strip().startswith('* '):
                p = P(stylename="ListParagraph")
                teletype.addTextToElement(p, f"  - {process_inline_text(line.strip()[2:])}")
                doc.text.addElement(p)
                continue

            if re.match(r'^\d+\.\s', line.strip()):
                match = re.match(r'^(\d+)\.\s(.+)$', line.strip())
                if match:
                    p = P(stylename="ListParagraph")
                    teletype.addTextToElement(p, f"  {match.group(1)}. {process_inline_text(match.group(2))}")
                    doc.text.addElement(p)
                continue

            text = process_inline_text(line)
            if text.strip():
                p = P(stylename="Normal")
                teletype.addTextToElement(p, text)
                doc.text.addElement(p)

        # Figuras restantes del capitulo
        for fig_name, old_caption in chapter_figures:
            caption = FIGURE_CAPTIONS.get(fig_name, old_caption.split(': ', 1)[-1] if ': ' in old_caption else old_caption)
            doc = add_figure_with_caption(doc, fig_name, caption, figure_counter)

    # =========================================================================
    # GUARDAR DOCUMENTO
    # =========================================================================
    print("[6/6] Guardando documento...")
    output_path = OUTPUT_DIR / f"TESIS_MIESC_v4.0.0_{datetime.now().strftime('%Y-%m-%d')}.odt"
    doc.save(str(output_path))

    print("\n" + "=" * 60)
    print("DOCUMENTO ODT GENERADO EXITOSAMENTE")
    print("Formato: Reglamento de Tesis MCD (DD 047-020)")
    print("=" * 60)
    print(f"\nArchivo: {output_path}")
    print(f"Tamano: {output_path.stat().st_size / 1024:.1f} KB")
    print(f"Figuras incluidas: {figure_counter[0]}")
    print("\nCaracteristicas del documento:")
    print("  - Caratula segun Anexo 1 del Reglamento")
    print("  - Margenes: Izq 3cm, Sup/Der/Inf 2cm")
    print("  - Fuente: Arial 12pt, interlineado 1.5")
    print("  - Encabezados con jerarquia para indice automatico")
    print("  - Figuras numeradas para indice de ilustraciones")

    return output_path


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='MIESC Thesis Generator - Genera la tesis en formato ODT',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python generate_thesis.py              # Genera figuras y documento
  python generate_thesis.py --figures-only  # Solo figuras
  python generate_thesis.py --doc-only      # Solo documento ODT
        """
    )
    parser.add_argument('--figures-only', action='store_true',
                       help='Solo genera las figuras PNG')
    parser.add_argument('--doc-only', action='store_true',
                       help='Solo genera el documento ODT')

    args = parser.parse_args()

    print("=" * 60)
    print("MIESC THESIS GENERATOR v4.0.0")
    print("Formato: ODT (Open Document Text)")
    print("Compatible con: LibreOffice, Google Docs, MS Word")
    print("=" * 60)

    if args.doc_only:
        output = generate_odt_document()
    elif args.figures_only:
        generate_figures()
        output = None
    else:
        generate_figures()
        output = generate_odt_document()

    if output:
        print("\n" + "=" * 60)
        print("INSTRUCCIONES DE USO")
        print("=" * 60)
        print("""
FORMATO SEGUN REGLAMENTO DE TESIS MCD (DD 047-020)

=== GOOGLE DOCS (recomendado) ===

1. Subir el archivo .odt a Google Drive
2. Abrir con Google Docs
3. GENERAR INDICE DE CONTENIDOS:
   - Borrar las instrucciones donde dice "Google Docs: Insertar > Indice"
   - Posicionar cursor ahi
   - Insertar > Indice > seleccionar estilo
4. El indice de ilustraciones ya esta incluido estaticamente
5. Agregar logos IUA y UNDEF en la caratula
6. Agregar numeracion de paginas: Insertar > Numeros de pagina

=== LIBREOFFICE ===

1. Abrir el archivo .odt directamente
2. GENERAR INDICE DE CONTENIDOS:
   - Insertar > Indices y Tablas > Indice General
   - Seleccionar niveles 1-4
3. Agregar logos IUA y UNDEF en la caratula
4. Numeracion de paginas: Insertar > Campos > Numero de pagina

=== FORMATO APLICADO ===
- Margenes: Izquierdo 3cm, otros 2cm
- Fuente: Arial 12pt
- Caratula segun Anexo 1 del Reglamento
- Figuras numeradas con titulos debajo
""")

    return 0


if __name__ == "__main__":
    sys.exit(main())
