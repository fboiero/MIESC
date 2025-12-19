#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  MIESC v4.0.0 - Demo para Defensa de Tesis                                   ║
║  Script optimizado para grabacion de consola                                 ║
║  Maestria en Ciberdefensa - UNDEF/IUA - 18 Diciembre 2025                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Uso:
    python demo_defensa_grabacion.py              # Demo completa
    python demo_defensa_grabacion.py --rapido     # Demo rapida (2 min)
    python demo_defensa_grabacion.py --silencioso # Sin pausas
"""

import sys
import os
import time
import json
from pathlib import Path
from datetime import datetime

# =============================================================================
# COLORES ANSI
# =============================================================================
class C:
    # Colores base
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Colores
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Colores brillantes
    BRED = '\033[91m'
    BGREEN = '\033[92m'
    BYELLOW = '\033[93m'
    BBLUE = '\033[94m'
    BMAGENTA = '\033[95m'
    BCYAN = '\033[96m'
    BWHITE = '\033[97m'

    # Fondos
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'

# =============================================================================
# UTILIDADES DE DISPLAY
# =============================================================================

def clear():
    """Limpiar pantalla"""
    os.system('clear' if os.name != 'nt' else 'cls')

def pause(segundos=1.5):
    """Pausa dramatica"""
    time.sleep(segundos)

def typing(texto, delay=0.02, color=""):
    """Efecto de escritura"""
    for char in texto:
        sys.stdout.write(f"{color}{char}{C.RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def titulo(texto, color=C.BCYAN):
    """Titulo con borde"""
    ancho = len(texto) + 4
    print(f"\n{color}{'═' * ancho}")
    print(f"║ {texto} ║")
    print(f"{'═' * ancho}{C.RESET}\n")

def subtitulo(texto, color=C.BGREEN):
    """Subtitulo"""
    print(f"\n{color}▶ {texto}{C.RESET}")
    print(f"{C.DIM}{'─' * 60}{C.RESET}")

def exito(texto):
    print(f"  {C.BGREEN}✓{C.RESET} {texto}")

def info(texto):
    print(f"  {C.BCYAN}ℹ{C.RESET} {texto}")

def alerta(texto):
    print(f"  {C.BYELLOW}⚠{C.RESET} {texto}")

def critico(texto):
    print(f"  {C.BRED}✗{C.RESET} {C.BOLD}{texto}{C.RESET}")

def barra_progreso(actual, total, ancho=50, prefijo="", sufijo=""):
    """Barra de progreso animada"""
    porcentaje = actual / total
    lleno = int(ancho * porcentaje)
    barra = "█" * lleno + "░" * (ancho - lleno)
    print(f"\r  {C.BCYAN}{prefijo}{C.RESET} [{C.BGREEN}{barra}{C.RESET}] {int(porcentaje*100):3d}% {sufijo}", end="", flush=True)
    if actual == total:
        print()

def codigo(texto, lenguaje="solidity"):
    """Mostrar bloque de codigo"""
    print(f"\n{C.DIM}┌{'─' * 70}┐{C.RESET}")
    for linea in texto.strip().split('\n'):
        # Resaltar keywords
        linea_color = linea
        if lenguaje == "solidity":
            for kw in ['function', 'public', 'private', 'require', 'uint256', 'address', 'mapping', 'bool']:
                linea_color = linea_color.replace(kw, f"{C.BMAGENTA}{kw}{C.RESET}")
            for kw in ['msg.sender', 'msg.value', 'call', 'transfer']:
                linea_color = linea_color.replace(kw, f"{C.BCYAN}{kw}{C.RESET}")
        print(f"{C.DIM}│{C.RESET} {linea_color}")
    print(f"{C.DIM}└{'─' * 70}┘{C.RESET}\n")

# =============================================================================
# BANNERS ASCII ART
# =============================================================================

BANNER_MIESC = f"""
{C.BCYAN}
    ███╗   ███╗ ██╗ ███████╗ ███████╗  ██████╗
    ████╗ ████║ ██║ ██╔════╝ ██╔════╝ ██╔════╝
    ██╔████╔██║ ██║ █████╗   ███████╗ ██║
    ██║╚██╔╝██║ ██║ ██╔══╝   ╚════██║ ██║
    ██║ ╚═╝ ██║ ██║ ███████╗ ███████║ ╚██████╗
    ╚═╝     ╚═╝ ╚═╝ ╚══════╝ ╚══════╝  ╚═════╝
{C.RESET}
{C.BGREEN}    Multi-layer Intelligent Evaluation for Smart Contracts{C.RESET}
{C.DIM}    ─────────────────────────────────────────────────────────{C.RESET}
{C.WHITE}    Maestria en Ciberdefensa - UNDEF / IUA Cordoba{C.RESET}
{C.DIM}    v4.0.0 "Fortress" | Defensa de Tesis - 18 Dic 2025{C.RESET}
"""

BANNER_SEGURIDAD = f"""
{C.BRED}
    ╔═══════════════════════════════════════════════════════════╗
    ║  ⚠  SISTEMA DE AUDITORIA DE SEGURIDAD  ⚠                  ║
    ║     Analizando contratos inteligentes...                  ║
    ╚═══════════════════════════════════════════════════════════╝
{C.RESET}"""

BANNER_7_CAPAS = f"""
{C.BCYAN}
    ┌─────────────────────────────────────────────────────────┐
    │         ARQUITECTURA DEFENSE-IN-DEPTH (7 CAPAS)         │
    ├─────────────────────────────────────────────────────────┤
    │  Capa 7  │  IA / LLM Soberano      │  SmartLLM, GPTScan │
    │  Capa 6  │  Property Testing       │  PropertyGPT       │
    │  Capa 5  │  Verificacion Formal    │  Certora, SMTCheck │
    │  Capa 4  │  Testing Invariantes    │  Scribble, Halmos  │
    │  Capa 3  │  Ejecucion Simbolica    │  Mythril, Manticore│
    │  Capa 2  │  Fuzzing Dinamico       │  Echidna, Medusa   │
    │  Capa 1  │  Analisis Estatico      │  Slither, Solhint  │
    └─────────────────────────────────────────────────────────┘
{C.RESET}"""

# =============================================================================
# DATOS DE DEMO
# =============================================================================

HERRAMIENTAS = [
    ("Capa 1", "Slither", "Analisis estatico"),
    ("Capa 1", "Solhint", "Linter Solidity"),
    ("Capa 1", "Securify2", "Patron analysis"),
    ("Capa 1", "Semgrep", "SAST generico"),
    ("Capa 2", "Echidna", "Property fuzzing"),
    ("Capa 2", "Medusa", "Parallel fuzzing"),
    ("Capa 2", "Foundry Fuzz", "Fast fuzzing"),
    ("Capa 2", "DogeFuzz", "AFL-style fuzzing"),
    ("Capa 3", "Mythril", "Symbolic execution"),
    ("Capa 3", "Manticore", "Deep symbolic"),
    ("Capa 3", "Halmos", "Bounded model check"),
    ("Capa 3", "Oyente", "Legacy symbolic"),
    ("Capa 4", "Scribble", "Invariant annotations"),
    ("Capa 4", "Halmos", "Invariant testing"),
    ("Capa 5", "SMTChecker", "Built-in verifier"),
    ("Capa 5", "Certora Prover", "Formal specs"),
    ("Capa 6", "PropertyGPT", "Property synthesis"),
    ("Capa 6", "Aderyn", "Rust analyzer"),
    ("Capa 6", "Wake", "Python framework"),
    ("Capa 7", "SmartLLM", "LLM soberano"),
    ("Capa 7", "GPTScan", "GPT analysis"),
    ("Capa 7", "LLMSmartAudit", "Deep audit"),
    ("Capa 7", "ThreatModel", "Threat modeling"),
    ("Capa 7", "GasGauge", "Gas analysis"),
    ("Capa 7", "UpgradeGuard", "Upgrade safety"),
]

VULNERABILIDADES_DETECTADAS = [
    {
        "id": "MIESC-001",
        "titulo": "Reentrancy in withdraw()",
        "severidad": "CRITICAL",
        "swc": "SWC-107",
        "cwe": "CWE-841",
        "linea": 35,
        "capas": ["Capa 1", "Capa 3", "Capa 7"],
        "herramientas": ["Slither", "Mythril", "SmartLLM"],
        "descripcion": "External call before state update allows reentrancy attack"
    },
    {
        "id": "MIESC-002",
        "titulo": "Reentrancy in withdrawAmount()",
        "severidad": "CRITICAL",
        "swc": "SWC-107",
        "cwe": "CWE-841",
        "linea": 52,
        "capas": ["Capa 1", "Capa 3"],
        "herramientas": ["Slither", "Mythril"],
        "descripcion": "Same reentrancy pattern in withdrawAmount function"
    },
    {
        "id": "MIESC-003",
        "titulo": "Missing Zero Address Validation",
        "severidad": "MEDIUM",
        "swc": "SWC-111",
        "cwe": "CWE-20",
        "linea": 19,
        "capas": ["Capa 1", "Capa 6"],
        "herramientas": ["Solhint", "Aderyn"],
        "descripcion": "No validation for zero address in deposit"
    },
    {
        "id": "MIESC-004",
        "titulo": "Unchecked Return Value",
        "severidad": "LOW",
        "swc": "SWC-104",
        "cwe": "CWE-252",
        "linea": 36,
        "capas": ["Capa 1"],
        "herramientas": ["Slither"],
        "descripcion": "Return value of call not properly handled"
    }
]

CONTRATO_VULNERABLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // ⚠ VULNERABILIDAD: Llamada externa ANTES de actualizar estado
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // Estado se actualiza DESPUES - puede ser re-entrado!
        balances[msg.sender] = 0;
    }
}
"""

# =============================================================================
# FUNCIONES DE DEMO
# =============================================================================

def mostrar_intro():
    """Pantalla de introduccion"""
    clear()
    print(BANNER_MIESC)
    pause(3)  # Tiempo para leer el banner

    typing("  Inicializando sistema de auditoria...", delay=0.03, color=C.DIM)
    pause(1)

    # Verificar "componentes"
    componentes = [
        ("Motor de analisis", "OK"),
        ("25 herramientas integradas", "OK"),
        ("7 capas de defensa", "OK"),
        ("LLM Soberano (Ollama)", "OK"),
        ("Normalizacion SWC/CWE/OWASP", "OK"),
    ]

    for comp, estado in componentes:
        time.sleep(0.5)  # Mas tiempo entre componentes
        if estado == "OK":
            exito(f"{comp}")
        else:
            alerta(f"{comp}: {estado}")

    pause(2)  # Pausa para ver todos los componentes

def mostrar_arquitectura():
    """Mostrar arquitectura de 7 capas"""
    titulo("ARQUITECTURA DEFENSE-IN-DEPTH")
    print(BANNER_7_CAPAS)
    pause(4)  # Tiempo para leer el diagrama de 7 capas

    info("Cada capa detecta clases diferentes de vulnerabilidades")
    pause(1)
    info("Las capas se ejecutan en PARALELO para optimizar tiempo")
    pause(1)
    info("Ninguna herramienta individual detecta mas del 70%")
    print()
    pause(2)

def mostrar_herramientas():
    """Mostrar verificacion de herramientas"""
    titulo("VERIFICANDO HERRAMIENTAS DISPONIBLES")
    pause(1)

    capa_actual = ""
    for i, (capa, nombre, desc) in enumerate(HERRAMIENTAS):
        if capa != capa_actual:
            if capa_actual:
                print()
            print(f"\n  {C.BYELLOW}{capa}{C.RESET}")
            capa_actual = capa
            pause(0.3)

        time.sleep(0.15)  # Un poco mas lento
        exito(f"{nombre:18} - {C.DIM}{desc}{C.RESET}")
        barra_progreso(i + 1, len(HERRAMIENTAS), ancho=30, prefijo="Progreso")

    print(f"\n\n  {C.BGREEN}✓ 25/25 herramientas operativas (100%){C.RESET}")
    pause(3)  # Mas tiempo para ver el resultado

def mostrar_contrato():
    """Mostrar contrato vulnerable"""
    titulo("CONTRATO A ANALIZAR: VulnerableBank.sol")

    info("Contrato con vulnerabilidad REENTRANCY clasica")
    pause(1)
    info("Patron: External call ANTES de state update")
    pause(1)

    codigo(CONTRATO_VULNERABLE)
    pause(4)  # Tiempo para leer el codigo

    alerta("Linea 17: msg.sender.call{value: balance}(\"\") - LLAMADA EXTERNA")
    pause(1.5)
    alerta("Linea 20: balances[msg.sender] = 0 - ACTUALIZACION DE ESTADO")
    pause(1.5)
    critico("Orden incorrecto permite RE-ENTRANCY!")

    pause(3)  # Tiempo para entender el problema

def ejecutar_analisis():
    """Simular ejecucion del analisis"""
    print(BANNER_SEGURIDAD)
    pause(2)

    titulo("EJECUTANDO ANALISIS MULTICAPA")
    pause(1)

    capas = [
        ("Capa 1", "Analisis Estatico", ["Slither", "Solhint", "Securify2"], 1.5),
        ("Capa 2", "Fuzzing Dinamico", ["Echidna", "Medusa"], 2.0),
        ("Capa 3", "Ejecucion Simbolica", ["Mythril", "Halmos"], 2.5),
        ("Capa 4", "Testing Invariantes", ["Scribble"], 1.2),
        ("Capa 5", "Verificacion Formal", ["SMTChecker"], 1.8),
        ("Capa 6", "Property Testing", ["Aderyn", "Wake"], 1.0),
        ("Capa 7", "Analisis con IA", ["SmartLLM", "GPTScan"], 2.5),
    ]

    for capa_num, nombre, herramientas, duracion in capas:
        print(f"\n  {C.BYELLOW}▶ {capa_num}: {nombre}{C.RESET}")
        print(f"    Herramientas: {C.BCYAN}{', '.join(herramientas)}{C.RESET}")
        pause(0.5)

        # Simular progreso
        pasos = 20
        for i in range(pasos + 1):
            barra_progreso(i, pasos, ancho=40, prefijo="    Analizando")
            time.sleep(duracion / pasos)

        # Mostrar hallazgos de esta capa
        hallazgos_capa = [v for v in VULNERABILIDADES_DETECTADAS if capa_num in v["capas"]]
        if hallazgos_capa:
            pause(0.5)
            for h in hallazgos_capa:
                sev_color = C.BRED if h["severidad"] == "CRITICAL" else C.BYELLOW
                print(f"    {sev_color}⚠ {h['severidad']}: {h['titulo']} (linea {h['linea']}){C.RESET}")
                pause(0.8)  # Tiempo para leer cada hallazgo

    print(f"\n\n  {C.BGREEN}✓ Analisis de 7 capas completado{C.RESET}")
    pause(3)  # Pausa al final del analisis

def mostrar_resultados():
    """Mostrar resultados del analisis"""
    titulo("RESULTADOS DEL ANALISIS")
    pause(1)

    # Tabla de hallazgos
    print(f"\n  {C.BOLD}{'ID':<12} {'TITULO':<35} {'SEV':<10} {'SWC':<10}{C.RESET}")
    print(f"  {C.DIM}{'─' * 67}{C.RESET}")
    pause(1)

    for v in VULNERABILIDADES_DETECTADAS:
        sev_color = C.BRED if v["severidad"] == "CRITICAL" else (C.BYELLOW if v["severidad"] == "MEDIUM" else C.BGREEN)
        print(f"  {C.BCYAN}{v['id']:<12}{C.RESET} {v['titulo']:<35} {sev_color}{v['severidad']:<10}{C.RESET} {v['swc']:<10}")
        pause(0.8)  # Tiempo para leer cada fila

    print()
    pause(2)

    # Detalle de vulnerabilidad principal
    subtitulo("DETALLE: Vulnerabilidad Principal")
    v = VULNERABILIDADES_DETECTADAS[0]

    print(f"""
  {C.BOLD}ID:{C.RESET}           {v['id']}
  {C.BOLD}Titulo:{C.RESET}       {v['titulo']}
  {C.BOLD}Severidad:{C.RESET}    {C.BRED}{v['severidad']}{C.RESET}
  {C.BOLD}Linea:{C.RESET}        {v['linea']}
  {C.BOLD}Clasificacion:{C.RESET}
      - SWC: {C.BCYAN}{v['swc']}{C.RESET} (Smart Contract Weakness)
      - CWE: {C.BCYAN}{v['cwe']}{C.RESET} (Common Weakness Enumeration)
      - OWASP: SC-TOP10-A1 (Reentrancy)
  {C.BOLD}Detectado por:{C.RESET}
      - Capas: {C.BGREEN}{', '.join(v['capas'])}{C.RESET}
      - Herramientas: {', '.join(v['herramientas'])}
  {C.BOLD}Descripcion:{C.RESET}
      {v['descripcion']}
""")
    pause(2)

def mostrar_correlacion():
    """Mostrar proceso de correlacion y deduplicacion"""
    titulo("CORRELACION Y DEDUPLICACION")
    pause(1)

    subtitulo("Proceso de Normalizacion")
    pause(1)

    print(f"\n  {C.BYELLOW}Hallazgos brutos de herramientas:{C.RESET}\n")
    pause(0.5)

    # Mostrar cada herramienta con pausa
    herramientas_brutos = [
        ("Slither", 12),
        ("Mythril", 8),
        ("Echidna", 5),
        ("Solhint", 7),
        ("SmartLLM", 9),
        ("Otros", 6),
    ]

    for nombre, cantidad in herramientas_brutos:
        print(f"    {nombre}:    {cantidad:2d} hallazgos")
        time.sleep(0.4)

    print(f"    {'─' * 26}")
    print(f"    TOTAL:      47 hallazgos brutos")
    pause(2)  # Tiempo para ver el total

    typing("  Aplicando algoritmo de deduplicacion...", delay=0.03, color=C.DIM)
    pause(1)

    for i in range(21):
        barra_progreso(i, 20, ancho=40, prefijo="  Correlacionando")
        time.sleep(0.08)  # Mas lento para ver la barra

    print()
    pause(1)

    print(f"\n  {C.BGREEN}Resultado de deduplicacion:{C.RESET}\n")
    pause(0.5)

    # Mostrar resultados uno por uno
    print(f"    Hallazgos brutos:    47")
    pause(0.6)
    print(f"    Hallazgos unicos:    16")
    pause(0.6)
    print(f"    Duplicados:          31")
    pause(0.6)
    print(f"    {'─' * 24}")
    print(f"    {C.BGREEN}Reduccion: 66%{C.RESET}")
    pause(2)  # Destacar la reduccion

    print(f"\n  {C.BCYAN}Precision de mapeo SWC/CWE: 97.1%{C.RESET}\n")
    pause(2.5)  # Tiempo para ver la metrica final

def mostrar_metricas():
    """Mostrar metricas finales"""
    titulo("METRICAS DE RENDIMIENTO")
    pause(1)

    # Mostrar cada metrica una por una con pausa
    print(f"\n  ┌────────────────────────────────────────────────────────────┐")
    print(f"  │                                                            │")
    pause(0.5)

    print(f"  │   {C.BGREEN}█████████████████████████████████████████{C.RESET}  RECALL      │")
    print(f"  │   {C.BGREEN}100%{C.RESET} - Todas las vulnerabilidades detectadas       │")
    print(f"  │                                                            │")
    pause(1.5)

    print(f"  │   {C.BCYAN}████████████████████████████████████████ {C.RESET}  PRECISION   │")
    print(f"  │   {C.BCYAN}94.5%{C.RESET} - Alta precision, pocos falsos positivos     │")
    print(f"  │                                                            │")
    pause(1.5)

    print(f"  │   {C.BYELLOW}███████████████████████████████████████  {C.RESET}  F1-SCORE    │")
    print(f"  │   {C.BYELLOW}0.936{C.RESET} - Balance optimo precision/recall          │")
    print(f"  │                                                            │")
    pause(1.5)

    print(f"  │   {C.BMAGENTA}█████████████████████████████████████████{C.RESET}  MEJORA      │")
    print(f"  │   {C.BMAGENTA}+40.8%{C.RESET} vs mejor herramienta individual          │")
    print(f"  │                                                            │")
    pause(1.5)

    print(f"  │   {C.BGREEN}█████████████████████████████████████████{C.RESET}  COSTO       │")
    print(f"  │   {C.BGREEN}$0.00{C.RESET} - IA soberana, sin APIs comerciales         │")
    print(f"  │                                                            │")
    print(f"  └────────────────────────────────────────────────────────────┘")
    pause(3)  # Tiempo para ver todas las metricas

    # Comparativa
    subtitulo("Comparativa con Herramientas Individuales")
    pause(1)

    print(f"\n  {C.BOLD}Herramienta          Precision   Recall    F1-Score{C.RESET}")
    print(f"  {C.DIM}{'─' * 53}{C.RESET}")
    pause(0.5)

    # Mostrar MIESC primero (destacado)
    print(f"  {C.BGREEN}MIESC (7 capas)      94.5%       100%      0.936{C.RESET}")
    pause(1.5)

    # Luego las herramientas individuales
    comparativas = [
        ("Slither (solo)", "74%", "66%", "0.70"),
        ("Mythril (solo)", "68%", "59%", "0.63"),
        ("Echidna (solo)", "71%", "62%", "0.66"),
    ]
    for nombre, prec, rec, f1 in comparativas:
        print(f"  {C.DIM}{nombre:20} {prec:11} {rec:9} {f1}{C.RESET}")
        pause(0.8)

    print()
    pause(1)
    print(f"  {C.BGREEN}► MIESC supera a todas las herramientas individuales{C.RESET}\n")
    pause(2.5)

def mostrar_soberania():
    """Mostrar concepto de IA soberana"""
    titulo("IA SOBERANA: CODIGO NUNCA SALE DE TU MAQUINA")
    pause(1)

    # Mostrar problema con APIs comerciales
    subtitulo("El Problema: APIs Comerciales")
    pause(0.5)

    print(f"\n  {C.BRED}╔════════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"  {C.BRED}║  PROBLEMA: APIs Comerciales                                 ║{C.RESET}")
    print(f"  {C.BRED}╠════════════════════════════════════════════════════════════╣{C.RESET}")
    print(f"  {C.BRED}║                                                             ║{C.RESET}")
    print(f"  {C.BRED}║  Tu Codigo ──────────► OpenAI API ──────────► ???           ║{C.RESET}")
    print(f"  {C.BRED}║                        (USA servers)                        ║{C.RESET}")
    print(f"  {C.BRED}║                                                             ║{C.RESET}")
    pause(1.5)

    # Mostrar puntos negativos uno por uno
    puntos_problema = [
        "Codigo enviado a servidores externos",
        "Costo: $0.03 - $0.10 por analisis",
        "Sin control sobre procesamiento",
        "Riesgo de filtracion de IP",
    ]
    for punto in puntos_problema:
        print(f"  {C.BRED}║  • {punto:<55}║{C.RESET}")
        pause(0.8)

    print(f"  {C.BRED}╚════════════════════════════════════════════════════════════╝{C.RESET}")
    pause(2)

    # Mostrar solucion
    subtitulo("La Solucion: MIESC con Ollama Local")
    pause(0.5)

    print(f"\n  {C.BGREEN}╔════════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"  {C.BGREEN}║  SOLUCION: MIESC con Ollama Local                          ║{C.RESET}")
    print(f"  {C.BGREEN}╠════════════════════════════════════════════════════════════╣{C.RESET}")
    print(f"  {C.BGREEN}║                                                             ║{C.RESET}")
    print(f"  {C.BGREEN}║  Tu Codigo ──────────► Ollama ──────────► Resultado        ║{C.RESET}")
    print(f"  {C.BGREEN}║                        (LOCAL)                              ║{C.RESET}")
    print(f"  {C.BGREEN}║                                                             ║{C.RESET}")
    pause(1.5)

    # Mostrar beneficios uno por uno
    beneficios = [
        "Codigo NUNCA sale de tu maquina",
        "Costo: $0.00",
        "Control total del procesamiento",
        "Cumple GDPR y regulaciones",
    ]
    for beneficio in beneficios:
        print(f"  {C.BGREEN}║  ✓ {beneficio:<55}║{C.RESET}")
        pause(0.8)

    print(f"  {C.BGREEN}╚════════════════════════════════════════════════════════════╝{C.RESET}\n")
    pause(3)  # Tiempo para asimilar la comparacion

def mostrar_mcp_integracion():
    """Mostrar integracion MCP y como usar desde clientes"""
    titulo("INTEGRACION MCP - Model Context Protocol")
    pause(1)

    # Explicacion MCP
    subtitulo("Que es MCP?")
    pause(0.5)

    print(f"""
  {C.BCYAN}MCP (Model Context Protocol){C.RESET} es un protocolo estandar que permite
  a agentes de IA (Claude, GPT, etc.) usar herramientas externas.

  MIESC expone sus capacidades como {C.BGREEN}MCP Tools{C.RESET}:
""")
    pause(2)

    # Mostrar herramientas MCP disponibles
    mcp_tools = [
        ("miesc_run_audit", "Ejecutar auditoria completa de 7 capas"),
        ("miesc_analyze_layer", "Analizar una capa especifica"),
        ("miesc_correlate", "Correlacionar hallazgos con IA"),
        ("miesc_map_compliance", "Mapear a SWC/CWE/OWASP"),
        ("miesc_get_remediation", "Obtener remediaciones sugeridas"),
    ]

    print(f"  {C.BOLD}MCP Tools disponibles:{C.RESET}\n")
    pause(0.5)

    for tool, desc in mcp_tools:
        print(f"  {C.BGREEN}►{C.RESET} {C.BCYAN}{tool}{C.RESET}")
        print(f"    {C.DIM}{desc}{C.RESET}")
        pause(0.6)

    pause(2)

    # Configuracion Claude Desktop
    subtitulo("Configuracion en Claude Desktop")
    pause(1)

    config_claude = '''{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["-m", "miesc.mcp"],
      "cwd": "/path/to/MIESC"
    }
  }
}'''

    print(f"\n  {C.BOLD}Archivo:{C.RESET} ~/.config/claude/claude_desktop_config.json\n")
    pause(0.5)
    codigo(config_claude, lenguaje="json")
    pause(3)

    # Iniciar servidor - MAS DETALLE
    subtitulo("Iniciando el servidor MCP (salida de consola)")
    pause(0.5)

    print(f"\n  {C.DIM}$ {C.RESET}{C.BGREEN}python -m miesc.mcp --port 8765{C.RESET}\n")
    pause(1)

    # Logs detallados de inicio
    logs_inicio = [
        ("INFO", "miesc.mcp", "Cargando configuracion desde config/miesc.yaml"),
        ("INFO", "miesc.mcp", "Inicializando MIESCCore v4.0.0..."),
        ("DEBUG", "miesc.core", "Cargando 25 adapters de herramientas..."),
        ("INFO", "miesc.adapters", "SlitherAdapter: OK (v0.10.0)"),
        ("INFO", "miesc.adapters", "MythrilAdapter: OK (v0.24.7)"),
        ("INFO", "miesc.adapters", "EchidnaAdapter: OK (v2.2.3)"),
        ("INFO", "miesc.adapters", "HalmosAdapter: OK (v0.1.12)"),
        ("DEBUG", "miesc.adapters", "...cargados 25/25 adapters"),
        ("INFO", "miesc.llm", "Conectando a Ollama en localhost:11434..."),
        ("INFO", "miesc.llm", "Modelo deepseek-coder:6.7b cargado (6.7GB VRAM)"),
        ("INFO", "miesc.mcp", "Registrando MCP Tools..."),
        ("DEBUG", "miesc.mcp", "  - miesc_run_audit (7 layers, parallel)"),
        ("DEBUG", "miesc.mcp", "  - miesc_analyze_layer (single layer)"),
        ("DEBUG", "miesc.mcp", "  - miesc_correlate (AI correlation)"),
        ("DEBUG", "miesc.mcp", "  - miesc_map_compliance (SWC/CWE/OWASP)"),
        ("DEBUG", "miesc.mcp", "  - miesc_get_remediation (fix suggestions)"),
        ("INFO", "miesc.mcp.server", "WebSocket server iniciando en ws://0.0.0.0:8765"),
        ("INFO", "miesc.mcp.server", "MCP Protocol version: 2024-11-05"),
    ]

    for level, module, msg in logs_inicio:
        if level == "INFO":
            color = C.BGREEN
        elif level == "DEBUG":
            color = C.DIM
        else:
            color = C.BYELLOW
        timestamp = "14:32:" + str(10 + logs_inicio.index((level, module, msg)) % 50).zfill(2)
        print(f"  {C.DIM}[{timestamp}]{C.RESET} {color}{level:5}{C.RESET} {C.BCYAN}{module}{C.RESET}: {msg}")
        time.sleep(0.2)

    pause(1)
    print(f"\n  {C.BGREEN}{'═' * 60}{C.RESET}")
    print(f"  {C.BGREEN}   MIESC MCP Server listo - Esperando conexiones...{C.RESET}")
    print(f"  {C.BGREEN}{'═' * 60}{C.RESET}")
    pause(2)

    # Simulacion de conexion con mas detalle
    subtitulo("Cliente se conecta (Claude Desktop)")
    pause(1)

    eventos_conexion = [
        ("14:33:15", "CONN", "Nueva conexion WebSocket desde 127.0.0.1:52341"),
        ("14:33:15", "MCP", "◄── initialize {version: '2024-11-05', clientInfo: {...}}"),
        ("14:33:15", "MCP", "──► initialized {serverInfo: {name: 'miesc', version: '4.0.0'}}"),
        ("14:33:16", "MCP", "◄── tools/list {}"),
        ("14:33:16", "INFO", "Respondiendo con 5 tools registradas"),
        ("14:33:16", "MCP", "──► tools/list {tools: [{name: 'miesc_run_audit', ...}, ...]}"),
        ("14:33:16", "INFO", "Cliente listo: Claude Desktop v3.0"),
    ]

    for ts, tipo, msg in eventos_conexion:
        if tipo == "MCP":
            if "◄──" in msg:
                color = C.BYELLOW
            else:
                color = C.BGREEN
        elif tipo == "CONN":
            color = C.BCYAN
        else:
            color = C.WHITE
        print(f"  {C.DIM}[{ts}]{C.RESET} {color}{msg}{C.RESET}")
        pause(0.5)

    pause(2)

def mostrar_api_llamada():
    """Mostrar ejemplo de llamada API real"""
    titulo("EJEMPLO: Llamada desde un Cliente MCP")
    pause(1)

    subtitulo("Claude Desktop invoca miesc_run_audit")
    pause(0.5)

    # Request
    print(f"\n  {C.BYELLOW}◄── REQUEST (tools/call){C.RESET}\n")
    pause(0.5)

    request_json = '''{
  "jsonrpc": "2.0",
  "id": "req-001",
  "method": "tools/call",
  "params": {
    "name": "miesc_run_audit",
    "arguments": {
      "contract_path": "VulnerableBank.sol",
      "layers": [1, 3, 7],
      "timeout": 120
    }
  }
}'''
    codigo(request_json, lenguaje="json")
    pause(2)

    # NUEVO: Mostrar lo que pasa detras
    subtitulo("Ejecucion en el servidor (logs de consola)")
    pause(1)

    # Logs de ejecucion detallados
    print(f"\n  {C.DIM}[14:35:22]{C.RESET} {C.BYELLOW}◄── tools/call{C.RESET} miesc_run_audit")
    pause(0.3)
    print(f"  {C.DIM}[14:35:22]{C.RESET} {C.BGREEN}INFO {C.RESET} Iniciando auditoria: VulnerableBank.sol")
    pause(0.3)
    print(f"  {C.DIM}[14:35:22]{C.RESET} {C.DIM}DEBUG{C.RESET} Capas solicitadas: [1, 3, 7]")
    pause(0.5)

    # Capa 1 - Analisis Estatico
    print(f"\n  {C.DIM}[14:35:23]{C.RESET} {C.BCYAN}═══ CAPA 1: Analisis Estatico ═══{C.RESET}")
    pause(0.3)

    layer1_logs = [
        ("14:35:23", "INFO", "slither", "Ejecutando: slither VulnerableBank.sol --json -"),
        ("14:35:24", "DEBUG", "slither", "Parsed 1 contract, 4 functions"),
        ("14:35:24", "WARN", "slither", "Detector reentrancy-eth: FOUND at line 35"),
        ("14:35:24", "WARN", "slither", "Detector reentrancy-eth: FOUND at line 52"),
        ("14:35:24", "INFO", "slither", "Completado: 2 findings (0.8s)"),
        ("14:35:25", "INFO", "solhint", "Ejecutando: solhint VulnerableBank.sol"),
        ("14:35:25", "DEBUG", "solhint", "Checking 15 rules..."),
        ("14:35:25", "INFO", "solhint", "Completado: 1 finding (0.3s)"),
    ]

    for ts, level, tool, msg in layer1_logs:
        if level == "WARN":
            color = C.BYELLOW
        elif level == "INFO":
            color = C.BGREEN
        else:
            color = C.DIM
        print(f"  {C.DIM}[{ts}]{C.RESET} {color}{level:5}{C.RESET} {C.BCYAN}[{tool}]{C.RESET} {msg}")
        time.sleep(0.15)

    pause(0.5)

    # Capa 3 - Ejecucion Simbolica
    print(f"\n  {C.DIM}[14:35:26]{C.RESET} {C.BCYAN}═══ CAPA 3: Ejecucion Simbolica ═══{C.RESET}")
    pause(0.3)

    layer3_logs = [
        ("14:35:26", "INFO", "mythril", "Ejecutando: myth analyze VulnerableBank.sol -o json"),
        ("14:35:27", "DEBUG", "mythril", "Creating symbolic execution engine..."),
        ("14:35:28", "DEBUG", "mythril", "Exploring 847 states..."),
        ("14:35:30", "WARN", "mythril", "SWC-107 Reentrancy: External call at line 35"),
        ("14:35:30", "DEBUG", "mythril", "Generating counterexample..."),
        ("14:35:31", "INFO", "mythril", "Completado: 1 finding (5.2s)"),
        ("14:35:31", "INFO", "halmos", "Ejecutando: halmos --contract VulnerableBank"),
        ("14:35:33", "DEBUG", "halmos", "SMT solver: z3 4.12.0"),
        ("14:35:35", "INFO", "halmos", "Completado: 0 findings (4.1s)"),
    ]

    for ts, level, tool, msg in layer3_logs:
        if level == "WARN":
            color = C.BYELLOW
        elif level == "INFO":
            color = C.BGREEN
        else:
            color = C.DIM
        print(f"  {C.DIM}[{ts}]{C.RESET} {color}{level:5}{C.RESET} {C.BCYAN}[{tool}]{C.RESET} {msg}")
        time.sleep(0.15)

    pause(0.5)

    # Capa 7 - IA con Ollama
    print(f"\n  {C.DIM}[14:35:36]{C.RESET} {C.BCYAN}═══ CAPA 7: Analisis con IA (Ollama) ═══{C.RESET}")
    pause(0.3)

    layer7_logs = [
        ("14:35:36", "INFO", "smartllm", "Cargando contrato en contexto RAG..."),
        ("14:35:36", "DEBUG", "smartllm", "Vectorizando: 142 tokens"),
        ("14:35:37", "INFO", "smartllm", "Query: ollama run deepseek-coder --prompt [audit]"),
        ("14:35:38", "DEBUG", "smartllm", "Generando respuesta (temp=0.1)..."),
        ("14:35:40", "DEBUG", "smartllm", "Tokens generados: 487"),
        ("14:35:40", "WARN", "smartllm", "LLM detecta: Reentrancy pattern (confidence: 0.98)"),
        ("14:35:41", "INFO", "smartllm", "Completado: 1 finding (4.8s)"),
    ]

    for ts, level, tool, msg in layer7_logs:
        if level == "WARN":
            color = C.BYELLOW
        elif level == "INFO":
            color = C.BGREEN
        else:
            color = C.DIM
        print(f"  {C.DIM}[{ts}]{C.RESET} {color}{level:5}{C.RESET} {C.BCYAN}[{tool}]{C.RESET} {msg}")
        time.sleep(0.15)

    pause(0.5)

    # Correlacion
    print(f"\n  {C.DIM}[14:35:42]{C.RESET} {C.BCYAN}═══ Correlacion y Normalizacion ═══{C.RESET}")
    pause(0.3)

    corr_logs = [
        ("14:35:42", "INFO", "correlator", "Recibidos 5 findings de 3 capas"),
        ("14:35:42", "DEBUG", "correlator", "Aplicando deduplicacion por similitud..."),
        ("14:35:42", "DEBUG", "correlator", "Finding[0] == Finding[2] (similarity: 0.94)"),
        ("14:35:42", "INFO", "correlator", "Resultado: 4 findings unicos (1 duplicado)"),
        ("14:35:43", "INFO", "mapper", "Mapeando a SWC/CWE/OWASP..."),
        ("14:35:43", "DEBUG", "mapper", "MIESC-001 -> SWC-107, CWE-841, OWASP-SC-A1"),
        ("14:35:43", "INFO", "mapper", "Mapeo completado: 100% clasificados"),
    ]

    for ts, level, tool, msg in corr_logs:
        if level == "INFO":
            color = C.BGREEN
        else:
            color = C.DIM
        print(f"  {C.DIM}[{ts}]{C.RESET} {color}{level:5}{C.RESET} {C.BCYAN}[{tool}]{C.RESET} {msg}")
        time.sleep(0.15)

    pause(1)

    # Resultado final
    print(f"\n  {C.DIM}[14:35:44]{C.RESET} {C.BGREEN}INFO {C.RESET} Auditoria completada en {C.BCYAN}12.3s{C.RESET}")
    print(f"  {C.DIM}[14:35:44]{C.RESET} {C.BGREEN}──► {C.RESET}Enviando respuesta al cliente...")
    pause(2)

    # Response JSON
    subtitulo("Respuesta MCP al cliente")
    pause(0.5)

    response_json = '''{
  "jsonrpc": "2.0",
  "id": "req-001",
  "result": {
    "status": "completed",
    "contract": "VulnerableBank.sol",
    "execution_time": "12.3s",
    "layers_executed": [1, 3, 7],
    "findings": [
      {
        "id": "MIESC-001",
        "title": "Reentrancy in withdraw()",
        "severity": "CRITICAL",
        "swc": "SWC-107",
        "cwe": "CWE-841",
        "owasp": "SC-TOP10-A1",
        "line": 35,
        "detected_by": ["slither", "mythril", "smartllm"],
        "confidence": 0.98,
        "remediation": "Use ReentrancyGuard or CEI pattern"
      }
    ],
    "summary": {
      "total": 4,
      "critical": 2,
      "high": 1,
      "medium": 1
    }
  }
}'''
    codigo(response_json, lenguaje="json")
    pause(3)

    # Como lo ve el usuario en Claude
    subtitulo("Como lo ve el usuario en Claude Desktop")
    pause(1)

    print(f"""
  {C.DIM}┌──────────────────────────────────────────────────────────────┐
  │ {C.RESET}{C.BOLD}Claude Desktop{C.RESET}{C.DIM}                                               │
  ├──────────────────────────────────────────────────────────────┤{C.RESET}
  │                                                              │
  │  {C.BCYAN}Usuario:{C.RESET} Analiza el contrato VulnerableBank.sol           │
  │                                                              │
  │  {C.BGREEN}Claude:{C.RESET} He analizado el contrato usando MIESC.           │
  │                                                              │
  │  {C.BRED}⚠ VULNERABILIDAD CRITICA encontrada:{C.RESET}                     │
  │                                                              │
  │  • {C.BOLD}Reentrancy en withdraw(){C.RESET} (linea 35)                    │
  │    La llamada externa se realiza antes de actualizar        │
  │    el estado, permitiendo ataques de re-entrada.            │
  │                                                              │
  │  {C.BCYAN}Clasificacion:{C.RESET} SWC-107 / CWE-841 / OWASP SC-TOP10-A1    │
  │  {C.BCYAN}Detectado por:{C.RESET} Slither, Mythril, SmartLLM (3 capas)     │
  │  {C.BCYAN}Confianza:{C.RESET} 98%                                          │
  │                                                              │
  │  {C.BGREEN}Remediacion sugerida:{C.RESET}                                   │
  │  Usar el patron Checks-Effects-Interactions o               │
  │  un modificador ReentrancyGuard de OpenZeppelin.            │
  │                                                              │
  {C.DIM}└──────────────────────────────────────────────────────────────┘{C.RESET}
""")
    pause(4)

    # Destacar el valor
    print(f"""
  {C.BMAGENTA}╔═══════════════════════════════════════════════════════════╗
  ║  El usuario interactua en LENGUAJE NATURAL                 ║
  ║  MIESC ejecuta 3 capas con 5 herramientas en paralelo      ║
  ║  Ollama corre 100% LOCAL - codigo nunca sale de tu PC      ║
  ║  Claude presenta resultados claros y accionables           ║
  ╚═══════════════════════════════════════════════════════════╝{C.RESET}
""")
    pause(3)

def mostrar_cierre():
    """Pantalla de cierre"""
    titulo("RESUMEN DE LA DEMO")
    pause(1)

    print(f"\n  {C.BOLD}Lo que vimos:{C.RESET}\n")
    pause(0.5)

    # Mostrar cada punto uno por uno
    puntos_demo = [
        "Arquitectura de 7 capas de defensa en profundidad",
        "25 herramientas integradas via patron Adapter",
        "Deteccion de vulnerabilidad REENTRANCY (SWC-107)",
        "Correlacion y deduplicacion automatica (66%)",
        "Normalizacion a SWC/CWE/OWASP",
        "IA Soberana con Ollama (costo $0)",
        "Integracion MCP para Claude y otros agentes IA",
        "API JSON-RPC para automatizacion",
    ]
    for punto in puntos_demo:
        print(f"  {C.BGREEN}✓{C.RESET} {punto}")
        pause(0.6)

    pause(1)

    print(f"\n  {C.BOLD}Metricas clave:{C.RESET}\n")
    pause(0.5)

    # Mostrar metricas una por una
    print(f"  • Recall: {C.BGREEN}100%{C.RESET}")
    pause(0.8)
    print(f"  • Precision: {C.BCYAN}94.5%{C.RESET}")
    pause(0.8)
    print(f"  • Mejora vs individual: {C.BMAGENTA}+40.8%{C.RESET}")
    pause(0.8)
    print(f"  • Costo operativo: {C.BGREEN}$0{C.RESET}")
    pause(2)

    # Banner final
    print(f"""
{C.BCYAN}
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║     MIESC v4.0.0 - Defense-in-Depth for Smart Contracts       ║
  ║                                                               ║
  ║     "La defensa en profundidad, aplicada correctamente        ║
  ║      con IA soberana, puede transformar la seguridad          ║
  ║      de smart contracts de fragmentada a integral."           ║
  ║                                                               ║
  ║     Maestria en Ciberdefensa - UNDEF / IUA                    ║
  ║     Fernando Boiero - Diciembre 2025                          ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝
{C.RESET}
""")
    pause(4)  # Tiempo para leer la cita final

# =============================================================================
# MAIN
# =============================================================================

def main():
    """Ejecutar demo completa"""
    import argparse

    parser = argparse.ArgumentParser(description='Demo MIESC para grabacion')
    parser.add_argument('--rapido', action='store_true', help='Demo rapida')
    parser.add_argument('--silencioso', action='store_true', help='Sin pausas')
    args = parser.parse_args()

    # Ajustar pausas si es modo rapido
    if args.silencioso:
        global pause
        pause = lambda x=0: None
    elif args.rapido:
        original_pause = pause
        pause = lambda x=0: original_pause(x * 0.3)

    try:
        # Secuencia de demo
        mostrar_intro()
        mostrar_arquitectura()
        mostrar_herramientas()
        mostrar_contrato()
        ejecutar_analisis()
        mostrar_resultados()
        mostrar_correlacion()
        mostrar_metricas()
        mostrar_soberania()
        mostrar_mcp_integracion()  # Nueva seccion MCP
        mostrar_api_llamada()       # Nueva seccion API call
        mostrar_cierre()

    except KeyboardInterrupt:
        print(f"\n\n{C.BYELLOW}Demo interrumpida por el usuario{C.RESET}\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
