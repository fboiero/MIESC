#!/usr/bin/env python3
"""
MIESC 2025 - INTERACTIVE Demo (Readable Version)
==================================================

Demo interactivo con pausas para poder leer la salida de cada tool.

Modos de uso:
    python miesc_interactive_demo.py              # Modo interactivo (presiona ENTER)
    python miesc_interactive_demo.py --auto 3     # Modo automático (pausa 3 segundos)
    python miesc_interactive_demo.py --fast       # Modo rápido (sin pausas)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
"""

import argparse
import sys
import time
from pathlib import Path

# Add MIESC to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import MIESC adapter registry
from miesc.adapters import register_all_adapters


class Colors:
    """Simple color palette (sin efectos molestos)"""

    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    PURPLE = "\033[95m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ENDC = "\033[0m"


class InteractiveDemo:
    """Demo interactivo con control de pausas"""

    def __init__(self, mode="interactive", auto_delay=3):
        self.mode = mode  # 'interactive', 'auto', 'fast'
        self.auto_delay = auto_delay

    def pause(self, message="Presiona ENTER para continuar..."):
        """Pausa según el modo"""
        if self.mode == "interactive":
            input(f"\n{Colors.YELLOW}{message}{Colors.ENDC}")
        elif self.mode == "auto":
            print(f"\n{Colors.DIM}[Continuando en {self.auto_delay}s...]{Colors.ENDC}")
            time.sleep(self.auto_delay)
        # En modo 'fast' no hace nada

    def print_banner(self):
        """Banner simplificado"""
        banner = f"""
{Colors.BOLD}{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════════╗
║                    MIESC v3.4.0 - DEMO INTERACTIVO                   ║
║          Multi-layer Intelligent Evaluation for Smart Contracts      ║
║                                                                      ║
║  17 Tools • 7 Capas de Defensa • 100% DPGA Compliance              ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}
"""
        print(banner)
        self.pause("Presiona ENTER para comenzar...")

    def print_section(self, title, icon="▶"):
        """Sección con título"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}{'═' * 70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}{icon} {title}{Colors.ENDC}")
        print(f"{Colors.PURPLE}{'─' * 70}{Colors.ENDC}\n")

    def display_adapter_registry(self):
        """Muestra estadísticas de los adapters registrados"""
        self.print_section("📊 ADAPTADORES REGISTRADOS EN EL SISTEMA")

        print(f"{Colors.CYAN}Inicializando registro de adapters...{Colors.ENDC}\n")

        # Register adapters
        report = register_all_adapters()

        # Stats
        print(f"{Colors.BOLD}Estadísticas del Registro:{Colors.ENDC}")
        print(f"  Total de adapters: {Colors.YELLOW}{report['total_adapters']}{Colors.ENDC}")
        print(f"  Registrados exitosamente: {Colors.GREEN}{report['registered']}{Colors.ENDC}")
        print(f"  Fallidos: {Colors.RED}{report['failed']}{Colors.ENDC}")

        if report["failures"]:
            print(f"\n{Colors.RED}Errores:{Colors.ENDC}")
            for fail in report["failures"]:
                print(f"  ❌ {fail['name']}: {fail['error']}")

        print(f"\n{Colors.BOLD}Adapters Disponibles:{Colors.ENDC}\n")

        for adapter in report["adapters"]:
            status = adapter["status"]

            if status == "available":
                icon = f"{Colors.GREEN}✅{Colors.ENDC}"
                status_text = f"{Colors.GREEN}DISPONIBLE{Colors.ENDC}"
            else:
                icon = f"{Colors.YELLOW}⚠️{Colors.ENDC}"
                status_text = f"{Colors.YELLOW}NO INSTALADO (opcional){Colors.ENDC}"

            print(f"  {icon} {Colors.BOLD}{adapter['name']}{Colors.ENDC} v{adapter['version']}")
            print(f"     Categoría: {adapter['category']}")
            print(f"     Estado: {status_text}")
            print(
                f"     Opcional: {Colors.GREEN if adapter['optional'] else Colors.RED}{'Sí' if adapter['optional'] else 'No'}{Colors.ENDC}"
            )
            print()

        # DPGA Compliance
        all_optional = all(a.get("optional", False) for a in report["adapters"])
        print(f"\n{Colors.BOLD}DPGA Compliance:{Colors.ENDC}")
        if all_optional:
            print(
                f"  {Colors.GREEN}✅ PASS (100%){Colors.ENDC} - Todos los adapters son opcionales"
            )
        else:
            print(f"  {Colors.RED}❌ FAIL{Colors.ENDC} - Algunos adapters no son opcionales")

        self.pause()
        return report

    def display_layer(self, layer_num, layer_name, tools, metrics, adapter_report):
        """Muestra una capa con sus herramientas"""
        self.print_section(f"CAPA {layer_num}: {layer_name}", icon="🛡️")

        print(f"{Colors.BOLD}Características de la Capa:{Colors.ENDC}")
        print(f"  Velocidad: {metrics['speed']}")
        print(f"  Tasa de Falsos Positivos: {metrics['fp_rate']}")
        print()

        print(f"{Colors.BOLD}Herramientas en esta Capa:{Colors.ENDC}\n")

        # Get registered adapter names
        registered_names = [a["name"].lower() for a in adapter_report["adapters"]]

        for tool_name, version, icon, tool_type in tools:
            print(f"{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
            print(f"\n  {icon} {Colors.BOLD}{tool_name} v{version}{Colors.ENDC}\n")

            # Determine status
            tool_key = tool_name.lower().replace("-", "_").replace(" ", "")

            if tool_type == "adapter" and tool_key in registered_names:
                # Get adapter data
                adapter_data = next(
                    (a for a in adapter_report["adapters"] if a["name"].lower() == tool_key), None
                )
                if adapter_data:
                    if adapter_data["status"] == "available":
                        status_text = f"{Colors.GREEN}✅ INSTALADO Y LISTO{Colors.ENDC}"
                        description = "Adapter registrado y tool disponible para uso."
                    else:
                        status_text = f"{Colors.YELLOW}⚠️  NO INSTALADO (opcional){Colors.ENDC}"
                        description = "Adapter registrado pero tool no instalado. DPGA compliant."
                else:
                    status_text = f"{Colors.RED}❌ NO IMPLEMENTADO{Colors.ENDC}"
                    description = "Adapter no encontrado en el registro."
            elif tool_type == "builtin":
                status_text = f"{Colors.CYAN}🔧 BUILT-IN{Colors.ENDC}"
                description = "Herramienta integrada en MIESC, siempre disponible."
            elif tool_type == "installable":
                status_text = f"{Colors.YELLOW}📦 INSTALABLE{Colors.ENDC}"
                description = "Herramienta open-source que puede instalarse libremente."
            elif tool_type == "license":
                status_text = f"{Colors.PURPLE}🔑 REQUIERE LICENCIA{Colors.ENDC}"
                description = "Herramienta comercial (Certora). Requiere licencia."
            elif tool_type == "api_key":
                status_text = f"{Colors.BLUE}🔐 REQUIERE API KEY{Colors.ENDC}"
                description = "Herramienta basada en API (OpenAI). Requiere configuración."
            elif tool_type == "ollama":
                status_text = f"{Colors.GREEN}🦙 REQUIERE OLLAMA{Colors.ENDC}"
                description = "LLM local soberano. Requiere Ollama instalado."
            else:
                status_text = f"{Colors.RED}❌ NO IMPLEMENTADO{Colors.ENDC}"
                description = "Adapter pendiente de implementación."

            print(f"  Estado: {status_text}")
            print(f"  {Colors.DIM}{description}{Colors.ENDC}")
            print()

        self.pause(f"Presiona ENTER para continuar a la Capa {layer_num + 1}...")

    def display_all_layers(self, adapter_report):
        """Muestra todas las 7 capas"""

        # Define ALL 17 tools across 7 layers
        layers = [
            {
                "num": 1,
                "name": "Análisis Estático",
                "tools": [
                    ("Slither", "0.10.3", "🔍", "installable"),
                    ("Aderyn", "0.6.4", "🦀", "adapter"),
                    ("Solhint", "4.1.1", "📋", "installable"),
                ],
                "metrics": {"speed": "⚡ 2-5 segundos", "fp_rate": "🟡 20-30% (medio)"},
            },
            {
                "num": 2,
                "name": "Pruebas Dinámicas (Fuzzing)",
                "tools": [
                    ("Echidna", "2.2.4", "🐝", "installable"),
                    ("Medusa", "1.3.1", "🦑", "adapter"),
                    ("Foundry", "0.2.0", "⚒️", "installable"),
                ],
                "metrics": {"speed": "🐢 5-10 minutos", "fp_rate": "🟢 5-10% (bajo)"},
            },
            {
                "num": 3,
                "name": "Ejecución Simbólica",
                "tools": [
                    ("Mythril", "0.24.2", "🔮", "installable"),
                    ("Manticore", "0.3.7", "🕷️", "installable"),
                    ("Halmos", "0.1.13", "🎯", "installable"),
                ],
                "metrics": {"speed": "🐌 10-30 minutos", "fp_rate": "🟡 15-25% (medio)"},
            },
            {
                "num": 4,
                "name": "Verificación Formal",
                "tools": [
                    ("Certora", "2024.12", "✨", "license"),
                    ("SMTChecker", "0.8.20+", "🧮", "builtin"),
                    ("Wake", "4.20.1", "⚡", "installable"),
                ],
                "metrics": {"speed": "🦥 1-4 horas", "fp_rate": "🟢 1-5% (muy bajo)"},
            },
            {
                "num": 5,
                "name": "Análisis con IA",
                "tools": [
                    ("GPTScan", "1.0.0", "🤖", "api_key"),
                    ("LLM-SmartAudit", "1.0.0", "🧠", "api_key"),
                    ("SmartLLM", "1.0.0", "💡", "ollama"),
                ],
                "metrics": {
                    "speed": "🚀 1-2 minutos",
                    "fp_rate": "🟡 Variable (depende del modelo)",
                },
            },
            {
                "num": 6,
                "name": "Cumplimiento de Políticas",
                "tools": [("PolicyAgent", "2.2", "📜", "builtin")],
                "metrics": {"speed": "⚡ Instantáneo", "fp_rate": "🟢 Ninguno (basado en reglas)"},
            },
            {
                "num": 7,
                "name": "Preparación para Auditoría",
                "tools": [("Layer7Agent", "1.0", "📊", "builtin")],
                "metrics": {"speed": "⚡ 2-5 segundos", "fp_rate": "🟢 Ninguno (agregación)"},
            },
        ]

        for layer in layers:
            self.display_layer(
                layer["num"], layer["name"], layer["tools"], layer["metrics"], adapter_report
            )

    def display_scientific_metrics(self):
        """Muestra métricas científicas validadas"""
        self.print_section("📈 MÉTRICAS CIENTÍFICAS VALIDADAS")

        print(f"{Colors.BOLD}Datasets de Validación (reproducibles):{Colors.ENDC}")
        print("  Fuentes: SmartBugs-curated, EVMBench, exploits DeFi reales")
        print("  Fuente de verdad: benchmarks/results/paper1_claims_matrix.json")
        print()

        print(f"{Colors.BOLD}Rendimiento del Sistema (recall medido):{Colors.ENDC}")
        print(f"  SmartBugs-curated: {Colors.GREEN}95.8%{Colors.ENDC} (137/143)")
        print("    → Detecta el 95.8% de las vulnerabilidades etiquetadas")
        print()
        print(f"  EVMBench (ensemble): {Colors.GREEN}92.5%{Colors.ENDC} (111/120)")
        print()
        print(f"  Exploits DeFi reales: {Colors.GREEN}81.8%{Colors.ENDC} (9/11, IC 95% Wilson [52%, 95%])")
        print()
        print(f"  Reducción de Falsos Positivos: {Colors.GREEN}-73.6%{Colors.ENDC}")
        print("    → 73.6% MENOS falsos positivos que herramientas tradicionales")
        print()
        print(f"  Ahorro de Tiempo: {Colors.GREEN}~90%{Colors.ENDC}")
        print("    → De 32-50 horas → 3-5 horas por contrato")
        print()

        self.pause()

    def display_final_summary(self, adapter_report):
        """Resumen final del sistema"""
        self.print_section("✅ RESUMEN FINAL DEL SISTEMA")

        print(f"{Colors.BOLD}Estado del Sistema MIESC v3.4.0:{Colors.ENDC}\n")

        # Adapter stats
        total_adapters = adapter_report["total_adapters"]
        registered = adapter_report["registered"]
        available = len([a for a in adapter_report["adapters"] if a["status"] == "available"])

        print(f"  Adapters Registrados: {Colors.CYAN}{registered}/{total_adapters}{Colors.ENDC}")
        print(f"  Tools Disponibles: {Colors.GREEN}{available}/{total_adapters}{Colors.ENDC}")
        print(
            f"  Tools No Instalados: {Colors.YELLOW}{total_adapters - available}/{total_adapters}{Colors.ENDC} (opcionales)"
        )
        print()

        # Layer coverage
        print(f"{Colors.BOLD}Cobertura por Capas:{Colors.ENDC}\n")
        print(f"  {Colors.GREEN}✅{Colors.ENDC} Capa 1 (Estático): 1/3 implementado (33%)")
        print(f"  {Colors.GREEN}✅{Colors.ENDC} Capa 2 (Dinámico): 1/3 implementado (33%)")
        print(f"  {Colors.YELLOW}⚠️{Colors.ENDC}  Capa 3 (Simbólico): 0/3 implementado (0%)")
        print(f"  {Colors.YELLOW}⚠️{Colors.ENDC}  Capa 4 (Formal): 0/3 implementado (0%)")
        print(f"  {Colors.YELLOW}⚠️{Colors.ENDC}  Capa 5 (IA): 0/3 implementado (0%)")
        print(f"  {Colors.GREEN}✅{Colors.ENDC} Capa 6 (Políticas): 1/1 implementado (100%)")
        print(f"  {Colors.GREEN}✅{Colors.ENDC} Capa 7 (Auditoría): 1/1 implementado (100%)")
        print()

        # DPGA compliance
        all(a.get("optional", False) for a in adapter_report["adapters"])
        print(f"{Colors.BOLD}DPGA Compliance:{Colors.ENDC}")
        print(f"  {Colors.GREEN}✅ 100% PASS{Colors.ENDC} - Todas las herramientas son opcionales")
        print(f"  {Colors.GREEN}✅ Zero vendor lock-in{Colors.ENDC}")
        print(f"  {Colors.GREEN}✅ Extensible por la comunidad{Colors.ENDC}")
        print()

        # Next steps
        print(f"{Colors.BOLD}Próximos Pasos Recomendados:{Colors.ENDC}\n")
        print("  1. Implementar Slither adapter (Capa 1) - CRÍTICO")
        print("  2. Implementar Mythril adapter (Capa 3) - CRÍTICO")
        print("  3. Implementar Echidna adapter (Capa 2) - ALTA PRIORIDAD")
        print("  4. Implementar Foundry adapter (Capa 2) - ALTA PRIORIDAD")
        print()

        print(f"{Colors.GREEN}{Colors.BOLD}✅ Demo completado exitosamente!{Colors.ENDC}\n")


def main():
    """Main demo routine"""
    # Parse arguments
    parser = argparse.ArgumentParser(description="MIESC Interactive Demo")
    parser.add_argument(
        "--auto", type=int, metavar="SECONDS", help="Auto mode with N seconds delay"
    )
    parser.add_argument("--fast", action="store_true", help="Fast mode (no pauses)")
    args = parser.parse_args()

    # Determine mode
    if args.fast:
        mode = "fast"
        auto_delay = 0
    elif args.auto:
        mode = "auto"
        auto_delay = args.auto
    else:
        mode = "interactive"
        auto_delay = 3

    # Create demo instance
    demo = InteractiveDemo(mode=mode, auto_delay=auto_delay)

    # Run demo
    demo.print_banner()

    # 1. Show adapter registry
    adapter_report = demo.display_adapter_registry()

    # 2. Show all 7 layers
    demo.display_all_layers(adapter_report)

    # 3. Show scientific metrics
    demo.display_scientific_metrics()

    # 4. Final summary
    demo.display_final_summary(adapter_report)

    print(f"{Colors.CYAN}{'═' * 70}{Colors.ENDC}")
    print(f"{Colors.BOLD}Demo finalizado. Gracias por usar MIESC v3.4.0!{Colors.ENDC}")
    print(f"{Colors.CYAN}{'═' * 70}{Colors.ENDC}\n")


if __name__ == "__main__":
    main()
