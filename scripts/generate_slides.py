#!/usr/bin/env python3
"""
Generador de Presentacion HTML para Defensa de Tesis MIESC
Genera slides interactivos con reveal.js

Uso:
    python generate_slides.py
    # Abre presentation.html en el navegador
"""

import os
from pathlib import Path
from datetime import datetime

# Configuracion
OUTPUT_FILE = "presentation.html"
TITLE = "MIESC - Defensa de Tesis"
AUTHOR = "Fernando Boiero"
INSTITUTION = "Universidad de la Defensa Nacional (UNDEF) - IUA"

# Template HTML con reveal.js CDN
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/dist/reset.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/dist/reveal.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/dist/theme/black.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/plugin/highlight/monokai.css">
    <style>
        :root {{
            --r-background-color: #0f0f23;
            --r-main-color: #eaeaea;
            --r-heading-color: #00d4ff;
            --r-link-color: #00ff9d;
        }}
        .reveal h1 {{ color: #00d4ff; text-shadow: 0 0 20px rgba(0,212,255,0.5); }}
        .reveal h2 {{ color: #00ff9d; }}
        .reveal h3 {{ color: #ff6b6b; }}
        .reveal table {{ font-size: 0.7em; margin: 0 auto; }}
        .reveal table th {{ background: #1a1a3e; color: #00d4ff; }}
        .reveal table td {{ background: #0a0a1e; }}
        .reveal pre {{ font-size: 0.55em; }}
        .reveal .highlight {{ color: #ff6b6b; font-weight: bold; }}
        .reveal .success {{ color: #00ff9d; }}
        .reveal .cyber {{ color: #00d4ff; }}
        .reveal blockquote {{
            background: rgba(0,212,255,0.1);
            border-left: 4px solid #00d4ff;
            padding: 1em;
        }}
        .columns {{ display: flex; gap: 2em; }}
        .columns > div {{ flex: 1; }}
        .metric-box {{
            background: linear-gradient(135deg, #1a1a3e, #0a0a1e);
            border: 1px solid #00d4ff;
            border-radius: 10px;
            padding: 1em;
            margin: 0.5em;
            text-align: center;
        }}
        .metric-value {{ font-size: 2em; color: #00ff9d; font-weight: bold; }}
        .metric-label {{ font-size: 0.8em; color: #888; }}
        .logo-banner {{
            font-family: monospace;
            color: #00d4ff;
            text-shadow: 0 0 10px rgba(0,212,255,0.8);
        }}
    </style>
</head>
<body>
    <div class="reveal">
        <div class="slides">
            {slides}
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/dist/reveal.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/plugin/notes/notes.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/plugin/highlight/highlight.js"></script>
    <script>
        Reveal.initialize({{
            hash: true,
            slideNumber: 'c/t',
            showSlideNumber: 'all',
            transition: 'slide',
            backgroundTransition: 'fade',
            plugins: [ RevealHighlight, RevealNotes ]
        }});
    </script>
</body>
</html>
"""

# Contenido de las slides
SLIDES_CONTENT = """
<!-- SLIDE 1: Portada -->
<section data-background-gradient="linear-gradient(135deg, #0f0f23, #1a1a3e)">
    <pre class="logo-banner" style="font-size: 0.4em; text-align: center; background: none; box-shadow: none;">
███╗   ███╗██╗███████╗███████╗ ██████╗
████╗ ████║██║██╔════╝██╔════╝██╔════╝
██╔████╔██║██║█████╗  ███████╗██║
██║╚██╔╝██║██║██╔══╝  ╚════██║██║
██║ ╚═╝ ██║██║███████╗███████║╚██████╗
╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝
    </pre>
    <h2>Multi-layer Intelligent Evaluation<br>for Smart Contracts</h2>
    <h4>Un Enfoque de Ciberdefensa para la Seguridad<br>de Contratos Inteligentes</h4>
    <p style="margin-top: 2em; color: #888;">
        <strong>Ing. Fernando Boiero</strong><br>
        Maestria en Ciberdefensa - UNDEF/IUA Cordoba<br>
        Diciembre 2025
    </p>
</section>

<!-- SLIDE 2: Agenda -->
<section>
    <h2>Agenda</h2>
    <div style="text-align: left; margin: 0 auto; width: 60%;">
        <ol>
            <li>Contexto y Motivacion</li>
            <li>Problema de Investigacion</li>
            <li>Objetivos</li>
            <li>Marco Teorico</li>
            <li>Solucion Propuesta: MIESC</li>
            <li>Arquitectura de 7 Capas</li>
            <li>Resultados Experimentales</li>
            <li>Demo en Vivo</li>
            <li>Conclusiones</li>
            <li>Trabajos Futuros</li>
        </ol>
    </div>
</section>

<!-- SLIDE 3: Contexto -->
<section data-background-color="#1a0000">
    <h1>1. Contexto y Motivacion</h1>
    <h3>El Ciberespacio como Dominio Estrategico</h3>
</section>

<!-- SLIDE 4: La Amenaza -->
<section>
    <h2>La Amenaza es Real</h2>
    <div class="metric-box" style="display: inline-block;">
        <div class="metric-value">$7.8B+</div>
        <div class="metric-label">Perdidos en smart contracts (2016-2024)</div>
    </div>
    <table style="margin-top: 1em;">
        <tr><th>Ano</th><th>Incidente</th><th>Perdida</th><th>Vulnerabilidad</th></tr>
        <tr><td>2016</td><td>The DAO</td><td style="color:#ff6b6b">$60M</td><td>Reentrancy</td></tr>
        <tr><td>2017</td><td>Parity Wallet</td><td style="color:#ff6b6b">$280M</td><td>Access Control</td></tr>
        <tr><td>2022</td><td>Ronin Bridge</td><td style="color:#ff6b6b">$625M</td><td>Key Compromise</td></tr>
        <tr><td>2023</td><td>Euler Finance</td><td style="color:#ff6b6b">$197M</td><td>Flash Loan</td></tr>
    </table>
</section>

<!-- SLIDE 5: Problema Fragmentacion -->
<section>
    <h2>El Problema: Fragmentacion</h2>
    <div class="columns">
        <div>
            <h4 style="color:#00d4ff">Herramientas Existentes</h4>
            <ul style="font-size: 0.8em;">
                <li>Analisis estatico (Slither)</li>
                <li>Fuzzers (Echidna)</li>
                <li>Ejecucion simbolica (Mythril)</li>
                <li>Verificacion formal (Certora)</li>
                <li>IA (GPTScan)</li>
            </ul>
        </div>
        <div>
            <h4 style="color:#ff6b6b">Problemas</h4>
            <ul style="font-size: 0.8em;">
                <li>Salidas incompatibles</li>
                <li>Nomenclaturas diferentes</li>
                <li>Cobertura incompleta</li>
                <li><strong>Ninguna detecta &gt;70%</strong></li>
            </ul>
        </div>
    </div>
</section>

<!-- SLIDE 6: Problema Soberania -->
<section>
    <h2>El Problema: Soberania de Datos</h2>
    <blockquote>
        En ciberdefensa, la confidencialidad del codigo es <strong>CRITICA</strong>
    </blockquote>
    <p>Las soluciones con IA comercial (OpenAI, Anthropic) comprometen:</p>
    <ul>
        <li><span class="highlight">Propiedad intelectual:</span> Codigo enviado a terceros</li>
        <li><span class="highlight">Dependencia externa:</span> Perdida de capacidad operativa</li>
        <li><span class="highlight">Cumplimiento normativo:</span> GDPR, LGPD</li>
    </ul>
</section>

<!-- SLIDE 7: Planteamiento -->
<section data-background-color="#001a00">
    <h1>2. Problema de Investigacion</h1>
</section>

<!-- SLIDE 8: Problemas Especificos -->
<section>
    <h2>Problemas Especificos</h2>
    <div style="text-align: left; font-size: 0.85em;">
        <p><strong>P1:</strong> No existe un framework que integre coherentemente las principales herramientas.</p>
        <p><strong>P2:</strong> Las salidas utilizan nomenclaturas y formatos incompatibles.</p>
        <p><strong>P3:</strong> Las soluciones con IA dependen de servicios externos.</p>
        <p><strong>P4:</strong> No existe una arquitectura que aplique <span class="cyber">Defense-in-Depth</span> a smart contracts.</p>
    </div>
</section>

<!-- SLIDE 9: Objetivos -->
<section>
    <h2>Objetivos</h2>
    <h4 style="color:#00d4ff">Objetivo General</h4>
    <p style="font-size: 0.8em;">Desarrollar un framework de codigo abierto que integre multiples herramientas en una arquitectura de defensa en profundidad, con IA soberana.</p>
    <h4 style="color:#00ff9d; margin-top: 1em;">Objetivos Especificos</h4>
    <ol style="font-size: 0.75em;">
        <li>Integrar <strong>25 herramientas</strong> en <strong>7 capas</strong></li>
        <li>Normalizar salidas a SWC/CWE/OWASP</li>
        <li>Implementar IA <strong>100% local</strong> (Ollama)</li>
        <li>Cumplir estandares Digital Public Good</li>
        <li>Integrar via MCP Protocol</li>
    </ol>
</section>

<!-- SLIDE 10: Marco Teorico -->
<section data-background-color="#0a001a">
    <h1>3. Marco Teorico</h1>
</section>

<!-- SLIDE 11: Fundamentos -->
<section>
    <h2>Fundamentos Teoricos</h2>
    <div class="columns">
        <div class="metric-box">
            <h4>Defense-in-Depth</h4>
            <p style="font-size: 0.7em;">Saltzer & Schroeder (1975)</p>
            <p style="font-size: 0.65em;">"Multiples capas independientes de defensa"</p>
        </div>
        <div class="metric-box">
            <h4>Multi-Tool Analysis</h4>
            <p style="font-size: 0.7em;">Durieux et al. (2020)</p>
            <p style="font-size: 0.65em;">"La combinacion mejora significativamente la deteccion"</p>
        </div>
    </div>
</section>

<!-- SLIDE 12: Solucion -->
<section data-background-color="#001a1a">
    <h1>4. Solucion Propuesta</h1>
    <h2>MIESC v4.0.0</h2>
</section>

<!-- SLIDE 13: MIESC Vision -->
<section>
    <h2>MIESC: Vision General</h2>
    <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 0.5em;">
        <div class="metric-box" style="width: 150px;">
            <div class="metric-value">25</div>
            <div class="metric-label">Herramientas</div>
        </div>
        <div class="metric-box" style="width: 150px;">
            <div class="metric-value">7</div>
            <div class="metric-label">Capas</div>
        </div>
        <div class="metric-box" style="width: 150px;">
            <div class="metric-value">100%</div>
            <div class="metric-label">Recall</div>
        </div>
        <div class="metric-box" style="width: 150px;">
            <div class="metric-value">$0</div>
            <div class="metric-label">Costo</div>
        </div>
    </div>
    <p style="margin-top: 1em;">
        <span class="success">IA Soberana</span> con Ollama - codigo NUNCA sale de tu maquina
    </p>
</section>

<!-- SLIDE 14: Arquitectura -->
<section>
    <h2>Arquitectura de 7 Capas</h2>
    <pre style="font-size: 0.5em; text-align: center;"><code>
        SMART CONTRACT
              │
       [CoordinatorAgent]
              │
    ┌────┬────┬────┬────┬────┬────┬────┐
    │ L1 │ L2 │ L3 │ L4 │ L5 │ L6 │ L7 │
    │Static│Dyn│Symb│Inv│Form│Prop│ AI │
    └────┴────┴────┴────┴────┴────┴────┘
              │
       [NORMALIZATION]
              │
    [REPORT: JSON/HTML/PDF]
    </code></pre>
</section>

<!-- SLIDE 15: Capas Detalle -->
<section>
    <h2>Las 7 Capas de Defensa</h2>
    <table style="font-size: 0.65em;">
        <tr><th>Capa</th><th>Tipo</th><th>Herramientas</th><th>Tiempo</th></tr>
        <tr><td>1</td><td>Estatico</td><td>Slither, Solhint, Securify2</td><td>~5s</td></tr>
        <tr><td>2</td><td>Fuzzing</td><td>Echidna, Medusa, DogeFuzz</td><td>~30s</td></tr>
        <tr><td>3</td><td>Simbolico</td><td>Mythril, Manticore, Halmos</td><td>1-5min</td></tr>
        <tr><td>4-5</td><td>Formal</td><td>SMTChecker, Certora, PropertyGPT</td><td>2-10min</td></tr>
        <tr><td>6-7</td><td>IA</td><td>SmartLLM, GPTScan, ThreatModel</td><td>30-60s</td></tr>
    </table>
</section>

<!-- SLIDE 16: Resultados -->
<section data-background-color="#1a1a00">
    <h1>5. Resultados Experimentales</h1>
</section>

<!-- SLIDE 17: Metricas -->
<section>
    <h2>Resultados: Comparativa</h2>
    <table>
        <tr><th>Herramienta</th><th>Precision</th><th>Recall</th><th>F1-Score</th></tr>
        <tr><td>Slither (individual)</td><td>74%</td><td>66%</td><td>0.70</td></tr>
        <tr><td>Mythril (individual)</td><td>68%</td><td>59%</td><td>0.63</td></tr>
        <tr><td>Echidna (individual)</td><td>71%</td><td>62%</td><td>0.66</td></tr>
        <tr style="background: rgba(0,255,157,0.2);"><td><strong>MIESC (7 capas)</strong></td><td><strong>94.5%</strong></td><td><strong>92.8%</strong></td><td><strong>0.936</strong></td></tr>
    </table>
    <div class="metric-box" style="margin-top: 1em; display: inline-block;">
        <div class="metric-value">+40.8%</div>
        <div class="metric-label">Mejora vs mejor individual</div>
    </div>
</section>

<!-- SLIDE 18: Metricas v4 -->
<section>
    <h2>Evolucion v3.5 → v4.0</h2>
    <table style="font-size: 0.8em;">
        <tr><th>Metrica</th><th>v3.5</th><th>v4.0</th><th>Mejora</th></tr>
        <tr><td>Precision</td><td>89.47%</td><td>94.5%</td><td style="color:#00ff9d">+5.03pp</td></tr>
        <tr><td>Recall</td><td>86.2%</td><td>92.8%</td><td style="color:#00ff9d">+6.6pp</td></tr>
        <tr><td>FP Rate</td><td>10.53%</td><td>5.5%</td><td style="color:#00ff9d">-48%</td></tr>
        <tr><td>Adapters</td><td>22</td><td>25</td><td style="color:#00ff9d">+13.6%</td></tr>
    </table>
</section>

<!-- SLIDE 19: Demo -->
<section data-background-color="#001a00">
    <h1>6. Demo en Vivo</h1>
    <pre><code class="bash">python demo_thesis_defense.py --quick --auto</code></pre>
</section>

<!-- SLIDE 20: Vulnerabilidad -->
<section>
    <h2>Vulnerabilidad Detectada</h2>
    <pre><code class="solidity">function withdraw() public {
    uint256 balance = balances[msg.sender];
    require(balance > 0, "No balance");

    // VULNERABILIDAD: External call ANTES de state update
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");

    // State update DESPUES - puede ser re-entered!
    balances[msg.sender] = 0;
}</code></pre>
    <p><strong>SWC-107:</strong> Reentrancy | <span class="highlight">Severidad: CRITICAL</span></p>
</section>

<!-- SLIDE 21: Conclusiones -->
<section data-background-color="#0a0a1a">
    <h1>7. Conclusiones</h1>
</section>

<!-- SLIDE 22: Objetivos Alcanzados -->
<section>
    <h2>Objetivos Alcanzados</h2>
    <table style="font-size: 0.7em;">
        <tr><th>Objetivo</th><th>Resultado</th><th>Estado</th></tr>
        <tr><td>Integrar herramientas</td><td>25/25 (100%)</td><td style="color:#00ff9d">CUMPLIDO</td></tr>
        <tr><td>7 capas defensa</td><td>7 implementadas</td><td style="color:#00ff9d">CUMPLIDO</td></tr>
        <tr><td>Normalizar SWC/CWE/OWASP</td><td>97.1% precision</td><td style="color:#00ff9d">CUMPLIDO</td></tr>
        <tr><td>Costo $0</td><td>$0/auditoria</td><td style="color:#00ff9d">CUMPLIDO</td></tr>
        <tr><td>Mejorar deteccion >20%</td><td>+40.8%</td><td style="color:#00d4ff">SUPERADO</td></tr>
        <tr><td>Reducir duplicados >40%</td><td>66%</td><td style="color:#00d4ff">SUPERADO</td></tr>
    </table>
</section>

<!-- SLIDE 23: Contribuciones -->
<section>
    <h2>Contribuciones Principales</h2>
    <ol style="font-size: 0.8em; text-align: left;">
        <li><strong>Arquitectura de 7 Capas:</strong> Primera implementacion Defense-in-Depth para smart contracts</li>
        <li><strong>Protocolo ToolAdapter:</strong> Interfaz unificada para herramientas heterogeneas</li>
        <li><strong>Normalizacion Triple:</strong> Mapeo automatico SWC/CWE/OWASP</li>
        <li><strong>IA Soberana:</strong> Backend local con Ollama</li>
        <li><strong>MCP Server:</strong> Primera herramienta con Model Context Protocol</li>
        <li><strong>Open Source:</strong> Digital Public Good (DPGA)</li>
    </ol>
</section>

<!-- SLIDE 24: Trabajos Futuros -->
<section data-background-color="#1a0a1a">
    <h1>8. Trabajos Futuros</h1>
</section>

<!-- SLIDE 25: Roadmap -->
<section>
    <h2>Roadmap v5.0</h2>
    <table style="font-size: 0.75em;">
        <tr><th>Feature</th><th>Descripcion</th><th>Impacto</th></tr>
        <tr><td>PyPI</td><td>pip install miesc</td><td>Alto</td></tr>
        <tr><td>Multi-chain</td><td>Solana, Cairo, Soroban</td><td>Alto</td></tr>
        <tr><td>VSCode</td><td>Extension IDE</td><td>Medio</td></tr>
        <tr><td>Fine-tuning</td><td>Modelos especializados</td><td>Alto</td></tr>
        <tr><td>Runtime</td><td>Monitoreo post-deployment</td><td>Alto</td></tr>
    </table>
</section>

<!-- SLIDE 26: Gracias -->
<section data-background-gradient="linear-gradient(135deg, #0f0f23, #1a1a3e)">
    <h1>Gracias</h1>
    <h2>Preguntas?</h2>
    <p style="margin-top: 2em; font-size: 0.8em;">
        <strong>Fernando Boiero</strong><br>
        fboiero@frvm.utn.edu.ar<br>
        github.com/fboiero/MIESC
    </p>
</section>
"""

def generate_presentation():
    """Genera la presentacion HTML"""
    html_content = HTML_TEMPLATE.format(
        title=TITLE,
        slides=SLIDES_CONTENT
    )

    output_path = Path(__file__).parent / OUTPUT_FILE
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"Presentacion generada: {output_path}")
    print(f"\nPara ver la presentacion:")
    print(f"  open {OUTPUT_FILE}")
    print(f"\nControles:")
    print(f"  - Flechas: Navegar slides")
    print(f"  - ESC: Vista general")
    print(f"  - F: Pantalla completa")
    print(f"  - S: Vista presentador")

    return output_path

if __name__ == "__main__":
    generate_presentation()
