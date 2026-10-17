#!/usr/bin/env python3
"""Render the thesis delivery PDF with the DD 047/20 Art. 24 format.

Assembles docs/tesis/*.md (ES) in reglamento order and runs pandoc -> XeLaTeX:
A4, Arial 12 pt, 1.5 line spacing, margins left 3 cm / top-right-bottom 2 cm,
arabic page numbers bottom-centre from the 2nd page (cover unnumbered), a table of
contents, and SVG figures embedded via rsvg-convert.

Usage: python scripts/render_thesis_pdf.py [--lang es]
Output: docs/tesis/build/tesis_miesc_es.pdf
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESIS = ROOT / "docs" / "tesis"
BUILD = TESIS / "build"

# Reglamento order (Art. 17): cover, index, abstract + front matter, chapters,
# appendices, references, glossary. The cover comes first and stays unnumbered;
# the table of contents is injected right after it.
FRONT_MATTER = [
    "SECCION_PRELIMINAR.md",
    "LISTA_DE_ACRONIMOS.md",
    "LISTA_DE_FIGURAS.md",
    "LISTA_DE_TABLAS.md",
]
CHAPTERS = [
    "CAPITULO_INTRODUCCION.md",
    "CAPITULO_MARCO_TEORICO.md",
    "CAPITULO_ESTADO_DEL_ARTE.md",
    "CAPITULO_DESARROLLO.md",
    "CAPITULO_RESULTADOS.md",
    "CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md",
    "CAPITULO_JUSTIFICACION_MCP.md",
    "CAPITULO_TRABAJOS_FUTUROS.md",
]
APPENDICES = [
    "APENDICE_SALIDAS_HERRAMIENTAS.md",
    "APENDICE_CODIGO_FUENTE.md",
    "APENDICE_TECNICAS_ANALISIS.md",
]
BACK_MATTER = [
    "REFERENCIAS_BIBLIOGRAFICAS.md",
    "GLOSARIO.md",
]

HEADER_TEX = r"""
\usepackage{fontspec}
\setmainfont{Arial}
% Monospace font with box-drawing glyphs (fixes CLI-output tables in appendices).
\setmonofont{Menlo}
\usepackage[a4paper,left=3cm,top=2cm,right=2cm,bottom=2cm]{geometry}
\usepackage{setspace}
\onehalfspacing
\usepackage{fancyhdr}
\pagestyle{fancy}
\fancyhf{}
\fancyfoot[C]{\thepage}
\renewcommand{\headrulewidth}{0pt}
% Headings already carry manual numbers in the text -> disable LaTeX auto-numbering.
\setcounter{secnumdepth}{-1}
\setcounter{tocdepth}{2}
% Cover (page 1) unnumbered; arabic numbering shows from page 2 (Art. 24.4).
\AtBeginDocument{\thispagestyle{empty}}
\usepackage{graphicx}
% Cover border frame (reglamento Anexo 1).
\usepackage{tikz}
\usetikzlibrary{calc}
% Art. 24.6: figure captions below, table captions above.
\usepackage{caption}
\captionsetup[figure]{position=below}
\captionsetup[table]{position=above}
% Note: box-drawing glyphs inside code blocks are covered by \setmonofont{Menlo};
% rare diagonal glyphs in prose may still be absent if the main font lacks them.
% Tolerate over-wide code/tables instead of failing the build.
\setlength{\emergencystretch}{3em}
\usepackage{float}
"""

RAW_NEWPAGE = "\n\n```{=latex}\n\\newpage\n```\n\n"
RAW_TOC = "\n\n```{=latex}\n\\tableofcontents\n\\newpage\n```\n\n"

# Cover built per reglamento DD 047/20 Anexo N° 1 (exact font sizes): Maestría 20,
# Trabajo Final / Tesis de Posgrado 18, title 16, subtitle 14, author 14, director 13,
# place/date 12. Replaces PORTADA_TESIS.md (whose Resumen/Abstract/Datos duplicate
# SECCION_PRELIMINAR). titlepage env keeps page 1 unnumbered.
TITLEPAGE_TEX = r"""

```{=latex}
\begin{titlepage}
\begin{tikzpicture}[remember picture,overlay]
  \draw[line width=0.5pt]
    ($(current page.north west)+(2cm,-2cm)$) rectangle
    ($(current page.south east)+(-2cm,2cm)$);
\end{tikzpicture}
\centering
\vspace*{1.1cm}
\noindent\hspace{0.3cm}\includegraphics[height=2.7cm]{logo_cruc_iua.png}\hfill\includegraphics[height=2.4cm]{logo_undef.png}\hspace{0.3cm}
\par
\vspace{2.6cm}
{\fontsize{20}{24}\selectfont\textbf{MAESTRÍA EN CIBERDEFENSA}\par}
\vspace{1.0cm}
{\fontsize{18}{22}\selectfont Trabajo Final de Maestría\par}
\vspace{2.6cm}
{\fontsize{16}{20}\selectfont\textbf{MIESC: Framework Multi-capa de Integración de Herramientas para Seguridad de Smart Contracts}\par}
\vspace{0.6cm}
{\fontsize{14}{18}\selectfont\textit{Multi-layer Integration Framework for Smart Contract Security}\par}
\vspace{2.6cm}
{\fontsize{14}{18}\selectfont Ing. Fernando Boiero\par}
\vspace{0.5cm}
{\fontsize{13}{16}\selectfont Director: Mg. Eduardo Casanovas\par}
\vfill
{\fontsize{12}{15}\selectfont Córdoba, Provincia de Córdoba, Argentina — Noviembre 2025\par}
\vspace{1.2cm}
\end{titlepage}
```

"""

# Glyphs that Arial (main font) lacks and that appear in prose/tables (e.g. the
# Ch.6 sovereignty scorecard ✓/✗/◑). Mapped to font-independent LaTeX so they
# render; applied only OUTSIDE fenced code blocks (box-drawing chars inside code
# are handled by \setmonofont{Menlo} and must stay literal).
SYMBOL_MAP = {
    "✓": r"$\checkmark$",
    "✗": r"$\times$",
    "◑": r"$\circ$",
    "∈": r"$\in$",
    "⁻": r"$^{-}$",
    "ⱼ": r"$_{j}$",
    "╲": r"\textbackslash{}",
}


CODE_GLYPH_FALLBACK = {
    "╲": "\\",
    "∈": "in",
    "ⱼ": "_j",
    "⁻": "^-",
}


def _replace_symbols_outside_code(md: str) -> str:
    out: list[str] = []
    in_fence = False
    for line in md.split("\n"):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            # Glyphs the mono font lacks inside code blocks: the diagonal of one
            # ASCII-art diagram (§H.9.2) and the set/index symbols of the GNN
            # formulas (§H.7), both in APENDICE_TECNICAS_ANALISIS.md. ASCII
            # equivalents keep the blocks legible without a missing glyph.
            for src, dst in CODE_GLYPH_FALLBACK.items():
                if src in line:
                    line = line.replace(src, dst)
            out.append(line)
            continue
        for src, dst in SYMBOL_MAP.items():
            if src in line:
                line = line.replace(src, dst)
        out.append(line)
    return "\n".join(out)


# Lists whose "Pág." column holds stale, manually-estimated page numbers that cannot
# be auto-regenerated (the figures are described in tables, not LaTeX floats). Drop
# that column so the delivery PDF shows no wrong numbers, and drop the note that
# claims the numbers regenerate automatically.
# LISTA_DE_FIGURAS.md is now regenerated from the real captions without a page column,
# so only the table list still carries one.
PAGE_COLUMN_LISTS = {"LISTA_DE_TABLAS.md"}


def _drop_last_table_column(md: str) -> str:
    out: list[str] = []
    for line in md.split("\n"):
        s = line.rstrip()
        stripped = s.strip()
        if stripped.startswith("|") and stripped.endswith("|") and stripped.count("|") >= 3:
            cells = stripped.split("|")
            del cells[-2]  # remove the last data cell (the "Pág." column)
            out.append("|".join(cells))
        else:
            out.append(line)
    return "\n".join(out)


def _drop_blockquote_note(md: str) -> str:
    return "\n".join(ln for ln in md.split("\n") if not ln.lstrip().startswith(">"))


# Alphabetical lists whose "## A" … "## Z" letter headings are navigation aids inside the
# list, not sections of the thesis: keep them on the page but out of the table of contents.
LETTER_HEADING_LISTS = {"LISTA_DE_ACRONIMOS.md", "GLOSARIO.md"}
_LETTER_HEADING = re.compile(r"^(## [A-ZÑ])\s*$", re.M)


def _unlist_letter_headings(md: str) -> str:
    return _LETTER_HEADING.sub(r"\1 {.unlisted}", md)


def read(name: str) -> str:
    p = TESIS / name
    if not p.exists():
        print(f"  WARN missing: {name}", file=sys.stderr)
        return ""
    text = p.read_text(encoding="utf-8")
    if name in PAGE_COLUMN_LISTS:
        text = _drop_last_table_column(_drop_blockquote_note(text))
    if name in LETTER_HEADING_LISTS:
        text = _unlist_letter_headings(text)
    return text


def assemble() -> str:
    parts: list[str] = []
    # Cover = reglamento Anexo 1 titlepage (replaces PORTADA_TESIS.md, whose
    # Resumen/Abstract/Datos are already in SECCION_PRELIMINAR).
    parts.append(TITLEPAGE_TEX)
    parts.append(RAW_TOC)
    for group in (FRONT_MATTER, CHAPTERS, APPENDICES, BACK_MATTER):
        for name in group:
            body = read(name)
            if body:
                parts.append(body)
                parts.append(RAW_NEWPAGE)
    return _replace_symbols_outside_code("\n\n".join(parts))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang", default="es")
    args = ap.parse_args()

    for tool in ("pandoc", "xelatex", "rsvg-convert"):
        if not shutil.which(tool):
            print(f"ERROR: required tool not found: {tool}", file=sys.stderr)
            return 2

    BUILD.mkdir(parents=True, exist_ok=True)
    combined = BUILD / f"tesis_combined_{args.lang}.md"
    header = BUILD / "header_art24.tex"
    out_pdf = BUILD / f"tesis_miesc_{args.lang}.pdf"

    combined.write_text(assemble(), encoding="utf-8")
    # Let raw-LaTeX \includegraphics (e.g. the cover logo) resolve relative paths
    # against docs/tesis, since pandoc runs xelatex in a temp directory.
    header.write_text(HEADER_TEX + "\n\\graphicspath{{" + str(TESIS) + "/}}\n", encoding="utf-8")

    cmd = [
        "pandoc",
        str(combined),
        "-f",
        "markdown+raw_tex",
        "--pdf-engine=xelatex",
        f"--include-in-header={header}",
        f"--resource-path={TESIS}",
        "-V",
        "lang=es",
        "-o",
        str(out_pdf),
    ]
    print("  " + " ".join(cmd))
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode == 0:
        print(f"OK -> {out_pdf}")
    return r.returncode


if __name__ == "__main__":
    raise SystemExit(main())
