# Control de entrega — Tesis MIESC (ES)

> Documento interno de cierre. No es material público ni parte de la tesis.

- **Fecha de control:** 2026-10-20
- **Base de main:** `origin/main @ 69d2f421` (merge de PR #160, edición corregida completa)
- **Render:** `python3 scripts/render_thesis_pdf.py --docx` → `docs/tesis/build/` (gitignored)
- **Salida verificada:** PDF A4, **247 páginas**; log de render sin warnings/overfull/underfull/missing-glyph.

## Carátula (Anexo 1, DD 047/20) — p.1

Cumple: logos en las dos esquinas superiores (UCC izq., UNDEF/IUA der.), marco completo,
sin bloque de texto de instituciones, título ES + EN, autor, director, y fecha
"Córdoba, Provincia de Córdoba, Argentina — Noviembre 2025". Carátula sin número de página;
la numeración abajo-centro arranca en el Índice (marcado "1" = 2ª página física). OK.

> Nota sobre "0 warnings": el log de pandoc→xelatex no emite por defecto los avisos de
> overfull/underfull de LaTeX; la ausencia en el log es consistente con "0 warnings" pero
> el control real de desbordes de margen se hace visualmente en la lectura página por página.

## Hallazgos — página → qué → cómo se corrige

### F1 — Índice: filas A–Z de la Lista de Acrónimos y del Glosario (forma)
- **Páginas:** Índice (pp.1–2 impresas): bajo "Lista de Acrónimos y Abreviaturas" aparecen
  filas `A … 12`, `B … 12`, … `Z … 17`; ídem bajo "Glosario de Términos" (`A … 241` … `Z … 246`).
- **Qué:** las letras A–Z son separadores de navegación *dentro* de las listas alfabéticas,
  no entradas de contenido; ensucian el Índice (≈45 filas de plantilla).
- **Causa raíz (verificada):** `scripts/render_thesis_pdf.py` ya intenta ocultarlas marcándolas
  `{.unlisted}` (`_unlist_letter_headings`), pero en pandoc 3.8.3 `{.unlisted}` **solo** no
  excluye del TOC: sigue emitiendo `\subsection{}` (con `\addcontentsline`). Prueba empírica:
  `## B {.unlisted}` → `\subsection{B}` (en TOC); `## C {.unnumbered .unlisted}` → `\subsection*{C}`
  (sin `\addcontentsline`, fuera del TOC).
- **Cómo se corrige:** en `_unlist_letter_headings`, cambiar el reemplazo
  `r"\1 {.unlisted}"` → `r"\1 {.unnumbered .unlisted}"`. Solo afecta el listado del Índice;
  el cuerpo de ambas listas no cambia visualmente (secnumdepth=-1 ya oculta la numeración).
- **Estado:** PENDIENTE de aplicar + re-render.

### F2 — Figuras: doble caption y contador en conflicto (forma)
- **Páginas:** todas las figuras (p.ej. p.31–32 Fig. 2.1; p.34 Fig. 2.2; p.35–36 Fig. 2.3;
  p.37 Fig. 2.4; p.38 Fig. 2.5; y las de Cap. 4/5/6/7/8).
- **Qué:** cada figura aparece con DOS epígrafes:
  1. arriba, caption manual en negrita `**Figura 2.1.** Taxonomía…` (numeración por capítulo,
     la que usa la Lista de Figuras y la misma convención que las tablas);
  2. abajo, caption auto-generado por pandoc `Figura 1: Figura 2.1 - Taxonomía…` con un
     contador propio plano ("Figura 1", "Figura 2"…) que NO coincide con la numeración 2.x.
- **Causa raíz (verificada):** en el fuente hay la línea negrita + `![Figura 2.1 - …](figures/*.svg)`;
  pandoc (`implicit_figures`) convierte el *alt* en un `\begin{figure}…\caption{…}\end{figure}`
  numerado "Figura N:". Las tablas no sufren esto porque son pipe-tables (sin float).
- **Opciones de fix (todas de forma):**
  - (A) Suprimir el auto-caption vaciando el alt → pierde el `\centering`/float (la imagen queda
    inline, sin centrar). **Descartada.**
  - (B) `\captionsetup[figure]{position=below, labelformat=empty}` + un único caption: mantiene
    el float centrado, saca el prefijo "Figura N:", y deja un solo epígrafe debajo con la
    numeración 2.x (cumple Art. 24.6 "epígrafe de figura abajo"). Requiere colapsar la línea
    negrita y el alt en un solo texto (en el render script, sin tocar contenido de capítulos).
    **Recomendada.**
- **Decisión pendiente (consultar a Fernando):** confirmar opción B (caption único abajo,
  estilo "Figura 2.1. <texto>") vs. mantener el caption arriba como las tablas y solo suprimir
  el auto-caption. Es un cambio visible y sistemático sobre la edición congelada de figuras.
- **Estado:** PENDIENTE — requiere decisión de enfoque.

### F3 — Figuras reutilizadas entre capítulos con rótulo horneado desfasado (FONDO — preguntar)
- **Páginas:** Fig. 4.1 (p.54) reutiliza la misma pirámide que Fig. 2.4 (p.37); Fig. 4.2 (p.57)
  reutiliza el mismo diagrama Adapter que Fig. 2.3 (p.35).
- **Qué:** el contenido de cada SVG encaja en ambos contextos, pero el **título horneado dentro
  del SVG** mantiene la etiqueta del Cap. 2: el gráfico de la Fig. 4.2 muestra impreso
  "Figura 2.3. Patrón Adapter en MIESC" aunque su epígrafe sea "Figura 4.2". Lo mismo con la
  pirámide ("Pirámide de Herramientas…", sin número, pero es la de 2.4).
- **Por qué es fondo:** es una decisión de contenido (reusar el mismo diagrama bajo dos números)
  y el texto está embebido en el asset SVG; corregirlo implica regenerar figuras o cambiar
  referencias, no es forma de markdown/render.
- **Pregunta a Fernando:** ¿se deja la reutilización tal cual, se quita el rótulo interno de los
  SVG, o la Fig. 4.2 debe ser un diagrama de clases distinto? NO lo toco hasta que lo definas.
- **Estado:** PENDIENTE — decisión del autor.

### F4 — Bloques de salida de herramientas desbordan el margen derecho (forma)
- **Páginas:** p.80 (tabla ASCII de la salida de Slither se envuelve: `-----+` cae en línea aparte),
  p.81 (línea `INFO:Slither:… (2 contracts with 100 detectors), 9` llega al borde y se corta),
  revisar también otras salidas de terminal en Cap. 5 y apéndices.
- **Qué:** los code blocks sin lenguaje (salidas de herramientas, ASCII tables) tienen líneas más
  anchas que el ancho de texto; XeLaTeX/fancyvrb no las parte → desbordan o se envuelven feo.
- **Cómo se corrige (a validar):** en el header del render, `\usepackage{fvextra}` +
  `\fvset{breaklines=true,breakanywhere=true}` (y, si hace falta, mono un punto más chico para
  code). Afecta solo el wrapping de verbatim; no cambia contenido. Validar que pandoc 3.8.3 aplique
  fvextra a sus entornos `Highlighting`/`verbatim`.
- **Estado:** PENDIENTE — validar fix + re-render.

### F5 — Tabla 5.2: nombre de contrato colisiona con columna LOC (forma, a verificar)
- **Página:** p.78, Tabla 5.2 "Corpus de contratos de prueba". Fila "AccessControlFlawed.sol"
  (el nombre más largo) parece solaparse con el valor LOC ("AccessControlFlawed120l").
- **Causa probable:** ancho de la 1ª columna calculado por pandoc demasiado angosto para el
  nombre más largo.
- **A verificar:** zoom en p.78 para confirmar solape real vs. artefacto de resolución.
- **Estado:** PENDIENTE — verificar.

### Observaciones menores (no bloqueantes)
- Lista de Acrónimos: tablas de letras con una sola entrada (B, F, P, T, W) renderizan centradas/
  angostas por auto-ancho de pandoc. Cosmético; consistente; no se corrige salvo pedido.
- Los SVG de figuras llevan el título "horneado" dentro de la imagen, que duplica el epígrafe.
  Parte del asset; no se toca en esta pasada de forma.


## Estado final (aplicado en la rama `docs/thesis-delivery-check`, 2026-10-20)

| Hallazgo | Estado | Cómo se resolvió |
|---|---|---|
| F1 Índice con filas A–Z | **Aplicado** | `_unlist_letter_headings` → `{.unnumbered .unlisted}`; el Índice del PDF ya no lista las letras (0 filas, verificado sobre el texto de las pp. 1–2). |
| F2 Doble epígrafe en figuras | **Aplicado (opción B)** | El renderer fusiona la línea `**Figura X.Y.** texto` con el `alt` de la imagen y `\captionsetup[figure]{labelformat=empty}` suprime el prefijo automático: un solo epígrafe debajo, "Figura X.Y. texto", en las 20 figuras. Los `.md` de los capítulos no cambian. |
| F3 Figuras reutilizadas con rótulo horneado | **Parcial** | Se eliminó el título "Figura N: …" horneado dentro de 14 SVG (numeración vieja que contradecía las leyendas); la reutilización de las Figs. 2.3→4.2 y 2.4→4.1 sigue pendiente de decisión del autor. |
| F4 Desborde de salidas de terminal | **Aplicado** | `fvextra` (instalado en el árbol TeX del usuario con `tlmgr --usermode install fvextra`) + `breaklines/breakanywhere` y `\small` en `verbatim` y `Highlighting`; pp. 77–78 ya no desbordan. |
| F5 Tabla 5.2 colisión de columnas | **Aplicado** | Separadores de las Tablas 5.2 y 5.5 ensanchados en la primera columna (pandoc deriva los anchos relativos de la línea de guiones); "AccessControlFlawed.sol" ya no pisa LOC. |

Render tras los cambios: 236 páginas (menos que 247 por el epígrafe único y el mono más chico en bloques), 0 warnings. Requisito nuevo del entorno de render: paquete LaTeX `fvextra` (BasicTeX no lo trae; `tlmgr --usermode install fvextra`).
