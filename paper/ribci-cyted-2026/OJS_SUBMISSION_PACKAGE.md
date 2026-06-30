# Paquete de envío — RIBCi–CYTED 2026

**Evento:** IV Simposio Internacional de Blockchain y Ciberseguridad (RIBCi–CYTED 2026)
**Plataforma:** https://www.iscap.pt/edicoesceos/index.php/livrosatas/about/submissions
**Editor:** Edições CEOS.PP / ISCAP
**Fecha límite:** 30 de junio de 2026
**Revisión:** doble ciego · **Idioma:** inglés · **Formato:** IEEE
**Generado:** 2026-06-30 (artefactos aditivos; no modifica el baseline congelado)

---

## Archivos a subir (versiones ANONIMIZADAS, doble ciego)

| Paper | Archivo Word (subir) | Fuente |
|---|---|---|
| 1 | `paper1-MIESC-anon.docx` | `paper1-MIESC-anon.tex` |
| 2 | `paper2-remediation-anon.docx` | `paper2-remediation-anon.tex` |

> Los PDF/LaTeX originales con autores (`../miesc-paper.pdf`, `../paper2-remediation.pdf`) quedan intactos y se usan para la versión final (camera-ready) tras la aceptación.

---

## PAPER 1

- **Título:** MIESC: A Multi-layer Framework for Automated Smart Contract Security Evaluation
- **Categoría:** Full paper (Research — original research results)
- **Idioma:** English
- **Keywords:** smart contracts; blockchain security; vulnerability detection; defense-in-depth; multi-agent systems; retrieval-augmented generation; static analysis; formal verification

**Abstract (187 palabras):**

Automated smart contract security tools tend to specialize: static analyzers cover known code patterns, fuzzers exercise reachable states, and LLM-based auditors can reason about higher-level intent but vary across runs. This paper studies whether a reproducible orchestration of these techniques improves coverage for smart-contract triage. MIESC combines 35 analysis modules across 9 layers, normalizes their outputs, applies RAG-backed false-positive filtering, and records the artifacts needed to reproduce each reported claim. On SmartBugs-curated (143 contracts), the primary static+intelligence profile reports 95.8% recall (137/143); a secondary local 32B follow-up over the remaining misses raises this to 97.9% (140/143). On 11 real DeFi exploits ($1.59B in evaluated losses), MIESC detects 9/11 cases (81.8%; Cohen's κ=0.773 on this small sample). On an EVMBench local high-severity extraction (40 audits, 120 findings), a four-provider union ensemble detects 111/120 vulnerabilities (92.5% recall), compared with 82.5% for the best single provider and 59.2% for a local 32B model. We report the EVMBench result as a local extraction rather than an official leaderboard score, and we publish the claim matrix and source artifacts. MIESC is available under AGPL-3.0.

---

## PAPER 2

- **Título:** From Findings to Verifiable Remediation Artifacts: A Smart Contract Security Pipeline
- **Categoría:** Full paper (Research — original research results)
- **Idioma:** English
- **Keywords:** smart contracts; automated program repair; exploit testing; formal verification; security compliance; defense-in-depth

**Abstract (209 palabras):**

Detection tools usually stop at the finding: they identify a vulnerable function, but the patch, regression test, and audit evidence remain manual work. This paper evaluates how far an automated smart-contract pipeline can move from a finding to inspectable remediation artifacts without hiding residual failures. MIESC takes normalized Solidity findings, emits self-contained patch candidates, generates Foundry exploit tests, creates formal-specification stubs, and maps findings to compliance controls. On SmartBugs-curated (143 contracts), the v2 remediation baseline applies patches to 123 contracts after 18 no-HIGH and 2 empty-scan cases, compiles all 123 emitted patches standalone, eliminates the target finding in 86/123 cases by MIESC re-scan, satisfies a bounded no-regression criterion in 121/123 cases, and leaves 58/123 patched contracts clean of HIGH findings under external Slither validation. We keep these metrics separate because each answers a different question: whether a patch was emitted, whether it compiles, whether the original scanner still reports the target class, and whether an independent analyzer still reports HIGH findings. On an illustrative vulnerable contract, the generated tests and specifications show the end-to-end artifact flow. The pipeline can run locally without API calls, but the external Slither result shows that automated remediation remains a triage aid rather than a proof of semantic correctness. MIESC is available under AGPL-3.0.

---

## Autores (cargar en metadatos de OJS — NO en el documento)

Orden y afiliación idénticos para ambos papers:

| # | Nombre | Afiliación | Email | ORCID |
|---|---|---|---|---|
| 1 | Fernando Boiero (autor de contacto) | Universidad Tecnológica Nacional (UTN), Facultad Regional Villa María, Córdoba, Argentina | fboiero@frvm.utn.edu.ar | _(completar)_ |
| 2 | Sebastián Norberto Mussetta | Universidad Tecnológica Nacional (UTN), Facultad Regional Villa María, Córdoba, Argentina | smussetta@frvm.utn.edu.ar | _(completar)_ |
| 3 | Norberto Gaspar Cena | Universidad Tecnológica Nacional (UTN), Facultad Regional Villa María, Córdoba, Argentina | ngcena@frvm.utn.edu.ar | _(completar)_ |

---

## Nota al editor (campo "Comentarios al editor")

> Both submissions are original and unpublished, and are not under review at any
> other venue. They are companion papers that cross-reference each other; the
> companion citation has been anonymized in each manuscript for double-blind
> review. The manuscripts follow IEEE conference format and are submitted in
> Word (.docx) per the platform's file-format requirement. Author names,
> affiliations, acknowledgments, and the public repository URL have been removed
> for double-blind review and will be restored in the camera-ready version.

---

## Anonimización aplicada (doble ciego)

En ambas versiones `-anon` se quitó/neutralizó:

- Bloque de autores, afiliación UTN-FRVM y emails `@frvm.utn.edu.ar`.
- Agradecimientos auto-identificatorios (tesis UNDEF–IUA / UTN-FRVM).
- URL del repositorio `github.com/fboiero/MIESC` → "(link withheld for review)".
- Cita al paper companion (Boiero et al.) → "Anonymous Author(s)".

Verificado programáticamente: 0 tokens de identidad en cuerpo, tablas y referencias.

## Checklist de OJS antes de enviar

- [ ] Registrarse / iniciar sesión en la plataforma OJS.
- [ ] Marcar las 4 condiciones de envío (original, formato Word, URLs en refs, normas verificadas).
- [ ] Categoría: Full Paper · Idioma: English.
- [ ] Subir el `.docx` anonimizado correspondiente.
- [ ] Cargar título, abstract, keywords y los 3 autores en metadatos.
- [ ] Pegar la nota al editor.
- [ ] Repetir como **dos envíos separados** (Paper 1 y Paper 2).

## Para la versión final (camera-ready, si son aceptados)

Restaurar en cada manuscrito: nombres + afiliación + emails de autores, sección
de agradecimientos completa, URL real del repositorio y la cita real al paper
companion. Usar los PDF/LaTeX originales no anonimizados como base.
