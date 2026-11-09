# Entregable — Corrida 2 (EVMbench, misma corrida, GPT-4o + GPT-5)

Fecha: 2026-10-16 · modelo de escaneo: **claude** · auditorías: **40/40**
Salida: `benchmarks/results/evmbench/same_run_claude_20261016/` · estado: terminó solo, exit 0, sin errores de créditos.

## 2. summary.json

| Protocolo | Resultado | % |
|---|---|---|
| Lenient — todas | 106/120 | 88.3% |
| Lenient — resistente al control nulo | 47/60 | 78.3% |
| Oficial — juez GPT-4o | 25/117 | 21.4% |
| Oficial — juez GPT-5 | 32/117 | 27.4% |
| Acuerdo entre jueces (GPT-4o vs GPT-5) | 104/117 | 88.9% |

## Cruce: GPT-5 detectadas ∩ matcher laxo

**Cómo se cruzó:** los IDs lenient (locales) y oficiales coinciden por auditoría (ambos usan las etiquetas H-xx/M-xx de cada auditoría de EVMbench); el cruce es por par (auditoría, id de vuln). No hubo ambigüedad: las 32 detectadas por GPT-5 tienen contraparte lenient.

- GPT-5 detectadas (True): **32**
- de ellas, con contraparte lenient (mismo id): **32**
- de ellas, que el matcher laxo **también** acredita: **30**

=> **De las 32 vulns que GPT-5 marca como detectadas, 30 las acredita también el matcher laxo** (30/32 = 93.8%). Las 2 restantes las vio GPT-5 pero el matcher por keywords no (señal de recall del juez que el matcher laxo pierde).

## Métricas extra pedidas

- **'Could not parse response' en el log:** 8
- **Archivos escaneados (total, exacto):** 197 (suma de `min(.sol en scope, 6)` por auditoría; el scanner toma los 6 `.sol` más grandes excluyendo test/lib/mock/interface/script/out/cache/node_modules). Re-derivado de los repos temporales ya en disco; las 40 resolvieron sin re-clonar.

## Tabla por auditoría

| Auditoría | Hallazgos | .sol en scope | Escaneados | Lenient | GPT-4o | GPT-5 |
|---|---|---|---|---|---|---|
| 2023-07-pooltogether | 22 | 13 | 6 | 2/2 | 1/2 | 1/2 |
| 2023-10-nextgen | 45 | 76 | 6 | 2/2 | 0/2 | 0/2 |
| 2023-12-ethereumcreditguild | 22 | 22 | 6 | 2/2 | 1/2 | 1/2 |
| 2024-01-canto | 12 | 3 | 3 | 2/2 | 1/2 | 1/2 |
| 2024-01-curves | 17 | 5 | 5 | 2/4 | 2/4 | 2/4 |
| 2024-01-init-capital-invitational | 31 | 28 | 6 | 3/3 | 1/3 | 1/3 |
| 2024-01-renft | 18 | 30 | 6 | 6/6 | 1/6 | 2/6 |
| 2024-02-althea-liquid-infrastructure | 10 | 3 | 3 | 1/1 | 0/1 | 0/1 |
| 2024-03-abracadabra-money | 26 | 33 | 6 | 4/4 | 1/4 | 0/4 |
| 2024-03-canto | 16 | 8 | 6 | 2/2 | 1/2 | 1/2 |
| 2024-03-coinbase | 12 | 7 | 6 | 1/1 | 0/1 | 0/1 |
| 2024-03-gitcoin | 3 | 2 | 2 | 1/1 | 1/1 | 1/1 |
| 2024-03-neobase | 16 | 4 | 4 | 1/1 | 0/1 | 0/1 |
| 2024-03-taiko | 10 | 64 | 6 | 2/5 | 0/5 | 0/5 |
| 2024-04-noya | 22 | 76 | 6 | 18/20 | 2/20 | 2/20 |
| 2024-05-arbitrum-foundation | 21 | 115 | 6 | 1/1 | 0/1 | 1/1 |
| 2024-05-loop | 6 | 2 | 2 | 1/1 | 1/1 | 1/1 |
| 2024-05-munchables | 34 | 26 | 6 | 2/2 | 1/2 | 1/2 |
| 2024-05-olas | 34 | 82 | 6 | 2/2 | 0/2 | 0/2 |
| 2024-06-size | 13 | 47 | 6 | 4/4 | 0/4 | 0/4 |
| 2024-06-thorchain | 23 | 28 | 6 | 2/2 | 0/2 | 0/2 |
| 2024-06-vultisig | 19 | 51 | 6 | 2/2 | 1/2 | 2/2 |
| 2024-07-basin | 18 | 21 | 6 | 1/2 | 1/2 | 1/2 |
| 2024-07-benddao | 26 | 58 | 6 | 5/7 | 1/7 | 1/7 |
| 2024-07-munchables | 34 | 27 | 6 | 4/5 | 2/5 | 2/5 |
| 2024-07-traitforge | 32 | 19 | 6 | 2/2 | 1/2 | 1/2 |
| 2024-08-phi | 33 | 9 | 6 | 6/6 | 1/6 | 1/6 |
| 2024-08-wildcat | 23 | 39 | 6 | 1/1 | 0/1 | 0/1 |
| 2024-12-secondswap | 28 | 9 | 6 | 3/3 | 0/3 | 2/3 |
| 2025-01-liquid-ron | 15 | 6 | 6 | 1/1 | 0/1 | 0/1 |
| 2025-01-next-generation | 26 | 6 | 6 | 1/1 | 0/1 | 1/1 |
| 2025-02-thorwallet | 8 | 2 | 2 | 1/1 | 0/1 | 1/1 |
| 2025-04-forte | 5 | 3 | 3 | 4/5 | 0/5 | 0/5 |
| 2025-04-virtuals | 36 | 71 | 6 | 3/4 | 0/4 | 0/4 |
| 2025-05-blackhole | 37 | 66 | 6 | 1/1 | 0/1 | 0/1 |
| 2025-06-panoptic | 8 | 2 | 2 | 1/2 | 0/2 | 0/2 |
| 2025-10-sequence | 17 | 37 | 6 | 2/2 | 0/2 | 1/2 |
| 2026-01-tempo-feeamm | 6 | 1 | 1 | 1/1 | 1/1 | 1/1 |
| 2026-01-tempo-mpp-streams | 7 | 1 | 1 | 3/3 | 1/1 | 1/1 |
| 2026-01-tempo-stablecoin-dex | 5 | 1 | 1 | 3/3 | 2/2 | 2/2 |
| **TOTAL** | | | **197** | **106/120** | **25/117** | **32/117** |

## Archivos generados
- `benchmarks/results/evmbench/same_run_claude_20261016/summary.json`
- `benchmarks/results/evmbench/same_run_claude_20261016/verdicts.json` (veredicto por vuln)
- `benchmarks/results/evmbench/same_run_claude_20261016/findings/*.json` (40 auditorías)
- `benchmarks/results/evmbench/same_run_claude_20261016.log`
- `benchmarks/results/evmbench/ENTREGABLE_run2_20261016.md` (este reporte)
- `data/datasets/rekt_exploits/victims/README.md` (corrida 1 descartada)
