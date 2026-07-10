# SmartBugs-Curated — Provenance & Licensing

The Solidity contracts under `dataset/` are redistributed here, unmodified, from
the upstream **SmartBugs-Curated** dataset to support the reproducible paper and
regression workflows in this repository.

## Upstream source

- Repository: https://github.com/smartbugs/smartbugs-curated
- Description: "SB Curated is a curated dataset of Solidity smart contracts
  annotated with tagged vulnerabilities. The dataset was created to evaluate the
  accuracy of automated analysis tools."
- Contents: 143 annotated contracts with 208 tagged vulnerabilities, organized
  according to the DASP taxonomy.

## Licensing of the contracts

Per the upstream project's own statement:

> All the contracts were obtained from public websites or using Etherscan and
> they retain their original licenses.

Each contract file carries inline annotations recording its origin and author
(`@source`, `@author`) and the reported vulnerability locations
(`@vulnerable_at_lines`). Those per-file annotations, together with the upstream
repository, are the authoritative record of each contract's origin and license.

No additional license is asserted by MIESC over these third-party contracts. They
are included solely for benchmark reproducibility; refer to the upstream
repository and the per-file `@source` annotations for the terms governing any
individual contract.

## Academic references

- Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). *Empirical Review
  of Automated Analysis Tools on 47,587 Ethereum Smart Contracts.* ICSE 2020.
- Ferreira, J. F., et al. *SmartBugs: A Framework to Analyze Solidity Smart
  Contracts.* ICSE 2020 (tool demonstration).

> Note: verify author ordering and the exact title of each reference against the
> upstream publication before citing. The two works above are distinct (the
> empirical study vs. the framework/tool paper) and should not be conflated.
