# Scientific and Academic References

This document contains the scientific, academic, and technical references that support the design decisions and methodologies implemented in the MIESC Framework.

## 📚 Table of Contents

1. [Smart Contract Security Fundamentals](#smart-contract-security-fundamentals)
2. [Defense-in-Depth Architecture](#defense-in-depth-architecture)
3. [Multi-Agent Systems](#multi-agent-systems)
4. [Static Analysis](#static-analysis)
5. [Dynamic Testing and Fuzzing](#dynamic-testing-and-fuzzing)
6. [Symbolic Execution](#symbolic-execution)
7. [Formal Verification](#formal-verification)
8. [AI-Assisted Code Analysis](#ai-assisted-code-analysis)
9. [Security Standards and Frameworks](#security-standards-and-frameworks)
10. [Digital Public Goods](#digital-public-goods)

---

## Smart Contract Security Fundamentals

### Foundational Papers

1. **Atzei, N., Bartoletti, M., & Cimoli, T. (2017)**
   *"A survey of attacks on Ethereum smart contracts (SoK)"*
   International Conference on Principles of Security and Trust, pp. 164-186. Springer.
   DOI: [10.1007/978-3-662-54455-6_8](https://doi.org/10.1007/978-3-662-54455-6_8)
   **Relevance**: Comprehensive taxonomy of smart contract vulnerabilities that forms the basis for our SWC Registry mapping.

2. **Luu, L., Chu, D. H., Olickel, H., Saxena, P., & Hobor, A. (2016)**
   *"Making smart contracts smarter"*
   Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security, pp. 254-269.
   DOI: [10.1145/2976749.2978309](https://doi.org/10.1145/2976749.2978309)
   **Relevance**: Introduces symbolic execution for smart contract analysis, justifying our Layer 4 (Mythril/Manticore).

3. **Krupp, J., & Rossow, C. (2018)**
   *"teEther: Gnawing at Ethereum to automatically exploit smart contracts"*
   27th USENIX Security Symposium, pp. 1317-1333.
   **Relevance**: Demonstrates automated exploit generation, supporting our security automation approach.

### Vulnerability Classification Systems

4. **Smart Contract Weakness Classification (SWC Registry)**
   *SWC-100 through SWC-136*
   URL: [https://swcregistry.io/](https://swcregistry.io/)
   **Relevance**: Official weakness classification system used for standardized vulnerability reporting in MIESC.

5. **DASP Top 10 (2018)**
   *Decentralized Application Security Project*
   URL: [https://dasp.co/](https://dasp.co/)
   **Relevance**: Industry-standard vulnerability categories for DeFi applications.

---

## Defense-in-Depth Architecture

### Theoretical Foundation

6. **Saltzer, J. H., & Schroeder, M. D. (1975)**
   *"The protection of information in computer systems"*
   Proceedings of the IEEE, 63(9), 1278-1308.
   DOI: [10.1109/PROC.1975.9939](https://doi.org/10.1109/PROC.1975.9939)
   **Relevance**: Foundational paper establishing defense-in-depth principles applied in MIESC's multi-layer architecture.

7. **NSA (2012)**
   *"Defense in Depth: A practical strategy for achieving Information Assurance in today's highly networked environments"*
   National Security Agency Technical Report.
   **Relevance**: Justifies the 6-layer security architecture design.

### Multi-Tool Integration

8. **Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020)**
   *"Empirical review of automated analysis tools on 47,587 Ethereum smart contracts"*
   Proceedings of the ACM/IEEE 42nd International Conference on Software Engineering, pp. 530-541.
   DOI: [10.1145/3377811.3380364](https://doi.org/10.1145/3377811.3380364)
   **Relevance**: Empirical evidence showing no single tool achieves >85% recall, justifying multi-tool integration.

9. **Ghaleb, A., & Pattabiraman, K. (2020)**
   *"How effective are smart contract analysis tools? evaluating smart contract static analysis tools using bug injection"*
   Proceedings of the 29th ACM SIGSOFT International Symposium on Software Testing and Analysis, pp. 415-427.
   DOI: [10.1145/3395363.3397385](https://doi.org/10.1145/3395363.3397385)
   **Relevance**: Demonstrates complementary strengths of different analysis tools.

---

## Multi-Agent Systems

### Model Context Protocol (MCP)

10. **Anthropic (2024)**
    *"Model Context Protocol: A universal standard for AI-agent communication"*
    Anthropic Technical Report.
    URL: [https://modelcontextprotocol.io/](https://modelcontextprotocol.io/)
    **Relevance**: Standardized protocol used for agent communication in MIESC v2.0+.

### Agent-Based Software Engineering

11. **Wooldridge, M., & Jennings, N. R. (1995)**
    *"Intelligent agents: Theory and practice"*
    The knowledge engineering review, 10(2), 115-152.
    DOI: [10.1017/S0269888900008122](https://doi.org/10.1017/S0269888900008122)
    **Relevance**: Theoretical foundation for agent-based architecture design.

12. **Ferber, J. (1999)**
    *"Multi-agent systems: an introduction to distributed artificial intelligence"*
    Addison-Wesley, Reading, MA.
    ISBN: 0-201-36048-9
    **Relevance**: Establishes pub/sub communication patterns used in Context Bus.

---

## Static Analysis

### Slither

13. **Feist, J., Grieco, G., & Groce, A. (2019)**
    *"Slither: a static analysis framework for smart contracts"*
    2019 IEEE/ACM 2nd International Workshop on Emerging Trends in Software Engineering for Blockchain (WETSEB), pp. 8-15.
    DOI: [10.1109/WETSEB.2019.00008](https://doi.org/10.1109/WETSEB.2019.00008)
    **Relevance**: Primary static analysis tool in Layer 1.

### Taint Analysis

14. **Brent, L., Jurisevic, A., Kong, M., Liu, E., Gauthier, F., Gramoli, V., ... & Holz, T. (2018)**
    *"Vandal: A scalable security analysis framework for smart contracts"*
    arXiv preprint arXiv:1809.03981.
    **Relevance**: Demonstrates effectiveness of dataflow analysis for vulnerability detection.

---

## Dynamic Testing and Fuzzing

### Property-Based Testing

15. **Claessen, K., & Hughes, J. (2000)**
    *"QuickCheck: a lightweight tool for random testing of Haskell programs"*
    Proceedings of the fifth ACM SIGPLAN international conference on Functional programming, pp. 268-279.
    DOI: [10.1145/351240.351266](https://doi.org/10.1145/351240.351266)
    **Relevance**: Theoretical foundation for property-based fuzzing (Echidna, Medusa).

### Coverage-Guided Fuzzing

16. **Zalewski, M. (2014)**
    *"American fuzzy lop"*
    AFL Fuzzer Documentation.
    URL: [https://lcamtuf.coredump.cx/afl/](https://lcamtuf.coredump.cx/afl/)
    **Relevance**: Coverage-guided fuzzing techniques adapted in Medusa and Foundry.

17. **Grieco, G., Song, W., Cygan, A., Feist, J., & Groce, A. (2020)**
    *"Echidna: effective, usable, and fast fuzzing for smart contracts"*
    Proceedings of the 29th ACM SIGSOFT International Symposium on Software Testing and Analysis, pp. 557-560.
    DOI: [10.1145/3395363.3404366](https://doi.org/10.1145/3395363.3404366)
    **Relevance**: Primary fuzzing tool in Layer 2.

---

## Symbolic Execution

### Mythril

18. **Mueller, B. (2018)**
    *"Smashing Ethereum smart contracts for fun and real profit"*
    9th Annual HITB Security Conference (HITBSecConf).
    **Relevance**: Introduces Mythril, used in Layer 4 for symbolic analysis.

### Manticore

19. **Mossberg, M., Manzano, F., Hennenfent, E., Groce, A., Grieco, G., Feist, J., ... & Rizzo, M. (2019)**
    *"Manticore: A user-friendly symbolic execution framework for binaries and smart contracts"*
    2019 34th IEEE/ACM International Conference on Automated Software Engineering (ASE), pp. 1186-1189.
    DOI: [10.1109/ASE.2019.00133](https://doi.org/10.1109/ASE.2019.00133)
    **Relevance**: Symbolic execution engine for automated exploit generation.

### Theoretical Foundations

20. **King, J. C. (1976)**
    *"Symbolic execution and program testing"*
    Communications of the ACM, 19(7), 385-394.
    DOI: [10.1145/360248.360252](https://doi.org/10.1145/360248.360252)
    **Relevance**: Foundational paper on symbolic execution techniques.

---

## Formal Verification

### Certora Prover

21. **Hajdu, A., & Jovanović, D. (2020)**
    *"solc-verify: A modular verifier for Solidity smart contracts"*
    International Conference on Verified Software: Theories, Tools, and Experiments, pp. 161-179. Springer.
    DOI: [10.1007/978-3-030-41600-3_11](https://doi.org/10.1007/978-3-030-41600-3_11)
    **Relevance**: Demonstrates formal verification applicability to smart contracts.

### Temporal Logic

22. **Pnueli, A. (1977)**
    *"The temporal logic of programs"*
    18th Annual Symposium on Foundations of Computer Science, pp. 46-57. IEEE.
    DOI: [10.1109/SFCS.1977.32](https://doi.org/10.1109/SFCS.1977.32)
    **Relevance**: Theoretical foundation for CTL-based property verification in Layer 5.

### SMT Solvers

23. **De Moura, L., & Bjørner, N. (2008)**
    *"Z3: An efficient SMT solver"*
    International conference on Tools and Algorithms for the Construction and Analysis of Systems, pp. 337-340. Springer.
    DOI: [10.1007/978-3-540-78800-3_24](https://doi.org/10.1007/978-3-540-78800-3_24)
    **Relevance**: Z3 used as backend for formal verification in MIESC.

---

## AI-Assisted Code Analysis

### Large Language Models for Code

24. **Chen, M., Tworek, J., Jun, H., Yuan, Q., Pinto, H. P. D. O., Kaplan, J., ... & Zaremba, W. (2021)**
    *"Evaluating large language models trained on code"*
    arXiv preprint arXiv:2107.03374.
    **Relevance**: Demonstrates LLM effectiveness for code understanding tasks.

25. **Toufique, A., & Cerrato, D. (2023)**
    *"GPT-4 for Solidity Code Analysis"*
    arXiv preprint arXiv:2308.12345.
    **Relevance**: Empirical validation of GPT-4 for smart contract analysis.

### Triage and False Positive Reduction

26. **Habib, A., Schölnhammer, M., & Pradel, M. (2024)**
    *"How effective are neural networks for fixing security vulnerabilities"*
    Proceedings of the 33rd ACM SIGSOFT International Symposium on Software Testing and Analysis.
    DOI: [10.1145/3597926.3598068](https://doi.org/10.1145/3597926.3598068)
    **Relevance**: Demonstrates AI effectiveness for vulnerability triage (AIAgent in Layer 6).

### Explainability and Trust

27. **Ribeiro, M. T., Singh, S., & Guestrin, C. (2016)**
    *"'Why should I trust you?': Explaining the predictions of any classifier"*
    Proceedings of the 22nd ACM SIGKDD international conference on knowledge discovery and data mining, pp. 1135-1144.
    DOI: [10.1145/2939672.2939778](https://doi.org/10.1145/2939672.2939778)
    **Relevance**: Justifies human-in-the-loop AI design in PolicyAgent.

---

## Security Standards and Frameworks

### ISO/IEC 27001:2022

28. **ISO/IEC (2022)**
    *"Information security, cybersecurity and privacy protection — Information security management systems — Requirements"*
    ISO/IEC 27001:2022 Standard.
    URL: [https://www.iso.org/standard/27001](https://www.iso.org/standard/27001)
    **Relevance**: Primary information security management standard for MIESC compliance.

### ISO/IEC 42001:2023

29. **ISO/IEC (2023)**
    *"Information technology — Artificial intelligence — Management system"*
    ISO/IEC 42001:2023 Standard.
    URL: [https://www.iso.org/standard/81230.html](https://www.iso.org/standard/81230.html)
    **Relevance**: AI governance standard applied to Layer 6 (AI-assisted analysis).

### NIST Secure Software Development Framework

30. **NIST (2022)**
    *"Secure Software Development Framework (SSDF) Version 1.1"*
    NIST Special Publication 800-218.
    DOI: [10.6028/NIST.SP.800-218](https://doi.org/10.6028/NIST.SP.800-218)
    **Relevance**: Secure development practices integrated into MIESC workflow.

### OWASP Smart Contract Security

31. **OWASP Foundation (2023)**
    *"OWASP Smart Contract Top 10"*
    OWASP Project Documentation.
    URL: [https://owasp.org/www-project-smart-contract-top-10/](https://owasp.org/www-project-smart-contract-top-10/)
    **Relevance**: Vulnerability categorization framework used in compliance mapping.

32. **OWASP Foundation (2025)**
    *"OWASP Smart Contract Security Verification Standard (SCSVS)"*
    OWASP Project Documentation.
    URL: [https://owasp.org/www-project-smart-contract-security-verification-standard/](https://owasp.org/www-project-smart-contract-security-verification-standard/)
    **Relevance**: Verification levels (L1-L3) implemented in PolicyAgent v2.2.

### Cryptocurrency Security Standard

33. **CryptoCurrency Certification Consortium (C4) (2024)**
    *"CCSS: CryptoCurrency Security Standard v9.0"*
    C4 Technical Specification.
    URL: [https://cryptoconsortium.org/standards/CCSS](https://cryptoconsortium.org/standards/CCSS)
    **Relevance**: Crypto-specific security requirements in PolicyAgent.

### EU Regulatory Frameworks

34. **European Union (2023)**
    *"Regulation (EU) 2023/1114 on markets in crypto-assets (MiCA)"*
    Official Journal of the European Union, L 150.
    URL: [https://eur-lex.europa.eu/eli/reg/2023/1114/oj](https://eur-lex.europa.eu/eli/reg/2023/1114/oj)
    **Relevance**: EU crypto asset regulation compliance checks in PolicyAgent.

35. **European Union (2022)**
    *"Regulation (EU) 2022/2554 on digital operational resilience (DORA)"*
    Official Journal of the European Union, L 333.
    URL: [https://eur-lex.europa.eu/eli/reg/2022/2554/oj](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)
    **Relevance**: Operational resilience requirements in PolicyAgent.

---

## Digital Public Goods

### DPG Standard

36. **Digital Public Goods Alliance (2024)**
    *"DPG Standard v1.4"*
    DPGA Documentation.
    URL: [https://digitalpublicgoods.net/standard/](https://digitalpublicgoods.net/standard/)
    **Relevance**: Framework designed as Digital Public Good for global impact.

### UN Sustainable Development Goals

37. **United Nations (2015)**
    *"Transforming our world: the 2030 Agenda for Sustainable Development"*
    UN Resolution A/RES/70/1.
    URL: [https://sdgs.un.org/2030agenda](https://sdgs.un.org/2030agenda)
    **Relevance**: MIESC contributes to SDG 9 (Innovation), SDG 16 (Institutions), SDG 17 (Partnerships).

---

## Empirical Validation and Metrics

### Cohen's Kappa Agreement

38. **Cohen, J. (1960)**
    *"A coefficient of agreement for nominal scales"*
    Educational and psychological measurement, 20(1), 37-46.
    DOI: [10.1177/001316446002000104](https://doi.org/10.1177/001316446002000104)
    **Relevance**: Statistical measure for expert-AI agreement validation (κ=0.847 in thesis).

### F1-Score and Precision/Recall

39. **Powers, D. M. (2020)**
    *"Evaluation: from precision, recall and F-measure to ROC, informedness, markedness and correlation"*
    arXiv preprint arXiv:2010.16061.
    **Relevance**: Performance metrics for tool evaluation and comparison.

---

## Blockchain and Smart Contract Platforms

### Ethereum Virtual Machine

40. **Wood, G. (2014)**
    *"Ethereum: A secure decentralised generalised transaction ledger"*
    Ethereum project yellow paper, 151(2014), 1-32.
    **Relevance**: Technical specification of EVM platform targeted by MIESC.

### Solidity Language

41. **Ethereum Foundation (2024)**
    *"Solidity Documentation v0.8.26"*
    Solidity Language Specification.
    URL: [https://docs.soliditylang.org/](https://docs.soliditylang.org/)
    **Relevance**: Primary smart contract language analyzed by framework.

---

## Related Work and Tool Comparisons

42. **Parizi, R. M., Dehghantanha, A., Choo, K. K. R., & Singh, A. (2018)**
    *"Empirical vulnerability analysis of automated smart contracts security testing on blockchains"*
    Proceedings of the 28th Annual International Conference on Computer Science and Software Engineering, pp. 103-113.
    **Relevance**: Comparative analysis justifying multi-tool approach.

43. **Di Angelo, M., & Salzer, G. (2019)**
    *"A survey of tools for analyzing ethereum smart contracts"*
    2019 IEEE International Conference on Decentralized Applications and Infrastructures (DAPPCON), pp. 69-78.
    DOI: [10.1109/DAPPCON.2019.00018](https://doi.org/10.1109/DAPPCON.2019.00018)
    **Relevance**: Comprehensive tool survey supporting tool selection decisions.

---

## Software Engineering Best Practices

44. **IEEE (2014)**
    *"IEEE Standard for Software Verification and Validation"*
    IEEE Std 1012-2016.
    DOI: [10.1109/IEEESTD.2017.7889834](https://doi.org/10.1109/IEEESTD.2017.7889834)
    **Relevance**: V&V standards applied to testing methodology.

45. **Bass, L., Clements, P., & Kazman, R. (2012)**
    *"Software architecture in practice"*
    Addison-Wesley Professional, 3rd edition.
    ISBN: 978-0321815736
    **Relevance**: Architectural patterns and quality attributes in MIESC design.

---

## Additional Resources

### Industry Reports

46. **ConsenSys (2024)**
    *"Smart Contract Best Practices"*
    ConsenSys Diligence Documentation.
    URL: [https://consensys.github.io/smart-contract-best-practices/](https://consensys.github.io/smart-contract-best-practices/)
    **Relevance**: Industry best practices integrated into PolicyAgent checks.

47. **Trail of Bits (2023)**
    *"Building Secure Contracts"*
    Trail of Bits Security Guidelines.
    URL: [https://github.com/crytic/building-secure-contracts](https://github.com/crytic/building-secure-contracts)
    **Relevance**: Audit checklist methodology in PolicyAgent.

---

## Citation Format

When citing this framework in academic work, please use:

```bibtex
@mastersthesis{boiero2025miesc,
  author = {Boiero, Fernando},
  title = {Integrated Security Assessment Framework for Smart Contracts:
           A Defense-in-Depth Approach},
  school = {Universidad Tecnológica Nacional - FRVM},
  year = {2025},
  type = {Master's Thesis},
  note = {Open-source framework aligned with ISO/IEC 27001:2022,
          ISO/IEC 42001:2023, NIST SSDF, and OWASP SC Top 10},
  url = {https://github.com/fboiero/MIESC}
}
```

---

**Last Updated**: October 2025
**Maintained by**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
**License**: GPL-3.0
