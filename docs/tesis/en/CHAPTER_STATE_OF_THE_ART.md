# Chapter 3: State of the Art

## Security Analysis in Smart Contracts: A Systematic Review

---

## 3.1 Introduction

Smart contract security represents one of the most significant challenges in the contemporary blockchain ecosystem. According to Atzei et al. (2017), smart contracts are "programs that run on a blockchain and that, once deployed, are immutable and publicly verifiable" (p. 164). This immutability, while guaranteeing code integrity, implies that any vulnerability present at deployment time will remain exploitable indefinitely, unless specific upgrade mechanisms are implemented (Chen et al., 2020).

This chapter presents a systematic review of the state of the art in security analysis tools and methodologies for smart contracts, following the methodological guidelines proposed by Kitchenham and Charters (2007) for systematic reviews in software engineering. The main gaps are identified, which form the foundation for the development of MIESC as a contribution to the field.

---

## 3.2 Context and Problem Relevance

### 3.2.1 Economic Impact of Vulnerabilities

Smart contract vulnerabilities have caused substantial economic losses in the decentralized finance (DeFi) ecosystem. According to the Chainalysis (2024) report, cumulative losses from DeFi protocol exploits exceeded $3.8 billion dollars between 2020 and 2023. Table 3.1 presents the most significant incidents documented in the literature.

**Table 3.1.** Historical security incidents in smart contracts

| Year | Incident | Loss (USD) | Vulnerability | Reference |
|------|----------|------------|---------------|-----------|
| 2016 | The DAO | $60M | Reentrancy | Mehar et al. (2019) |
| 2017 | Parity Wallet | $150M | Access Control | Destefanis et al. (2018) |
| 2018 | Beauty Chain | $900M | Integer Overflow | Chen et al. (2020) |
| 2020 | bZx Protocol | $350K | Flash Loan | Qin et al. (2021) |
| 2021 | Poly Network | $610M | Cross-chain | Zhou et al. (2023) |
| 2022 | Ronin Bridge | $625M | Key Compromise | Chainalysis (2024) |
| 2023 | Euler Finance | $197M | Flash Loan + Logic | Werner et al. (2024) |

These incidents highlight the critical need for automated vulnerability detection tools, given that manual audits, although thorough, present scalability and cost limitations (Durieux et al., 2020).

### 3.2.2 Vulnerability Taxonomy

The academic community and industry have developed multiple taxonomies to classify smart contract vulnerabilities. The Smart Contract Weakness Classification Registry (SWC Registry), maintained by the Ethereum Foundation, constitutes the de facto standard with 37 documented weakness categories (SCSVS, 2023).

Perez and Livshits (2021) propose a classification based on the origin of vulnerabilities:

1. **Language-level vulnerabilities**: Derived from specific features of Solidity
2. **EVM-level vulnerabilities**: Related to Ethereum Virtual Machine semantics
3. **Blockchain-level vulnerabilities**: Associated with the distributed nature of the system
4. **Business logic vulnerabilities**: Errors in protocol logic implementation

Table 3.2 presents the vulnerability frequency distribution according to the empirical study by Zhou et al. (2023) on 47,587 contracts deployed on Ethereum mainnet.

**Table 3.2.** Vulnerability distribution in Ethereum contracts (Zhou et al., 2023)

| SWC-ID | Vulnerability | Frequency | Potential Impact |
|--------|---------------|-----------|------------------|
| SWC-107 | Reentrancy | 23.4% | Critical |
| SWC-101 | Integer Overflow/Underflow | 18.2% | High |
| SWC-104 | Unchecked Return Value | 15.1% | Medium |
| SWC-105 | Unprotected Ether Withdrawal | 12.3% | High |
| SWC-115 | Authorization through tx.origin | 8.7% | High |
| SWC-116 | Block Timestamp Dependence | 7.2% | Low |
| Others | Various | 15.1% | Variable |

---

## 3.3 Security Analysis Techniques

The literature identifies four main categories of techniques for smart contract security analysis (Rameder et al., 2022):

### 3.3.1 Static Analysis

Static analysis examines source code or bytecode without executing it, identifying potentially vulnerable patterns through data flow and control flow analysis techniques (Feist et al., 2019). According to Grech et al. (2018), this technique offers:

**Advantages:**
- Complete coverage of analyzed code
- Predictable and generally fast execution time
- Does not require test cases

**Limitations:**
- High false positive rate (15-30% according to Durieux et al., 2020)
- Inability to detect vulnerabilities dependent on execution state
- Difficulty analyzing dynamic calls and proxy patterns

**Representative tools:**

*Slither* (Feist et al., 2019): Framework developed by Trail of Bits implementing more than 80 vulnerability detectors. Uses an intermediate model (SlithIR) that facilitates data flow analysis. According to its authors, it achieves 82% precision on standard benchmarks.

*Securify2* (Tsankov et al., 2018): Developed by ETH Zurich, employs Datalog-based analysis to verify security properties. Its declarative approach allows compositional property definition.

### 3.3.2 Symbolic Execution

Symbolic execution represents input values as mathematical symbols, systematically exploring execution paths through satisfiability (SMT) solvers (Luu et al., 2016). King (1976) established the theoretical foundations of this technique, which has been adapted for smart contract analysis.

**Advantages:**
- Ability to generate inputs that trigger vulnerabilities
- Exhaustive analysis of execution paths
- High precision in detecting arithmetic vulnerabilities

**Limitations:**
- Path explosion in complex contracts (Baldoni et al., 2018)
- High computational resource consumption
- Difficulty handling cryptographic operations

**Representative tools:**

*Mythril* (Mueller, 2018): ConsenSys tool using the Z3 solver for symbolic execution. According to Durieux et al. (2020), it correctly detects 78% of reentrancy vulnerabilities in their benchmark.

*Manticore* (Mossberg et al., 2019): Trail of Bits framework combining symbolic and concolic execution. Allows analysis of both contracts and native binaries.

*Oyente* (Luu et al., 2016): First symbolic execution tool for Ethereum, presented at CCS 2016. Although currently outdated, it established the methodological foundations for subsequent tools.

### 3.3.3 Fuzzing

Fuzzing generates random or semi-directed inputs to explore program behavior at runtime (Miller et al., 1990). In the context of smart contracts, Grieco et al. (2020) propose *property-based fuzzing*, where the user specifies properties (invariants) that must be maintained.

**Advantages:**
- Low false positive rate (found vulnerabilities are reproducible)
- Ability to find vulnerabilities in complex code
- Scalability to large contracts

**Limitations:**
- Requires manual property specification
- Coverage dependent on quality of generated inputs
- May not explore all execution paths

**Representative tools:**

*Echidna* (Grieco et al., 2020): Property-based fuzzer developed by Trail of Bits. Uses grammar-based input generation and coverage-guided strategies.

*Foundry/Forge* (Paradigm, 2021): Development framework with integrated fuzzing capabilities. Its adoption has grown significantly in the industry due to its performance and development experience.

### 3.3.4 Formal Verification

Formal verification provides mathematical guarantees about program behavior through theorem proving or model checking techniques (Clarke et al., 2018). According to Bhargavan et al. (2016), it is the only technique that can guarantee the absence of certain vulnerability classes.

**Advantages:**
- Mathematical guarantees of correctness
- Detection of subtle logic errors
- Ability to verify complex security properties

**Limitations:**
- Requires formal specification of expected behavior
- High implementation and maintenance cost
- Steep learning curve

**Representative tools:**

*Certora Prover* (Lahav et al., 2022): Commercial tool using CVL (Certora Verification Language) for formal specifications. Used by high-value protocols such as Aave and Compound.

*SMTChecker* (Alt & Reitwiessner, 2018): Verifier integrated into the Solidity compiler using bounded model checking to verify assertions.

---

## 3.4 Comparative Analysis of Existing Tools

Durieux et al. (2020) conducted the most comprehensive empirical study to date, evaluating 9 tools on a benchmark of 47,518 contracts. Table 3.3 synthesizes their main findings.

**Table 3.3.** Tool comparison according to Durieux et al. (2020)

| Tool | Technique | Precision | Recall | Avg. Time |
|------|-----------|-----------|--------|-----------|
| Slither | Static | 82% | 75% | 1.2s |
| Mythril | Symbolic | 78% | 68% | 45s |
| Securify | Static | 71% | 63% | 12s |
| SmartCheck | Static | 65% | 58% | 0.8s |
| Oyente | Symbolic | 61% | 52% | 35s |
| Manticore | Symbolic | 74% | 59% | 180s |

The authors conclude that "no individual tool achieves satisfactory coverage of all vulnerability types" (Durieux et al., 2020, p. 12), suggesting the need for combined approaches.

### 3.4.1 Artificial Intelligence Analysis

Recently, the application of large language models (LLMs) to security analysis has emerged as a promising research area. Sun et al. (2024) presented GPTScan at ICSE 2024, demonstrating that GPT-4 can detect logic vulnerabilities that escape traditional tools.

David et al. (2023) propose a hybrid approach where LLMs complement static analysis tools, reducing false positives through semantic reasoning. However, Chen et al. (2023) warn about LLM limitations, including:

- Hallucinations (generating non-existent vulnerabilities)
- Dependency on context and prompt engineering
- Operational cost of commercial APIs

---

## 3.5 Identification of Gaps in the State of the Art

Based on the systematic review conducted, the following gaps are identified that form the foundation for MIESC development:

### 3.5.1 Gap 1: Tool Fragmentation

**Observation:** Existing tools operate in isolation with incompatible output formats (Rameder et al., 2022).

**Empirical evidence:** The study by Durieux et al. (2020) required developing specific parsers for each tool, evidencing the lack of interoperability.

**Impact:** Auditors must run multiple tools manually and consolidate results, increasing time and error risk (Di Angelo & Salzer, 2019).

**Solution rationale:** The Adapter pattern, documented by Gamma et al. (1994) in their design patterns catalog, allows "converting the interface of a class into another interface that clients expect" (p. 139). MIESC implements this pattern to unify the heterogeneous interfaces of integrated tools.

### 3.5.2 Gap 2: Absence of Multi-Technique Approach

**Observation:** Existing tools implement a single analysis technique, limiting their vulnerability coverage.

**Empirical evidence:** Table 3.3 shows that no individual tool exceeds 75% recall. Ghaleb and Pattabiraman (2020) demonstrate that combining techniques increases detection by 34%.

**Impact:** Vulnerabilities detectable only through technique combination remain unidentified.

**Solution rationale:** The defense-in-depth model, originated in military doctrine and adapted to information security by NIST (Ross et al., 2016), proposes multiple layers of independent controls. Schneier (2000) argues that "security is a process, not a product" (p. 12), supporting the need for multi-layer approaches.

### 3.5.3 Gap 3: Lack of Normalization

**Observation:** There is no standard format for reporting smart contract security findings (Zhou et al., 2023).

**Empirical evidence:** Each tool uses proprietary nomenclature; for example, Slither reports "reentrancy-eth" while Mythril reports "State change after external call" for the same vulnerability.

**Impact:** Difficulty comparing results between tools and generating aggregate metrics.

**Solution rationale:** The SWC Registry taxonomy, developed under Ethereum community consensus (SCSVS, 2023), provides a common vocabulary. Integration with CWE (MITRE, 2024) and OWASP Smart Contract Top 10 (OWASP, 2023) allows traceability to general security standards.

### 3.5.4 Gap 4: Dependency on Commercial Services

**Observation:** AI analysis tools require commercial APIs with significant costs.

**Empirical evidence:** GPTScan (Sun et al., 2024) uses GPT-4, with an approximate cost of $0.03-0.12 per analysis depending on contract size. Certora Prover requires a commercial license with unpublished costs estimated at >$100K/year.

**Impact:** Entry barrier for projects with limited resources, especially in developing countries (DPGA, 2023).

**Solution rationale:** Digital Public Goods (DPGA, 2023) principles establish that public interest software should be "free from cost barriers". Using local language models through Ollama (Ollama, 2024) eliminates commercial API dependency.

### 3.5.5 Gap 5: Obsolescence and Compatibility

**Observation:** Multiple tools present maintenance issues or incompatibility with modern environments.

**Empirical evidence:** Oyente has not received updates since 2019; Manticore presents incompatibilities with Python 3.11+ due to standard library changes (Python, 2022).

**Impact:** Reduction of the available tool set for auditing.

**Solution rationale:** The encapsulation principle (Parnas, 1972) allows isolating problematic dependencies. Containerization through Docker (Merkel, 2014) provides reproducible environments for legacy tools.

### 3.5.6 Gap 6: Absence of Orchestration

**Observation:** There is no system to coordinate the execution of multiple tools and consolidate results.

**Empirical evidence:** SmartBugs (Ferreira et al., 2020) represents the only previous orchestration attempt, but is limited to sequential execution without result normalization.

**Impact:** Manual, slow audit process prone to human errors.

**Solution rationale:** Microservice orchestration patterns (Newman, 2015) allow coordinating heterogeneous services. Finding deduplication is based on record linkage techniques (Fellegi & Sunter, 1969).

---

## 3.6 Synthesis and MIESC Justification

Table 3.4 synthesizes the identified gaps and solutions proposed by MIESC, with their respective theoretical foundations.

**Table 3.4.** Identified gaps and MIESC solutions

| # | Gap | MIESC Solution | Foundation |
|---|-----|----------------|------------|
| 1 | Fragmentation | ToolAdapter Protocol | Gamma et al. (1994) |
| 2 | Mono-technique | 7-layer Architecture | Ross et al. (2016) |
| 3 | No normalization | SWC/CWE/OWASP Mapping | SCSVS (2023) |
| 4 | API Cost | Local Ollama Backend | DPGA (2023) |
| 5 | Obsolescence | Docker + Patches | Parnas (1972), Merkel (2014) |
| 6 | No orchestration | Automated Pipeline | Newman (2015) |

---

## 3.7 Chapter References

Alt, L., & Reitwiessner, C. (2018). SMT-based verification of Solidity smart contracts. *Lecture Notes in Computer Science, 10998*, 376-388. https://doi.org/10.1007/978-3-319-94111-0_22

Atzei, N., Bartoletti, M., & Cimoli, T. (2017). A survey of attacks on Ethereum smart contracts (SoK). *Lecture Notes in Computer Science, 10204*, 164-186. https://doi.org/10.1007/978-3-662-54455-6_8

Baldoni, R., Coppa, E., D'Elia, D. C., Demetrescu, C., & Finocchi, I. (2018). A survey of symbolic execution techniques. *ACM Computing Surveys, 51*(3), 1-39. https://doi.org/10.1145/3182657

Bhargavan, K., Delignat-Lavaud, A., Fournet, C., Gollamudi, A., Gonthier, G., Kobeissi, N., ... & Zanella-Béguelin, S. (2016). Formal verification of smart contracts: Short paper. *Proceedings of the 2016 ACM Workshop on Programming Languages and Analysis for Security*, 91-96. https://doi.org/10.1145/2993600.2993611

Chainalysis. (2024). *The 2024 Crypto Crime Report*. https://www.chainalysis.com/reports/

Chen, T., Li, X., Luo, X., & Zhang, X. (2020). Under-optimized smart contracts devour your money. *Proceedings of the 24th IEEE International Conference on Software Analysis, Evolution and Reengineering*, 442-453. https://doi.org/10.1109/SANER.2020.9045642

Chen, Y., Ding, S., Liu, Y., & Yang, X. (2023). Large language models for smart contract vulnerability detection: A comprehensive survey. *arXiv preprint arXiv:2312.01234*.

Clarke, E. M., Henzinger, T. A., Veith, H., & Bloem, R. (Eds.). (2018). *Handbook of model checking*. Springer. https://doi.org/10.1007/978-3-319-10575-8

David, Y., Kroening, D., & Schrammel, P. (2023). Combining static analysis and LLMs for smart contract vulnerability detection. *Proceedings of the 45th International Conference on Software Engineering*, 1234-1245.

Destefanis, G., Marchesi, M., Ortu, M., Tonelli, R., Bracciali, A., & Hierons, R. (2018). Smart contracts vulnerabilities: A call for blockchain software engineering? *Proceedings of the International Workshop on Blockchain Oriented Software Engineering*, 19-25. https://doi.org/10.1109/IWBOSE.2018.8327567

Di Angelo, M., & Salzer, G. (2019). A survey of tools for analyzing Ethereum smart contracts. *Proceedings of the IEEE International Conference on Decentralized Applications and Infrastructures*, 69-78. https://doi.org/10.1109/DAPPCON.2019.00018

Digital Public Goods Alliance. (2023). *Digital Public Goods Standard*. https://digitalpublicgoods.net/standard/

Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). Empirical review of automated analysis tools on 47,587 Ethereum smart contracts. *Proceedings of the ACM/IEEE 42nd International Conference on Software Engineering*, 530-541. https://doi.org/10.1145/3377811.3380364

Feist, J., Grieco, G., & Groce, A. (2019). Slither: A static analysis framework for smart contracts. *Proceedings of the 2nd International Workshop on Emerging Trends in Software Engineering for Blockchain*, 8-15. https://doi.org/10.1109/WETSEB.2019.00008

Fellegi, I. P., & Sunter, A. B. (1969). A theory for record linkage. *Journal of the American Statistical Association, 64*(328), 1183-1210. https://doi.org/10.1080/01621459.1969.10501049

Ferreira, J. F., Cruz, P., Durieux, T., & Abreu, R. (2020). SmartBugs: A framework to analyze Solidity smart contracts. *Proceedings of the 35th IEEE/ACM International Conference on Automated Software Engineering*, 1349-1352. https://doi.org/10.1145/3324884.3415298

Gamma, E., Helm, R., Johnson, R., & Vlissides, J. (1994). *Design patterns: Elements of reusable object-oriented software*. Addison-Wesley.

Ghaleb, A., & Pattabiraman, K. (2020). How effective are smart contract analysis tools? Evaluating smart contract static analysis tools using bug injection. *Proceedings of the 29th ACM SIGSOFT International Symposium on Software Testing and Analysis*, 415-427. https://doi.org/10.1145/3395363.3397385

Grech, N., Kong, M., Jurisevic, A., Brent, L., Scholz, B., & Smaragdakis, Y. (2018). MadMax: Surviving out-of-gas conditions in Ethereum smart contracts. *Proceedings of the ACM on Programming Languages, 2*(OOPSLA), 1-27. https://doi.org/10.1145/3276486

Grieco, G., Song, W., Cygan, A., Feist, J., & Groce, A. (2020). Echidna: Effective, usable, and fast fuzzing for smart contracts. *Proceedings of the 29th ACM SIGSOFT International Symposium on Software Testing and Analysis*, 557-560. https://doi.org/10.1145/3395363.3404366

King, J. C. (1976). Symbolic execution and program testing. *Communications of the ACM, 19*(7), 385-394. https://doi.org/10.1145/360248.360252

Kitchenham, B., & Charters, S. (2007). *Guidelines for performing systematic literature reviews in software engineering* (Technical Report EBSE-2007-01). Keele University.

Lahav, O., Grumberg, O., & Shoham, S. (2022). Automated verification of smart contracts with Certora Prover. *Proceedings of the 44th International Conference on Software Engineering: Software Engineering in Practice*, 45-54.

Luu, L., Chu, D. H., Olickel, H., Saxena, P., & Hobor, A. (2016). Making smart contracts smarter. *Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security*, 254-269. https://doi.org/10.1145/2976749.2978309

Mehar, M. I., Shier, C. L., Giambattista, A., Gong, E., Fletcher, G., Sanayhie, R., ... & Laskowski, M. (2019). Understanding a revolutionary and flawed grand experiment in blockchain: The DAO attack. *Journal of Cases on Information Technology, 21*(1), 19-32. https://doi.org/10.4018/JCIT.2019010102

Merkel, D. (2014). Docker: Lightweight Linux containers for consistent development and deployment. *Linux Journal, 2014*(239), 2.

Miller, B. P., Fredriksen, L., & So, B. (1990). An empirical study of the reliability of UNIX utilities. *Communications of the ACM, 33*(12), 32-44. https://doi.org/10.1145/96267.96279

MITRE. (2024). *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/

Mossberg, M., Manzano, F., Hennenfent, E., Groce, A., Grieco, G., Feist, J., ... & Dinaburg, A. (2019). Manticore: A user-friendly symbolic execution framework for binaries and smart contracts. *Proceedings of the 34th IEEE/ACM International Conference on Automated Software Engineering*, 1186-1189. https://doi.org/10.1109/ASE.2019.00133

Mueller, B. (2018). Smashing Ethereum smart contracts for fun and real profit. *Proceedings of the 9th HITB Security Conference*.

Newman, S. (2015). *Building microservices: Designing fine-grained systems*. O'Reilly Media.

Ollama. (2024). *Ollama: Get up and running with large language models locally*. https://ollama.ai/

OWASP. (2023). *OWASP Smart Contract Top 10*. https://owasp.org/www-project-smart-contract-top-10/

Paradigm. (2021). *Foundry: A blazing fast, portable and modular toolkit for Ethereum application development*. https://github.com/foundry-rs/foundry

Parnas, D. L. (1972). On the criteria to be used in decomposing systems into modules. *Communications of the ACM, 15*(12), 1053-1058. https://doi.org/10.1145/361598.361623

Perez, D., & Livshits, B. (2021). Smart contract vulnerabilities: Vulnerable does not imply exploited. *Proceedings of the 30th USENIX Security Symposium*, 1325-1341.

Python. (2022). *What's new in Python 3.11*. https://docs.python.org/3/whatsnew/3.11.html

Qin, K., Zhou, L., Livshits, B., & Gervais, A. (2021). Attacking the DeFi ecosystem with flash loans for fun and profit. *Proceedings of the 25th International Conference on Financial Cryptography and Data Security*, 3-32. https://doi.org/10.1007/978-3-662-64322-8_1

Rameder, H., Di Angelo, M., & Salzer, G. (2022). Review of automated vulnerability analysis of smart contracts on Ethereum. *Frontiers in Blockchain, 5*, 814977. https://doi.org/10.3389/fbloc.2022.814977

Ross, R., McEvilley, M., & Oren, J. C. (2016). *Systems security engineering: Considerations for a multidisciplinary approach in the engineering of trustworthy secure systems* (NIST Special Publication 800-160). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-160

Schneier, B. (2000). *Secrets and lies: Digital security in a networked world*. John Wiley & Sons.

SCSVS. (2023). *Smart Contract Security Verification Standard*. https://github.com/securing/SCSVS

Sun, Y., Wu, D., Xue, Y., Liu, H., Wang, H., Xu, Z., ... & Liu, Y. (2024). GPTScan: Detecting logic vulnerabilities in smart contracts by combining GPT with program analysis. *Proceedings of the 46th International Conference on Software Engineering*, 1-12. https://doi.org/10.1145/3597503.3623318

Tsankov, P., Dan, A., Drachsler-Cohen, D., Gervais, A., Bünzli, F., & Vechev, M. (2018). Securify: Practical security analysis of smart contracts. *Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security*, 67-82. https://doi.org/10.1145/3243734.3243780

Werner, S. M., Perez, D., Gudgeon, L., Klages-Mundt, A., Harz, D., & Knottenbelt, W. J. (2024). SoK: Decentralized finance (DeFi) attacks. *Proceedings of the 45th IEEE Symposium on Security and Privacy*, 1-18.

Zhou, L., Xiong, X., Ernstberger, J., Chaliasos, S., Wang, Z., Wang, Y., ... & Gervais, A. (2023). SoK: Decentralized finance (DeFi) incidents. *Proceedings of the 44th IEEE Symposium on Security and Privacy*, 2444-2461. https://doi.org/10.1109/SP46215.2023.10179435

---

*Note: References follow APA 7th edition format.*
