# Benchmark Datasets

This directory contains external benchmark datasets for evaluating MIESC's vulnerability detection capabilities. These datasets are excluded from version control due to their size.

## Available Datasets

### SmartBugs-Curated

Peer-reviewed academic benchmark containing 143 contracts with verified security flaws.

**Source:** [SmartBugs-curated](https://github.com/smartbugs/smartbugs-curated)
**Paper:** ICSE 2020 - "SmartBugs: A Framework to Analyze Solidity Smart Contracts"

```bash
# Download
git clone https://github.com/smartbugs/smartbugs-curated.git smartbugs-curated
```

**Categories:**
| Category | Contracts | SWC ID |
|----------|-----------|--------|
| Reentrancy | 32 | SWC-107 |
| Access Control | 19 | SWC-105/106 |
| Arithmetic | 16 | SWC-101 |
| Unchecked Calls | 53 | SWC-104 |
| Bad Randomness | 8 | SWC-120 |
| Time Manipulation | 6 | SWC-116 |
| Denial of Service | 7 | SWC-113 |
| Front Running | 5 | SWC-114 |

### SolidiFI-Benchmark

Systematic bug injection dataset with 9,369 bugs across 7 vulnerability types.

**Source:** [SolidiFI-benchmark](https://github.com/DependableSystemsLab/SolidiFI-benchmark)
**Paper:** ISSTA 2020 - "How Effective Are Smart Contract Analysis Tools? Evaluating Smart Contract Static Analysis Tools Using Bug Injection"

```bash
# Download
git clone https://github.com/DependableSystemsLab/SolidiFI-benchmark.git solidifi-benchmark
```

**Bug Types:**

- Reentrancy
- Timestamp Dependency
- Unhandled Exceptions
- Unchecked Send
- TOD (Transaction Order Dependence)
- Integer Overflow/Underflow
- tx.origin

## Quick Setup

Download all datasets:

```bash
cd benchmarks/datasets/

# SmartBugs-curated (ICSE 2020)
git clone https://github.com/smartbugs/smartbugs-curated.git

# SolidiFI (ISSTA 2020)
git clone https://github.com/DependableSystemsLab/SolidiFI-benchmark.git solidifi-benchmark
```

## Running Benchmarks

```bash
# Run SmartBugs evaluation
python benchmarks/smartbugs_evaluation.py

# Run SolidiFI evaluation
python benchmarks/integrated_evaluation.py

# Run comparative benchmark
python benchmarks/comparative_benchmark.py
```

## References

1. Ferreira Torres, C., et al. "SmartBugs: A Framework to Analyze Solidity Smart Contracts." ICSE 2020.
2. Ghaleb, A., Pattabiraman, K. "How Effective Are Smart Contract Analysis Tools? Evaluating Smart Contract Static Analysis Tools Using Bug Injection." ISSTA 2020.
