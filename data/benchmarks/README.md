# MIESC Benchmark Datasets

This directory contains benchmark datasets for evaluating MIESC detection accuracy.

## Download Datasets

Run these commands to download the benchmark datasets:

```bash
cd data/benchmarks

# SmartBugs Curated - 143 contracts with known vulnerabilities
git clone --depth 1 https://github.com/smartbugs/smartbugs-curated.git

# Damn Vulnerable DeFi - 18 DeFi challenges
git clone --depth 1 https://github.com/theredguild/damn-vulnerable-defi.git

# SWC Registry (optional) - Official weakness classification
git clone --depth 1 https://github.com/SmartContractSecurity/SWC-registry.git
```

## Dataset Statistics

| Dataset | Contracts | Categories | Source |
|---------|-----------|------------|--------|
| SmartBugs Curated | 143 | 10 DASP categories | Academic |
| Damn Vulnerable DeFi | 18 | DeFi-specific | CTF |
| SWC Registry | ~37 | SWC test cases | Official |

## Running Benchmarks

```bash
# Full benchmark
python scripts/run_benchmark.py

# Quick sample (20 contracts)
python scripts/run_benchmark.py --quick

# Specific dataset only
python scripts/run_benchmark.py --dataset smartbugs

# Compare two runs
python scripts/run_benchmark.py --compare before.json after.json
```

## Vulnerability Categories (SmartBugs)

1. **Reentrancy** - Unexpected behavior from reentrant function calls
2. **Access Control** - Missing function modifiers or tx.origin usage
3. **Arithmetic** - Integer over/underflows
4. **Unchecked Low Level Calls** - Unverified call() or delegatecall() results
5. **Denial Of Service** - Time-consuming computations overwhelming contracts
6. **Bad Randomness** - Miner-influenced outcomes
7. **Front Running** - Dependent transactions in single blocks
8. **Time Manipulation** - Block timestamp manipulation
9. **Short Addresses** - Incorrectly padded EVM arguments

## References

- [SmartBugs Paper (ICSE 2020)](https://arxiv.org/abs/1910.10601)
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/)
- [SWC Registry](https://swcregistry.io/)
