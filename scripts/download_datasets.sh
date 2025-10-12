#!/bin/bash
#
# Download Public Solidity Datasets for Xaudit v2.0
# Downloads and organizes benchmark datasets for smart contract security testing
#

set -e

DATASETS_DIR="datasets"
mkdir -p "$DATASETS_DIR"

echo "🔍 Xaudit v2.0 - Dataset Downloader"
echo "===================================="
echo ""

# Function to download and extract dataset
download_dataset() {
    local name=$1
    local url=$2
    local dir=$3

    echo "📦 Downloading: $name"
    echo "   URL: $url"
    echo "   Destination: $dir"

    mkdir -p "$DATASETS_DIR/$dir"

    if [ -d "$DATASETS_DIR/$dir/.git" ]; then
        echo "   ✓ Already exists (git repo), pulling updates..."
        (cd "$DATASETS_DIR/$dir" && git pull)
    else
        echo "   ⬇ Cloning repository..."
        git clone "$url" "$DATASETS_DIR/$dir"
    fi

    echo "   ✅ Done!"
    echo ""
}

# 1. SmartBugs Curated - 142 annotated vulnerable contracts
download_dataset \
    "SmartBugs Curated" \
    "https://github.com/smartbugs/smartbugs-curated.git" \
    "smartbugs-curated"

# 2. SolidiFI-benchmark - 9,369 injected bugs
download_dataset \
    "SolidiFI Benchmark" \
    "https://github.com/DependableSystemsLab/SolidiFI-benchmark.git" \
    "solidifi-benchmark"

# 3. Smart Contract Dataset - 12K contracts
echo "📦 Downloading: Smart Contract Dataset (12K contracts)"
echo "   Note: This is a large dataset, downloading may take a while..."

if [ ! -d "$DATASETS_DIR/smart-contract-dataset" ]; then
    download_dataset \
        "Smart Contract Dataset" \
        "https://github.com/Catxiaobai/Smart-Contract-Dataset.git" \
        "smart-contract-dataset"
else
    echo "   ✓ Already exists, skipping..."
    echo ""
fi

# 4. VeriSmart-benchmarks - 129 contracts for formal verification
download_dataset \
    "VeriSmart Benchmarks" \
    "https://github.com/kupl/VeriSmart-benchmarks.git" \
    "verismart-benchmarks"

# 5. Not So Smart Contracts - Real vulnerability examples
download_dataset \
    "Not So Smart Contracts" \
    "https://github.com/crytic/not-so-smart-contracts.git" \
    "not-so-smart-contracts"

# 6. smartbugs-wild - 47,398 contracts from Ethereum
echo "📦 Downloading: SmartBugs Wild (47K+ contracts)"
echo "   ⚠️  WARNING: This is a VERY large dataset (several GB)"
echo "   Skipping by default. To download, run manually:"
echo "   git clone https://github.com/smartbugs/smartbugs-wild.git datasets/smartbugs-wild"
echo ""

# Create summary
echo "📊 Dataset Summary"
echo "=================="
echo ""

# Count contracts in each dataset
count_contracts() {
    local dir=$1
    local pattern=$2
    local count=$(find "$DATASETS_DIR/$dir" -name "$pattern" 2>/dev/null | wc -l | tr -d ' ')
    echo "$count"
}

SMARTBUGS_COUNT=$(count_contracts "smartbugs-curated" "*.sol")
SOLIDIFI_COUNT=$(count_contracts "solidifi-benchmark" "*.sol")
SMARTCONTRACT_COUNT=$(count_contracts "smart-contract-dataset" "*.sol")
VERISMART_COUNT=$(count_contracts "verismart-benchmarks" "*.sol")
NOTSO_COUNT=$(count_contracts "not-so-smart-contracts" "*.sol")

echo "Dataset                      | Contracts | Annotated | Purpose"
echo "-----------------------------|-----------|-----------|----------------------------------"
echo "SmartBugs Curated            | $SMARTBUGS_COUNT       | Yes       | Vulnerability detection"
echo "SolidiFI Benchmark           | $SOLIDIFI_COUNT    | Yes       | Injected bugs (7 types)"
echo "Smart Contract Dataset       | $SMARTCONTRACT_COUNT   | Partial   | Large-scale testing"
echo "VeriSmart Benchmarks         | $VERISMART_COUNT       | Yes       | Formal verification"
echo "Not So Smart Contracts       | $NOTSO_COUNT       | Yes       | Real vulnerability examples"
echo ""
echo "Total: ~$(($SMARTBUGS_COUNT + $SOLIDIFI_COUNT + $SMARTCONTRACT_COUNT + $VERISMART_COUNT + $NOTSO_COUNT)) contracts downloaded"
echo ""

# Create metadata file
cat > "$DATASETS_DIR/README.md" << 'EOF'
# Xaudit v2.0 - Public Datasets

This directory contains public datasets for benchmarking and testing the Xaudit framework.

## Datasets Included

### 1. SmartBugs Curated
- **Source**: https://github.com/smartbugs/smartbugs-curated
- **Contracts**: 142
- **Annotation**: Fully annotated with vulnerability types
- **Categories**: Reentrancy, Access Control, Arithmetic, Unchecked Calls, etc.
- **Purpose**: Ground truth for vulnerability detection benchmarking

### 2. SolidiFI Benchmark
- **Source**: https://github.com/DependableSystemsLab/SolidiFI-benchmark
- **Contracts**: 9,369
- **Annotation**: Injected bugs with known locations
- **Bug Types**: 7 categories (Reentrancy, TOD, Timestamp Dependency, etc.)
- **Purpose**: Controlled testing with known vulnerabilities

### 3. Smart Contract Dataset
- **Source**: https://github.com/Catxiaobai/Smart-Contract-Dataset
- **Contracts**: ~12,000
- **Annotation**: Partial (8 vulnerability types)
- **Purpose**: Large-scale testing and statistical analysis

### 4. VeriSmart Benchmarks
- **Source**: https://github.com/kupl/VeriSmart-benchmarks
- **Contracts**: 129
- **Annotation**: Formal specifications
- **Purpose**: Formal verification testing (Certora, Foundry Invariants)

### 5. Not So Smart Contracts
- **Source**: https://github.com/crytic/not-so-smart-contracts
- **Contracts**: ~50+
- **Annotation**: Detailed explanations
- **Purpose**: Real-world vulnerability examples from Crytic/Trail of Bits

### 6. SmartBugs Wild (Optional)
- **Source**: https://github.com/smartbugs/smartbugs-wild
- **Contracts**: 47,398
- **Annotation**: No
- **Purpose**: Wild corpus from Ethereum mainnet
- **Note**: VERY large dataset, download manually if needed

## Usage with Xaudit

### Run Single Dataset
```bash
python scripts/run_benchmark.py --dataset smartbugs-curated
```

### Run All Datasets
```bash
python scripts/run_benchmark.py --all
```

### Generate Comparison Report
```bash
python scripts/compare_tools.py --datasets smartbugs-curated solidifi-benchmark
```

## Directory Structure
```
datasets/
├── smartbugs-curated/
│   ├── reentrancy/
│   ├── access_control/
│   └── ...
├── solidifi-benchmark/
│   ├── bugs_injection/
│   └── ...
├── smart-contract-dataset/
│   ├── contracts/
│   └── ...
├── verismart-benchmarks/
│   └── ...
└── not-so-smart-contracts/
    ├── reentrancy/
    ├── bad_randomness/
    └── ...
```

## License

Each dataset has its own license. Please refer to the original repositories for licensing information.

## Citation

If using these datasets in research, please cite the original papers:

**SmartBugs:**
```
@inproceedings{ferreira2020smartbugs,
  title={SmartBugs: A Framework to Analyze Solidity Smart Contracts},
  author={Ferreira, Jo{\~a}o F and others},
  booktitle={ASE 2020},
  year={2020}
}
```

**SolidiFI:**
```
@inproceedings{so2021solidifi,
  title={SolidiFI: An Automated Vulnerability Detection Tool for Ethereum Smart Contracts},
  author={So, Sunbeom and others},
  booktitle={ICSE-NIER 2021},
  year={2021}
}
```

---

**Note**: Dataset metadata generated automatically by `download_datasets.sh`
EOF

echo "✅ All datasets downloaded successfully!"
echo ""
echo "📁 Location: $(pwd)/$DATASETS_DIR"
echo "📖 Documentation: $DATASETS_DIR/README.md"
echo ""
echo "Next steps:"
echo "  1. Run benchmark: python scripts/run_benchmark.py --dataset smartbugs-curated"
echo "  2. Compare tools: python scripts/compare_tools.py --all"
echo "  3. View results: python src/utils/web_dashboard.py --results analysis/benchmark"
echo ""
