// =============================================================================
// Example Hardhat Configuration with MIESC Integration
// =============================================================================
// Copy this file to your Hardhat project root and rename to hardhat.config.js
// Customize the settings as needed for your project.
// =============================================================================

require("@nomicfoundation/hardhat-toolbox");
require("hardhat-miesc"); // Add MIESC plugin

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },

  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },

  // =============================================================================
  // MIESC Configuration
  // =============================================================================
  miesc: {
    // Enable/disable plugin
    enabled: true,

    // Run MIESC after every compilation
    // Set to true for continuous security feedback
    runOnCompile: false,

    // Fail build on security issues
    failOnError: true,

    // Minimum severity to fail on: critical, high, medium, low
    failOn: "high",

    // Timeout in seconds
    timeout: 300,

    // Audit type: quick (4 tools), full (all 9 layers), layer (specific layer)
    auditType: "quick",

    // Layer number (1-9) when using "layer" audit type
    // Layer 1: Static Analysis (Slither, Aderyn, Solhint)
    // Layer 2: Dynamic Testing (Echidna, Medusa, Foundry)
    // Layer 3: Symbolic Execution (Mythril, Manticore, Halmos)
    // Layer 4: Formal Verification (Certora, SMTChecker)
    // Layer 5: Property Testing (PropertyGPT, Wake, Vertigo)
    // Layer 6: AI/LLM Analysis (SmartLLM, GPTScan)
    // Layer 7: Pattern Recognition (DA-GNN, SmartGuard)
    // Layer 8: DeFi Security (DeFi Analyzer, MEV Detector)
    // Layer 9: Advanced Detection (Threat Model, SmartBugs)
    layer: null,

    // Output format: text, json, sarif, markdown
    outputFormat: "text",

    // Save output to file (null = stdout only)
    outputFile: null,

    // Custom contracts path (null = use Hardhat's sources path)
    contractsPath: null,

    // Patterns to exclude from analysis
    exclude: ["**/mocks/**", "**/test/**"],

    // Verbose output
    verbose: false,
  },
};

// =============================================================================
// Alternative: TypeScript Configuration (hardhat.config.ts)
// =============================================================================
/*
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-miesc";

const config: HardhatUserConfig = {
  solidity: "0.8.20",
  miesc: {
    enabled: true,
    runOnCompile: false,
    failOnError: true,
    failOn: "high",
    auditType: "quick",
  },
};

export default config;
*/

// =============================================================================
// Usage Examples:
//
//   npx hardhat miesc                    # Run quick audit
//   npx hardhat miesc --type full        # Run full 9-layer audit
//   npx hardhat miesc --type layer --layer 1   # Run layer 1 only
//   npx hardhat miesc --output json --file report.json
//   npx hardhat miesc --ci --fail-on critical  # CI mode
//   npx hardhat miesc:quick              # Alias for quick audit
//   npx hardhat miesc:full               # Alias for full audit
//   npx hardhat miesc:layer 3            # Run specific layer
//   npx hardhat miesc:doctor             # Check MIESC installation
//   npx hardhat miesc:version            # Show MIESC version
//
// =============================================================================
