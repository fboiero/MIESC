/**
 * hardhat-miesc - Hardhat plugin for MIESC smart contract security analysis
 *
 * MIESC: Multi-layer Intelligent Evaluation for Smart Contracts
 * https://github.com/fboiero/MIESC
 *
 * @license AGPL-3.0
 */

const { task, subtask, types } = require("hardhat/config");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

// Default configuration
const DEFAULT_CONFIG = {
  enabled: true,
  runOnCompile: false,
  failOnError: true,
  failOn: "high", // critical, high, medium, low
  timeout: 300,
  outputFormat: "text", // text, json, sarif, markdown
  outputFile: null,
  contractsPath: null, // defaults to hardhat's sources path
  exclude: [],
  auditType: "quick", // quick, full, layer
  layer: null, // for layer audit type
  verbose: false,
};

// Extend Hardhat config
require("hardhat/config").extendConfig((config, userConfig) => {
  const miesc = userConfig.miesc || {};
  config.miesc = {
    ...DEFAULT_CONFIG,
    ...miesc,
  };
});

/**
 * Check if MIESC is installed
 */
async function checkMiescInstalled() {
  return new Promise((resolve) => {
    const proc = spawn("miesc", ["--version"], {
      stdio: "pipe",
      shell: true,
    });

    proc.on("close", (code) => {
      resolve(code === 0);
    });

    proc.on("error", () => {
      resolve(false);
    });
  });
}

/**
 * Run MIESC analysis
 */
async function runMiesc(contractsPath, config, hre) {
  const args = ["audit", config.auditType];

  // Add layer number if layer audit type
  if (config.auditType === "layer" && config.layer) {
    args.push(config.layer.toString());
  }

  // Add contracts path
  args.push(contractsPath);

  // Add CI flag if failOnError
  if (config.failOnError) {
    args.push("--ci");
    args.push("--fail-on", config.failOn);
  }

  // Add timeout
  args.push("--timeout", config.timeout.toString());

  // Add output format if not text
  if (config.outputFormat !== "text") {
    args.push("--output", config.outputFormat);
  }

  // Add verbose flag
  if (config.verbose) {
    args.push("--verbose");
  }

  if (config.verbose) {
    console.log(`\nRunning: miesc ${args.join(" ")}\n`);
  }

  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";

    const proc = spawn("miesc", args, {
      stdio: ["inherit", "pipe", "pipe"],
      shell: true,
      cwd: hre.config.paths.root,
    });

    proc.stdout.on("data", (data) => {
      const text = data.toString();
      stdout += text;
      if (config.outputFormat === "text") {
        process.stdout.write(text);
      }
    });

    proc.stderr.on("data", (data) => {
      const text = data.toString();
      stderr += text;
      process.stderr.write(text);
    });

    proc.on("close", (code) => {
      // Save output to file if specified
      if (config.outputFile && stdout) {
        const outputPath = path.resolve(hre.config.paths.root, config.outputFile);
        fs.writeFileSync(outputPath, stdout);
        console.log(`\nReport saved to: ${outputPath}`);
      }

      resolve({
        exitCode: code,
        stdout,
        stderr,
        success: code === 0,
      });
    });

    proc.on("error", (err) => {
      reject(new Error(`Failed to run MIESC: ${err.message}`));
    });
  });
}

/**
 * Parse MIESC JSON output
 */
function parseResults(output) {
  try {
    const results = JSON.parse(output);
    return {
      summary: results.summary || {},
      findings: results.findings || [],
      tools: results.tools || [],
    };
  } catch {
    return null;
  }
}

/**
 * Print summary table
 */
function printSummary(summary) {
  console.log("\n=== MIESC Security Audit Summary ===\n");
  console.log(`  Critical: ${summary.critical || 0}`);
  console.log(`  High:     ${summary.high || 0}`);
  console.log(`  Medium:   ${summary.medium || 0}`);
  console.log(`  Low:      ${summary.low || 0}`);
  console.log(`  Info:     ${summary.info || 0}`);
  console.log("");
}

// =============================================================================
// Hardhat Tasks
// =============================================================================

/**
 * Main audit task
 */
task("miesc", "Run MIESC security analysis on your contracts")
  .addOptionalParam("type", "Audit type: quick, full, or layer", "quick", types.string)
  .addOptionalParam("layer", "Layer number (1-9) when using layer type", undefined, types.int)
  .addOptionalParam("output", "Output format: text, json, sarif, markdown", "text", types.string)
  .addOptionalParam("file", "Save output to file", undefined, types.string)
  .addOptionalParam("failOn", "Fail on severity: critical, high, medium, low", "high", types.string)
  .addFlag("ci", "Enable CI mode (exit 1 on issues)")
  .addFlag("verbose", "Enable verbose output")
  .setAction(async (taskArgs, hre) => {
    console.log("\nMIESC - Multi-layer Intelligent Evaluation for Smart Contracts");
    console.log("================================================================\n");

    // Check MIESC installation
    const isInstalled = await checkMiescInstalled();
    if (!isInstalled) {
      throw new Error(
        "MIESC is not installed. Install with: pip install miesc\n" +
          "See: https://github.com/fboiero/MIESC"
      );
    }

    // Merge task args with config
    const config = {
      ...hre.config.miesc,
      auditType: taskArgs.type,
      layer: taskArgs.layer,
      outputFormat: taskArgs.output,
      outputFile: taskArgs.file,
      failOn: taskArgs.failOn,
      failOnError: taskArgs.ci || hre.config.miesc.failOnError,
      verbose: taskArgs.verbose || hre.config.miesc.verbose,
    };

    // Validate layer audit
    if (config.auditType === "layer" && !config.layer) {
      throw new Error("Layer number (1-9) required for layer audit type. Use --layer <number>");
    }

    // Get contracts path
    const contractsPath = config.contractsPath || hre.config.paths.sources;

    if (!fs.existsSync(contractsPath)) {
      throw new Error(`Contracts directory not found: ${contractsPath}`);
    }

    console.log(`Analyzing contracts in: ${contractsPath}`);
    console.log(`Audit type: ${config.auditType}${config.layer ? ` (layer ${config.layer})` : ""}`);
    console.log(`Fail on: ${config.failOn}`);
    console.log("");

    // Run MIESC
    const result = await runMiesc(contractsPath, config, hre);

    // Parse and display results for JSON output
    if (config.outputFormat === "json" && result.stdout) {
      const parsed = parseResults(result.stdout);
      if (parsed) {
        printSummary(parsed.summary);
      }
      // Print JSON to console if not saved to file
      if (!config.outputFile) {
        console.log(result.stdout);
      }
    }

    // Handle exit code
    if (!result.success && config.failOnError) {
      throw new Error(`MIESC found security issues (severity >= ${config.failOn})`);
    }

    return result;
  });

/**
 * Quick scan task (alias)
 */
task("miesc:quick", "Run quick MIESC security scan").setAction(async (_, hre) => {
  return hre.run("miesc", { type: "quick" });
});

/**
 * Full audit task (alias)
 */
task("miesc:full", "Run full 9-layer MIESC security audit").setAction(async (_, hre) => {
  return hre.run("miesc", { type: "full" });
});

/**
 * Layer-specific audit task
 */
task("miesc:layer", "Run specific layer audit")
  .addPositionalParam("layerNum", "Layer number (1-9)", undefined, types.int)
  .setAction(async (taskArgs, hre) => {
    return hre.run("miesc", { type: "layer", layer: taskArgs.layerNum });
  });

/**
 * Doctor task - check MIESC installation
 */
task("miesc:doctor", "Check MIESC installation and available tools").setAction(async () => {
  console.log("\nChecking MIESC installation...\n");

  const isInstalled = await checkMiescInstalled();
  if (!isInstalled) {
    console.log("MIESC is NOT installed.");
    console.log("\nInstall with: pip install miesc");
    console.log("See: https://github.com/fboiero/MIESC");
    return { installed: false };
  }

  console.log("MIESC is installed. Running diagnostics...\n");

  // Run miesc doctor
  return new Promise((resolve) => {
    const proc = spawn("miesc", ["doctor"], {
      stdio: "inherit",
      shell: true,
    });

    proc.on("close", (code) => {
      resolve({ installed: true, doctorExitCode: code });
    });
  });
});

/**
 * Version task
 */
task("miesc:version", "Show MIESC version").setAction(async () => {
  return new Promise((resolve) => {
    const proc = spawn("miesc", ["--version"], {
      stdio: "inherit",
      shell: true,
    });

    proc.on("close", () => {
      resolve();
    });
  });
});

// =============================================================================
// Compile Hook
// =============================================================================

// Hook into compile task if runOnCompile is enabled
subtask("compile:solidity:log:compilation-result").setAction(
  async (args, hre, runSuper) => {
    await runSuper(args);

    if (hre.config.miesc.enabled && hre.config.miesc.runOnCompile) {
      console.log("\nRunning MIESC security analysis (post-compile)...\n");
      try {
        await hre.run("miesc", {
          type: hre.config.miesc.auditType,
          layer: hre.config.miesc.layer,
          output: hre.config.miesc.outputFormat,
          file: hre.config.miesc.outputFile,
          failOn: hre.config.miesc.failOn,
          ci: hre.config.miesc.failOnError,
          verbose: hre.config.miesc.verbose,
        });
      } catch (error) {
        if (hre.config.miesc.failOnError) {
          throw error;
        }
        console.error(`MIESC warning: ${error.message}`);
      }
    }
  }
);

module.exports = {};
