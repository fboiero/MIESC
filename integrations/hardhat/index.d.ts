/**
 * hardhat-miesc - TypeScript type definitions
 *
 * MIESC: Multi-layer Intelligent Evaluation for Smart Contracts
 * https://github.com/fboiero/MIESC
 */

import "hardhat/types/config";

declare module "hardhat/types/config" {
  export interface HardhatUserConfig {
    miesc?: MiescUserConfig;
  }

  export interface HardhatConfig {
    miesc: MiescConfig;
  }

  export interface MiescUserConfig {
    /** Enable/disable MIESC plugin (default: true) */
    enabled?: boolean;

    /** Run MIESC automatically after compilation (default: false) */
    runOnCompile?: boolean;

    /** Fail build on security issues (default: true) */
    failOnError?: boolean;

    /** Minimum severity to fail on: critical, high, medium, low (default: "high") */
    failOn?: "critical" | "high" | "medium" | "low";

    /** Timeout in seconds (default: 300) */
    timeout?: number;

    /** Output format: text, json, sarif, markdown (default: "text") */
    outputFormat?: "text" | "json" | "sarif" | "markdown";

    /** Save output to file (default: null) */
    outputFile?: string | null;

    /** Path to contracts directory (default: hardhat sources path) */
    contractsPath?: string | null;

    /** Glob patterns to exclude from analysis */
    exclude?: string[];

    /** Audit type: quick, full, layer (default: "quick") */
    auditType?: "quick" | "full" | "layer";

    /** Layer number for layer audit type (1-9) */
    layer?: number | null;

    /** Enable verbose output (default: false) */
    verbose?: boolean;
  }

  export interface MiescConfig {
    enabled: boolean;
    runOnCompile: boolean;
    failOnError: boolean;
    failOn: "critical" | "high" | "medium" | "low";
    timeout: number;
    outputFormat: "text" | "json" | "sarif" | "markdown";
    outputFile: string | null;
    contractsPath: string | null;
    exclude: string[];
    auditType: "quick" | "full" | "layer";
    layer: number | null;
    verbose: boolean;
  }
}

export interface MiescResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  success: boolean;
}

export interface MiescSummary {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
}

export interface MiescFinding {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  location?: string;
  line?: number;
  tool: string;
  recommendation?: string;
}

export interface MiescResults {
  summary: MiescSummary;
  findings: MiescFinding[];
  tools: string[];
}
