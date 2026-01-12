/**
 * MIESC CLI Service
 *
 * Executes MIESC CLI directly without requiring a server.
 * This is the preferred method for local analysis.
 */

import * as vscode from 'vscode';
import * as child_process from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

export interface CLIFinding {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    category: string;
    description: string;
    recommendation: string;
    location: string;
    line?: number;
    column?: number;
    tool: string;
    confidence: number;
    swc_id?: string;
    cwe_id?: string;
}

export interface CLIAuditResult {
    success: boolean;
    contract: string;
    timestamp: string;
    execution_time_ms: number;
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        total: number;
    };
    findings: CLIFinding[];
    tools_used: string[];
    layers_executed: number[];
}

export class MIESCCli {
    private outputChannel: vscode.OutputChannel;
    private pythonPath: string;

    constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
        this.pythonPath = vscode.workspace.getConfiguration('miesc').get('pythonPath', 'python3');
    }

    /**
     * Check if MIESC CLI is available
     */
    async isAvailable(): Promise<boolean> {
        try {
            const result = await this.execCommand(`${this.pythonPath} -m miesc --version`);
            return result.includes('MIESC') || result.includes('miesc');
        } catch {
            // Try direct miesc command
            try {
                const result = await this.execCommand('miesc --version');
                return result.includes('MIESC') || result.includes('miesc');
            } catch {
                return false;
            }
        }
    }

    /**
     * Get MIESC version
     */
    async getVersion(): Promise<string> {
        try {
            const result = await this.execCommand(`${this.pythonPath} -m miesc --version`);
            const match = result.match(/(\d+\.\d+\.\d+)/);
            return match ? match[1] : 'unknown';
        } catch {
            return 'unknown';
        }
    }

    /**
     * Run quick audit on a file
     */
    async quickAudit(filePath: string): Promise<CLIAuditResult> {
        return this.runAudit(filePath, 'quick');
    }

    /**
     * Run full audit on a file
     */
    async fullAudit(filePath: string): Promise<CLIAuditResult> {
        return this.runAudit(filePath, 'full');
    }

    /**
     * Run audit with specific layers
     */
    async auditWithLayers(filePath: string, layers: number[]): Promise<CLIAuditResult> {
        const layerArg = `--layers ${layers.join(',')}`;
        return this.runAudit(filePath, 'quick', layerArg);
    }

    /**
     * Run custom detectors on a file
     */
    async runDetectors(filePath: string): Promise<CLIAuditResult> {
        const outputFile = path.join(os.tmpdir(), `miesc-detectors-${Date.now()}.json`);

        try {
            const cmd = `${this.pythonPath} -m miesc detectors run "${filePath}" --output "${outputFile}"`;
            this.outputChannel.appendLine(`[MIESC CLI] Running: ${cmd}`);

            await this.execCommand(cmd, 120000);

            if (fs.existsSync(outputFile)) {
                const content = fs.readFileSync(outputFile, 'utf8');
                const result = JSON.parse(content);
                fs.unlinkSync(outputFile);
                return this.normalizeResult(result, filePath);
            }

            throw new Error('No output file generated');
        } catch (error: any) {
            this.outputChannel.appendLine(`[MIESC CLI] Error: ${error.message}`);
            throw error;
        }
    }

    /**
     * Run audit command
     */
    private async runAudit(filePath: string, auditType: string, extraArgs: string = ''): Promise<CLIAuditResult> {
        const outputFile = path.join(os.tmpdir(), `miesc-audit-${Date.now()}.json`);
        const config = vscode.workspace.getConfiguration('miesc');
        const timeout = (config.get<number>('timeout') || 300) * 1000;

        try {
            const cmd = `${this.pythonPath} -m miesc audit ${auditType} "${filePath}" --output json ${extraArgs} > "${outputFile}"`;
            this.outputChannel.appendLine(`[MIESC CLI] Running: ${cmd}`);

            const startTime = Date.now();
            await this.execCommand(cmd, timeout);
            const executionTime = Date.now() - startTime;

            if (fs.existsSync(outputFile)) {
                const content = fs.readFileSync(outputFile, 'utf8');

                // Handle case where output might have non-JSON prefix
                const jsonStart = content.indexOf('{');
                const jsonContent = jsonStart >= 0 ? content.substring(jsonStart) : content;

                try {
                    const result = JSON.parse(jsonContent);
                    fs.unlinkSync(outputFile);
                    return this.normalizeResult(result, filePath, executionTime);
                } catch {
                    // If JSON parsing fails, try to extract findings from text output
                    fs.unlinkSync(outputFile);
                    return this.parseTextOutput(content, filePath, executionTime);
                }
            }

            // No output file, run without redirect and parse stdout
            const stdout = await this.execCommand(
                `${this.pythonPath} -m miesc audit ${auditType} "${filePath}" --output json ${extraArgs}`,
                timeout
            );

            return this.parseTextOutput(stdout, filePath, Date.now() - startTime);

        } catch (error: any) {
            this.outputChannel.appendLine(`[MIESC CLI] Error: ${error.message}`);

            // Return empty result on error
            return {
                success: false,
                contract: filePath,
                timestamp: new Date().toISOString(),
                execution_time_ms: 0,
                summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
                findings: [],
                tools_used: [],
                layers_executed: []
            };
        }
    }

    /**
     * Normalize result from different formats
     */
    private normalizeResult(result: any, filePath: string, executionTime?: number): CLIAuditResult {
        // Handle various result formats
        const findings: CLIFinding[] = [];

        if (Array.isArray(result.findings)) {
            for (const f of result.findings) {
                findings.push({
                    id: f.id || `finding-${findings.length}`,
                    title: f.title || f.name || 'Unknown Finding',
                    severity: this.normalizeSeverity(f.severity),
                    category: f.category || f.type || 'general',
                    description: f.description || '',
                    recommendation: f.recommendation || f.remediation || '',
                    location: f.location || f.file || filePath,
                    line: f.line || f.line_number,
                    column: f.column,
                    tool: f.tool || f.detector || 'miesc',
                    confidence: f.confidence || 0.8,
                    swc_id: f.swc_id || f.swc,
                    cwe_id: f.cwe_id || f.cwe
                });
            }
        }

        const summary = result.summary || this.calculateSummary(findings);

        return {
            success: true,
            contract: filePath,
            timestamp: new Date().toISOString(),
            execution_time_ms: executionTime || result.execution_time_ms || 0,
            summary: summary,
            findings: findings,
            tools_used: result.tools_used || result.tools || [],
            layers_executed: result.layers_executed || result.layers || []
        };
    }

    /**
     * Parse text output when JSON is not available
     */
    private parseTextOutput(output: string, filePath: string, executionTime: number): CLIAuditResult {
        const findings: CLIFinding[] = [];

        // Try to extract findings from text output
        // Pattern: [SEVERITY] Title - Location
        const findingPattern = /\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?)(?:\s+-\s+(.+?))?(?:\n|$)/gi;
        let match;

        while ((match = findingPattern.exec(output)) !== null) {
            const severity = match[1].toLowerCase() as CLIFinding['severity'];
            const title = match[2].trim();
            const location = match[3]?.trim() || filePath;

            // Extract line number if present
            const lineMatch = location.match(/:(\d+)/);
            const line = lineMatch ? parseInt(lineMatch[1]) : undefined;

            findings.push({
                id: `finding-${findings.length}`,
                title: title,
                severity: severity,
                category: 'general',
                description: title,
                recommendation: '',
                location: location,
                line: line,
                tool: 'miesc',
                confidence: 0.8
            });
        }

        return {
            success: true,
            contract: filePath,
            timestamp: new Date().toISOString(),
            execution_time_ms: executionTime,
            summary: this.calculateSummary(findings),
            findings: findings,
            tools_used: [],
            layers_executed: []
        };
    }

    /**
     * Calculate summary from findings
     */
    private calculateSummary(findings: CLIFinding[]): CLIAuditResult['summary'] {
        const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

        for (const f of findings) {
            summary[f.severity]++;
            summary.total++;
        }

        return summary;
    }

    /**
     * Normalize severity string
     */
    private normalizeSeverity(severity: string): CLIFinding['severity'] {
        const normalized = (severity || 'info').toLowerCase();
        if (['critical', 'high', 'medium', 'low', 'info'].includes(normalized)) {
            return normalized as CLIFinding['severity'];
        }
        return 'info';
    }

    /**
     * Execute a command and return stdout
     */
    private execCommand(command: string, timeout: number = 60000): Promise<string> {
        return new Promise((resolve, reject) => {
            child_process.exec(command, {
                timeout: timeout,
                maxBuffer: 50 * 1024 * 1024, // 50MB buffer
                env: { ...process.env, PYTHONUNBUFFERED: '1' }
            }, (error, stdout, stderr) => {
                if (error && !stdout) {
                    reject(error);
                    return;
                }

                // Log stderr if present
                if (stderr) {
                    this.outputChannel.appendLine(`[MIESC CLI] stderr: ${stderr}`);
                }

                resolve(stdout);
            });
        });
    }

    /**
     * Update Python path from settings
     */
    updatePythonPath(): void {
        this.pythonPath = vscode.workspace.getConfiguration('miesc').get('pythonPath', 'python3');
    }
}
