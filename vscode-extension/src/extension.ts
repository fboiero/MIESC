/**
 * MIESC Security Auditor - VS Code Extension
 *
 * Multi-layer Intelligent Evaluation for Smart Contracts
 * Provides real-time security analysis for Solidity smart contracts.
 *
 * Author: Fernando Boiero
 * Institution: UNDEF - IUA
 * License: GPL-3.0
 */

import * as vscode from 'vscode';
import axios from 'axios';
import * as path from 'path';
import * as fs from 'fs';
import { MIESCCli, CLIAuditResult, CLIFinding } from './services/miescCli';

// Types
interface MIESCFinding {
    id: string;
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    line?: number;
    column?: number;
    endLine?: number;
    endColumn?: number;
    tool: string;
    swc_id?: string;
    cwe_id?: string;
    recommendation?: string;
    confidence: number;
}

interface MIESCAuditResult {
    success: boolean;
    findings: MIESCFinding[];
    execution_time_ms: number;
    layers_executed: number[];
    tools_used: string[];
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        total: number;
    };
}

// Global state
let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let lastAuditResult: MIESCAuditResult | null = null;
let serverProcess: any = null;
let miescCli: MIESCCli;
let useCli: boolean = true; // Prefer CLI mode by default
let scanDebounceTimer: NodeJS.Timeout | undefined;
const SCAN_DEBOUNCE_MS = 1500; // Debounce delay for real-time scanning

// Decoration types for inline highlighting
const criticalDecorationType = vscode.window.createTextEditorDecorationType({
    backgroundColor: new vscode.ThemeColor('miesc.criticalBackground'),
    overviewRulerColor: '#ff0000',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
        contentText: ' [CRITICAL]',
        color: '#ff0000'
    }
});

const highDecorationType = vscode.window.createTextEditorDecorationType({
    backgroundColor: new vscode.ThemeColor('miesc.highBackground'),
    overviewRulerColor: '#ff6600',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
        contentText: ' [HIGH]',
        color: '#ff6600'
    }
});

const mediumDecorationType = vscode.window.createTextEditorDecorationType({
    backgroundColor: new vscode.ThemeColor('miesc.mediumBackground'),
    overviewRulerColor: '#ffcc00',
    overviewRulerLane: vscode.OverviewRulerLane.Right
});

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext) {
    console.log('MIESC Security Auditor is now active');

    // Initialize components
    diagnosticCollection = vscode.languages.createDiagnosticCollection('miesc');
    outputChannel = vscode.window.createOutputChannel('MIESC Security');

    // Initialize CLI client
    miescCli = new MIESCCli(outputChannel);

    // Read CLI preference from configuration
    const cliConfig = vscode.workspace.getConfiguration('miesc');
    useCli = cliConfig.get<boolean>('useCli') !== false; // Default to true

    // Check CLI availability if CLI mode is preferred
    if (useCli) {
        miescCli.isAvailable().then(async available => {
            if (available) {
                const version = await miescCli.getVersion();
                outputChannel.appendLine(`MIESC CLI available (v${version})`);
                useCli = true;
            } else {
                outputChannel.appendLine('MIESC CLI not found. Install with: pip install miesc');
                outputChannel.appendLine('Falling back to REST API mode.');
                useCli = false;
            }
        });
    } else {
        outputChannel.appendLine('CLI mode disabled by configuration. Using REST API mode.');
    }

    // Listen for configuration changes
    vscode.workspace.onDidChangeConfiguration(e => {
        if (e.affectsConfiguration('miesc.useCli')) {
            const newUseCli = vscode.workspace.getConfiguration('miesc').get<boolean>('useCli') !== false;
            if (newUseCli !== useCli) {
                useCli = newUseCli;
                outputChannel.appendLine(`Mode changed to: ${useCli ? 'CLI' : 'REST API'}`);
                if (useCli) {
                    miescCli.isAvailable().then(available => {
                        if (!available) {
                            vscode.window.showWarningMessage(
                                'MIESC CLI not found. Install with: pip install miesc'
                            );
                            useCli = false;
                        }
                    });
                }
            }
        }
        if (e.affectsConfiguration('miesc.pythonPath')) {
            miescCli.updatePythonPath();
        }
    });

    // Status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'miesc.showReport';
    statusBarItem.text = '$(shield) MIESC';
    statusBarItem.tooltip = 'MIESC Security Auditor - Click for last report';
    statusBarItem.show();

    // Register commands
    const commands = [
        vscode.commands.registerCommand('miesc.auditCurrentFile', auditCurrentFile),
        vscode.commands.registerCommand('miesc.auditWorkspace', auditWorkspace),
        vscode.commands.registerCommand('miesc.auditSelection', auditSelection),
        vscode.commands.registerCommand('miesc.quickScan', quickScan),
        vscode.commands.registerCommand('miesc.deepAudit', deepAudit),
        vscode.commands.registerCommand('miesc.showReport', showReport),
        vscode.commands.registerCommand('miesc.configureLayers', configureLayers),
        vscode.commands.registerCommand('miesc.startServer', startServer),
        vscode.commands.registerCommand('miesc.stopServer', stopServer)
    ];

    commands.forEach(cmd => context.subscriptions.push(cmd));
    context.subscriptions.push(diagnosticCollection);
    context.subscriptions.push(outputChannel);
    context.subscriptions.push(statusBarItem);

    // Auto-audit on save (if enabled)
    const config = vscode.workspace.getConfiguration('miesc');
    if (config.get('autoAuditOnSave')) {
        // Debounced on-save scanning
        const saveHandler = vscode.workspace.onDidSaveTextDocument(async (document) => {
            if (document.languageId === 'solidity') {
                await quickScan();
            }
        });
        context.subscriptions.push(saveHandler);

        // Real-time scanning on document change (debounced)
        const changeHandler = vscode.workspace.onDidChangeTextDocument((event) => {
            if (event.document.languageId === 'solidity' && event.contentChanges.length > 0) {
                // Clear existing timer
                if (scanDebounceTimer) {
                    clearTimeout(scanDebounceTimer);
                }

                // Set new debounced scan
                scanDebounceTimer = setTimeout(async () => {
                    // Only run quick scan if document is saved or if changes are significant
                    if (!event.document.isDirty) {
                        await runAudit(event.document.uri.fsPath, [1], false);
                    } else {
                        // For unsaved documents, run a lightweight pattern check
                        runLightweightCheck(event.document);
                    }
                }, SCAN_DEBOUNCE_MS);
            }
        });
        context.subscriptions.push(changeHandler);
    }

    // Register tree view providers
    vscode.window.registerTreeDataProvider('miesc.findings', new FindingsTreeProvider());
    vscode.window.registerTreeDataProvider('miesc.layers', new LayersTreeProvider());

    // Register hover provider for Solidity files
    const hoverProvider = vscode.languages.registerHoverProvider('solidity', new MIESCHoverProvider());
    context.subscriptions.push(hoverProvider);

    // Register code actions provider for quick fixes
    const codeActionsProvider = vscode.languages.registerCodeActionsProvider(
        'solidity',
        new MIESCCodeActionsProvider(),
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    );
    context.subscriptions.push(codeActionsProvider);

    outputChannel.appendLine('MIESC Security Auditor activated');
    outputChannel.appendLine(`Server URL: ${config.get('serverUrl')}`);
}

/**
 * Extension deactivation
 */
export function deactivate() {
    if (serverProcess) {
        serverProcess.kill();
    }
    outputChannel.appendLine('MIESC Security Auditor deactivated');
}

/**
 * Audit the current file
 */
async function auditCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active file to audit');
        return;
    }

    if (editor.document.languageId !== 'solidity') {
        vscode.window.showWarningMessage('Current file is not a Solidity file');
        return;
    }

    const config = vscode.workspace.getConfiguration('miesc');
    const layers = config.get<number[]>('defaultLayers') || [1, 2, 3, 7];

    await runAudit(editor.document.uri.fsPath, layers);
}

/**
 * Audit all Solidity files in workspace
 */
async function auditWorkspace() {
    const files = await vscode.workspace.findFiles('**/*.sol', '**/node_modules/**');

    if (files.length === 0) {
        vscode.window.showWarningMessage('No Solidity files found in workspace');
        return;
    }

    const config = vscode.workspace.getConfiguration('miesc');
    const layers = config.get<number[]>('defaultLayers') || [1, 2, 3, 7];

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'MIESC Workspace Audit',
        cancellable: true
    }, async (progress, token) => {
        for (let i = 0; i < files.length; i++) {
            if (token.isCancellationRequested) {
                break;
            }
            progress.report({
                increment: (100 / files.length),
                message: `Auditing ${path.basename(files[i].fsPath)} (${i + 1}/${files.length})`
            });
            await runAudit(files[i].fsPath, layers, false);
        }
    });

    vscode.window.showInformationMessage(`MIESC: Audited ${files.length} files`);
}

/**
 * Audit selected code
 */
async function auditSelection() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
        vscode.window.showWarningMessage('No code selected');
        return;
    }

    const selectedText = editor.document.getText(editor.selection);

    // Create temporary file with selection
    const tempDir = path.join(vscode.workspace.rootPath || '/tmp', '.miesc-temp');
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }

    const tempFile = path.join(tempDir, 'selection.sol');
    fs.writeFileSync(tempFile, selectedText);

    await runAudit(tempFile, [1, 3], true);

    // Cleanup
    fs.unlinkSync(tempFile);
}

/**
 * Quick scan - Layer 1 only (Static Analysis)
 */
async function quickScan() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== 'solidity') {
        return;
    }

    await runAudit(editor.document.uri.fsPath, [1]);
}

/**
 * Lightweight pattern-based check for real-time feedback
 * Runs without calling external tools - pure regex matching
 */
function runLightweightCheck(document: vscode.TextDocument) {
    const text = document.getText();
    const diagnostics: vscode.Diagnostic[] = [];

    // Define vulnerability patterns
    const patterns: { pattern: RegExp; severity: vscode.DiagnosticSeverity; message: string; code: string }[] = [
        {
            pattern: /\.call\{.*?\}\([^)]*\)(?![^;]*require|[^;]*assert|[^;]*success)/g,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'Unchecked call return value - consider checking success',
            code: 'SWC-104'
        },
        {
            pattern: /tx\.origin/g,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'tx.origin used for authorization - use msg.sender instead',
            code: 'SWC-115'
        },
        {
            pattern: /pragma solidity \^/g,
            severity: vscode.DiagnosticSeverity.Information,
            message: 'Floating pragma - consider locking to specific version',
            code: 'SWC-103'
        },
        {
            pattern: /selfdestruct\s*\(/g,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'selfdestruct detected - ensure proper access control',
            code: 'SWC-106'
        },
        {
            pattern: /delegatecall\s*\(/g,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'delegatecall detected - ensure target is trusted',
            code: 'SWC-112'
        },
        {
            pattern: /block\.(timestamp|number)\s*[<>=]/g,
            severity: vscode.DiagnosticSeverity.Information,
            message: 'Block property used for comparison - may be manipulable',
            code: 'SWC-116'
        },
        {
            pattern: /assembly\s*\{/g,
            severity: vscode.DiagnosticSeverity.Information,
            message: 'Inline assembly detected - verify carefully',
            code: 'SWC-127'
        },
        {
            pattern: /\.transfer\s*\(/g,
            severity: vscode.DiagnosticSeverity.Information,
            message: 'transfer() has fixed gas stipend - may fail with complex receivers',
            code: 'SWC-134'
        },
        {
            pattern: /blockhash\s*\([^)]*\)\s*%/g,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Weak randomness using blockhash - easily predictable',
            code: 'SWC-120'
        },
        {
            pattern: /\brevert\s*\(\s*\)/g,
            severity: vscode.DiagnosticSeverity.Information,
            message: 'Empty revert - consider adding error message',
            code: 'INFO-001'
        }
    ];

    for (const { pattern, severity, message, code } of patterns) {
        let match;
        while ((match = pattern.exec(text)) !== null) {
            const startPos = document.positionAt(match.index);
            const endPos = document.positionAt(match.index + match[0].length);
            const range = new vscode.Range(startPos, endPos);

            const diagnostic = new vscode.Diagnostic(range, `[MIESC] ${message}`, severity);
            diagnostic.source = 'MIESC (real-time)';
            diagnostic.code = code;
            diagnostics.push(diagnostic);
        }
    }

    diagnosticCollection.set(document.uri, diagnostics);

    // Update status bar with real-time count
    const errors = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
    const warnings = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;
    if (errors > 0 || warnings > 0) {
        updateStatusBar(`$(shield) ${errors}E ${warnings}W (live)`);
    } else {
        updateStatusBar('$(shield) MIESC');
    }
}

/**
 * Deep audit - All 9 layers
 */
async function deepAudit() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== 'solidity') {
        vscode.window.showWarningMessage('Open a Solidity file to run deep audit');
        return;
    }

    await runAudit(editor.document.uri.fsPath, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
}

/**
 * Run the audit using MIESC CLI or API
 */
async function runAudit(filePath: string, layers: number[], showNotification: boolean = true) {
    const config = vscode.workspace.getConfiguration('miesc');

    updateStatusBar('$(sync~spin) Auditing...');
    outputChannel.appendLine(`\n--- Audit Started: ${path.basename(filePath)} ---`);
    outputChannel.appendLine(`Layers: ${layers.join(', ')}`);
    outputChannel.appendLine(`Mode: ${useCli ? 'CLI' : 'REST API'}`);

    try {
        let result: MIESCAuditResult;

        if (useCli) {
            // Use CLI mode (preferred)
            result = await runAuditCli(filePath, layers);
        } else {
            // Fall back to REST API
            result = await runAuditApi(filePath, layers);
        }

        lastAuditResult = result;

        // Process results
        processAuditResults(filePath, result);

        // Update UI
        const summary = result.summary;
        updateStatusBar(`$(shield) ${summary.critical}C ${summary.high}H ${summary.medium}M`);

        outputChannel.appendLine(`\nResults:`);
        outputChannel.appendLine(`  Critical: ${summary.critical}`);
        outputChannel.appendLine(`  High: ${summary.high}`);
        outputChannel.appendLine(`  Medium: ${summary.medium}`);
        outputChannel.appendLine(`  Low: ${summary.low}`);
        outputChannel.appendLine(`  Execution time: ${result.execution_time_ms}ms`);

        if (showNotification) {
            const total = summary.critical + summary.high + summary.medium;
            if (total > 0) {
                vscode.window.showWarningMessage(
                    `MIESC found ${total} issues (${summary.critical}C, ${summary.high}H, ${summary.medium}M)`,
                    'Show Report'
                ).then(selection => {
                    if (selection === 'Show Report') {
                        showReport();
                    }
                });
            } else {
                vscode.window.showInformationMessage('MIESC: No significant issues found');
            }
        }

    } catch (error: any) {
        outputChannel.appendLine(`Error: ${error.message}`);
        updateStatusBar('$(shield) MIESC Error');
        vscode.window.showErrorMessage(`MIESC Error: ${error.message}`);
    }
}

/**
 * Run audit using CLI
 */
async function runAuditCli(filePath: string, layers: number[]): Promise<MIESCAuditResult> {
    let cliResult: CLIAuditResult;

    if (layers.length === 1 && layers[0] === 1) {
        // Quick scan
        cliResult = await miescCli.quickAudit(filePath);
    } else if (layers.length === 9) {
        // Full audit
        cliResult = await miescCli.fullAudit(filePath);
    } else {
        // Custom layers - use detectors for now
        cliResult = await miescCli.runDetectors(filePath);
    }

    // Convert CLI result to MIESCAuditResult format
    return {
        success: cliResult.success,
        findings: cliResult.findings.map(f => ({
            id: f.id,
            type: f.category,
            severity: f.severity,
            title: f.title,
            description: f.description,
            line: f.line,
            column: f.column,
            tool: f.tool,
            swc_id: f.swc_id,
            cwe_id: f.cwe_id,
            recommendation: f.recommendation,
            confidence: f.confidence
        })),
        execution_time_ms: cliResult.execution_time_ms,
        layers_executed: cliResult.layers_executed,
        tools_used: cliResult.tools_used,
        summary: cliResult.summary
    };
}

/**
 * Run audit using REST API
 */
async function runAuditApi(filePath: string, layers: number[]): Promise<MIESCAuditResult> {
    const config = vscode.workspace.getConfiguration('miesc');
    const serverUrl = config.get<string>('serverUrl') || 'http://localhost:8000';
    const timeout = (config.get<number>('timeout') || 300) * 1000;

    try {
        const response = await axios.post(`${serverUrl}/mcp/run_audit`, {
            contract_path: filePath,
            layers: layers,
            use_local_llm: config.get('useLocalLLM'),
            ollama_model: config.get('ollamaModel')
        }, {
            timeout: timeout
        });

        return response.data;
    } catch (error: any) {
        if (error.code === 'ECONNREFUSED') {
            // Try CLI as fallback
            if (await miescCli.isAvailable()) {
                outputChannel.appendLine('Server not available, falling back to CLI...');
                useCli = true;
                return runAuditCli(filePath, layers);
            }
            throw new Error('MIESC server not running and CLI not available. Install MIESC: pip install miesc');
        }
        throw error;
    }
}

/**
 * Process audit results and update diagnostics
 */
function processAuditResults(filePath: string, result: MIESCAuditResult) {
    const uri = vscode.Uri.file(filePath);
    const diagnostics: vscode.Diagnostic[] = [];
    const config = vscode.workspace.getConfiguration('miesc');
    const severityThreshold = config.get<string>('severityThreshold') || 'medium';
    const showInline = config.get<boolean>('showInlineWarnings') !== false;

    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const thresholdIndex = severityOrder.indexOf(severityThreshold);

    for (const finding of result.findings) {
        const findingSeverityIndex = severityOrder.indexOf(finding.severity);

        if (findingSeverityIndex > thresholdIndex) {
            continue;
        }

        const line = (finding.line || 1) - 1;
        const range = new vscode.Range(
            new vscode.Position(line, finding.column || 0),
            new vscode.Position(finding.endLine ? finding.endLine - 1 : line, finding.endColumn || 100)
        );

        const severity = getSeverity(finding.severity);
        const message = formatDiagnosticMessage(finding);

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = 'MIESC';
        diagnostic.code = finding.swc_id || finding.type;
        diagnostics.push(diagnostic);
    }

    diagnosticCollection.set(uri, diagnostics);

    // Apply decorations if enabled
    if (showInline) {
        applyDecorations(filePath, result.findings);
    }
}

/**
 * Apply inline decorations
 */
function applyDecorations(filePath: string, findings: MIESCFinding[]) {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.uri.fsPath !== filePath) {
        return;
    }

    const criticalRanges: vscode.Range[] = [];
    const highRanges: vscode.Range[] = [];
    const mediumRanges: vscode.Range[] = [];

    for (const finding of findings) {
        const line = (finding.line || 1) - 1;
        const range = new vscode.Range(
            new vscode.Position(line, 0),
            new vscode.Position(line, 1000)
        );

        switch (finding.severity) {
            case 'critical':
                criticalRanges.push(range);
                break;
            case 'high':
                highRanges.push(range);
                break;
            case 'medium':
                mediumRanges.push(range);
                break;
        }
    }

    editor.setDecorations(criticalDecorationType, criticalRanges);
    editor.setDecorations(highDecorationType, highRanges);
    editor.setDecorations(mediumDecorationType, mediumRanges);
}

/**
 * Format diagnostic message
 */
function formatDiagnosticMessage(finding: MIESCFinding): string {
    let message = `[${finding.severity.toUpperCase()}] ${finding.title}`;

    if (finding.swc_id) {
        message += ` (${finding.swc_id})`;
    }

    message += `\n\n${finding.description}`;

    if (finding.recommendation) {
        message += `\n\nRecommendation: ${finding.recommendation}`;
    }

    message += `\n\nDetected by: ${finding.tool} (confidence: ${Math.round(finding.confidence * 100)}%)`;

    return message;
}

/**
 * Get VS Code severity from MIESC severity
 */
function getSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'critical':
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        case 'low':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

/**
 * Show last audit report
 */
function showReport() {
    if (!lastAuditResult) {
        vscode.window.showInformationMessage('No audit results available. Run an audit first.');
        return;
    }

    const panel = vscode.window.createWebviewPanel(
        'miescReport',
        'MIESC Audit Report',
        vscode.ViewColumn.Beside,
        { enableScripts: true }
    );

    panel.webview.html = generateReportHtml(lastAuditResult);
}

/**
 * Generate HTML report
 */
function generateReportHtml(result: MIESCAuditResult): string {
    const findings = result.findings.map(f => `
        <div class="finding ${f.severity}">
            <div class="finding-header">
                <span class="severity-badge ${f.severity}">${f.severity.toUpperCase()}</span>
                <span class="finding-title">${f.title}</span>
                ${f.swc_id ? `<span class="swc-id">${f.swc_id}</span>` : ''}
            </div>
            <p class="finding-description">${f.description}</p>
            ${f.line ? `<p class="finding-location">Line: ${f.line}</p>` : ''}
            ${f.recommendation ? `<p class="finding-recommendation"><strong>Recommendation:</strong> ${f.recommendation}</p>` : ''}
            <p class="finding-tool">Detected by: ${f.tool} (${Math.round(f.confidence * 100)}% confidence)</p>
        </div>
    `).join('');

    return `<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: var(--vscode-font-family); padding: 20px; }
        .summary { display: flex; gap: 10px; margin-bottom: 20px; }
        .summary-item { padding: 10px 20px; border-radius: 5px; text-align: center; }
        .summary-item.critical { background: #ff0000; color: white; }
        .summary-item.high { background: #ff6600; color: white; }
        .summary-item.medium { background: #ffcc00; color: black; }
        .summary-item.low { background: #0066ff; color: white; }
        .finding { margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid; }
        .finding.critical { border-color: #ff0000; background: #ff000010; }
        .finding.high { border-color: #ff6600; background: #ff660010; }
        .finding.medium { border-color: #ffcc00; background: #ffcc0010; }
        .finding.low { border-color: #0066ff; background: #0066ff10; }
        .severity-badge { padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
        .severity-badge.critical { background: #ff0000; color: white; }
        .severity-badge.high { background: #ff6600; color: white; }
        .severity-badge.medium { background: #ffcc00; color: black; }
        .severity-badge.low { background: #0066ff; color: white; }
        .finding-title { font-weight: bold; margin-left: 10px; }
        .swc-id { color: #888; margin-left: 10px; }
        .finding-description { margin: 10px 0; }
        .finding-tool { color: #888; font-size: 12px; }
        .finding-recommendation { background: #f0f0f0; padding: 10px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>MIESC Security Audit Report</h1>

    <div class="summary">
        <div class="summary-item critical">
            <div style="font-size: 24px; font-weight: bold;">${result.summary.critical}</div>
            <div>Critical</div>
        </div>
        <div class="summary-item high">
            <div style="font-size: 24px; font-weight: bold;">${result.summary.high}</div>
            <div>High</div>
        </div>
        <div class="summary-item medium">
            <div style="font-size: 24px; font-weight: bold;">${result.summary.medium}</div>
            <div>Medium</div>
        </div>
        <div class="summary-item low">
            <div style="font-size: 24px; font-weight: bold;">${result.summary.low}</div>
            <div>Low</div>
        </div>
    </div>

    <p><strong>Execution Time:</strong> ${result.execution_time_ms}ms</p>
    <p><strong>Layers Executed:</strong> ${result.layers_executed.join(', ')}</p>
    <p><strong>Tools Used:</strong> ${result.tools_used.join(', ')}</p>

    <h2>Findings (${result.findings.length})</h2>
    ${findings || '<p>No issues found!</p>'}
</body>
</html>`;
}

/**
 * Configure layers dialog
 */
async function configureLayers() {
    const config = vscode.workspace.getConfiguration('miesc');
    const currentLayers = config.get<number[]>('defaultLayers') || [1, 2, 3, 7];

    const layerOptions = [
        { label: 'Layer 1: Static Analysis', description: 'Slither, Aderyn, Solhint', picked: currentLayers.includes(1), layer: 1 },
        { label: 'Layer 2: Dynamic Testing', description: 'Echidna, Medusa, Foundry, DogeFuzz', picked: currentLayers.includes(2), layer: 2 },
        { label: 'Layer 3: Symbolic Execution', description: 'Mythril, Manticore, Halmos', picked: currentLayers.includes(3), layer: 3 },
        { label: 'Layer 4: Formal Verification', description: 'Certora, SMTChecker', picked: currentLayers.includes(4), layer: 4 },
        { label: 'Layer 5: Property Testing', description: 'PropertyGPT, Wake, Vertigo', picked: currentLayers.includes(5), layer: 5 },
        { label: 'Layer 6: AI/LLM Analysis', description: 'SmartLLM, GPTScan, LLMSmartAudit', picked: currentLayers.includes(6), layer: 6 },
        { label: 'Layer 7: Pattern Recognition', description: 'DA-GNN, SmartGuard, Clone Detector', picked: currentLayers.includes(7), layer: 7 },
        { label: 'Layer 8: DeFi Security', description: 'DeFi Analyzer, MEV Detector, Gas Analyzer', picked: currentLayers.includes(8), layer: 8 },
        { label: 'Layer 9: Advanced Detection', description: 'Advanced Detector, SmartBugs, Threat Model', picked: currentLayers.includes(9), layer: 9 }
    ];

    const selected = await vscode.window.showQuickPick(layerOptions, {
        canPickMany: true,
        placeHolder: 'Select analysis layers to run by default'
    });

    if (selected) {
        const newLayers = selected.map(s => s.layer);
        await config.update('defaultLayers', newLayers, vscode.ConfigurationTarget.Global);
        vscode.window.showInformationMessage(`MIESC: Default layers updated to ${newLayers.join(', ')}`);
    }
}

/**
 * Start MIESC server
 */
async function startServer() {
    const config = vscode.workspace.getConfiguration('miesc');
    const pythonPath = config.get<string>('pythonPath') || 'python3';
    const miescPath = config.get<string>('miescPath') || '';

    outputChannel.appendLine('Starting MIESC server...');

    // TODO: Implement actual server start using child_process
    vscode.window.showInformationMessage(
        'To start the server, run: python -m uvicorn src.miesc_mcp_rest:app --reload',
        'Copy Command'
    ).then(selection => {
        if (selection === 'Copy Command') {
            vscode.env.clipboard.writeText('python -m uvicorn src.miesc_mcp_rest:app --reload');
        }
    });
}

/**
 * Stop MIESC server
 */
function stopServer() {
    if (serverProcess) {
        serverProcess.kill();
        serverProcess = null;
        vscode.window.showInformationMessage('MIESC server stopped');
    }
}

/**
 * Update status bar
 */
function updateStatusBar(text: string) {
    statusBarItem.text = text;
}

/**
 * Tree provider for findings view
 */
class FindingsTreeProvider implements vscode.TreeDataProvider<FindingItem> {
    getTreeItem(element: FindingItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: FindingItem): FindingItem[] {
        if (!lastAuditResult || element) {
            return [];
        }

        return lastAuditResult.findings.map(f => new FindingItem(
            f.title,
            f.severity,
            f.line,
            f.tool
        ));
    }
}

class FindingItem extends vscode.TreeItem {
    constructor(
        public readonly title: string,
        public readonly severity: string,
        public readonly line: number | undefined,
        public readonly tool: string
    ) {
        super(title, vscode.TreeItemCollapsibleState.None);
        this.description = `Line ${line || '?'} - ${tool}`;
        this.tooltip = `${severity.toUpperCase()}: ${title}`;
        this.iconPath = new vscode.ThemeIcon(
            severity === 'critical' || severity === 'high' ? 'error' : 'warning',
            new vscode.ThemeColor(severity === 'critical' ? 'errorForeground' : 'warningForeground')
        );
    }
}

/**
 * Tree provider for layers view
 */
class LayersTreeProvider implements vscode.TreeDataProvider<LayerItem> {
    getTreeItem(element: LayerItem): vscode.TreeItem {
        return element;
    }

    getChildren(): LayerItem[] {
        return [
            new LayerItem('Layer 1', 'Static Analysis', 'Slither, Aderyn, Solhint'),
            new LayerItem('Layer 2', 'Dynamic Testing', 'Echidna, Medusa, Foundry, DogeFuzz'),
            new LayerItem('Layer 3', 'Symbolic Execution', 'Mythril, Manticore, Halmos'),
            new LayerItem('Layer 4', 'Formal Verification', 'Certora, SMTChecker'),
            new LayerItem('Layer 5', 'Property Testing', 'PropertyGPT, Wake, Vertigo'),
            new LayerItem('Layer 6', 'AI/LLM Analysis', 'SmartLLM, GPTScan, LLMSmartAudit'),
            new LayerItem('Layer 7', 'Pattern Recognition', 'DA-GNN, SmartGuard'),
            new LayerItem('Layer 8', 'DeFi Security', 'DeFi Analyzer, MEV Detector'),
            new LayerItem('Layer 9', 'Advanced Detection', 'SmartBugs, Threat Model')
        ];
    }
}

class LayerItem extends vscode.TreeItem {
    constructor(
        public readonly layer: string,
        public readonly technique: string,
        public readonly tools: string
    ) {
        super(`${layer}: ${technique}`, vscode.TreeItemCollapsibleState.None);
        this.description = tools;
        this.tooltip = `${layer} - ${technique}\nTools: ${tools}`;
        this.iconPath = new vscode.ThemeIcon('layers');
    }
}

/**
 * Hover provider for showing vulnerability details on hover
 */
class MIESCHoverProvider implements vscode.HoverProvider {
    provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.Hover> {
        if (!lastAuditResult) {
            return null;
        }

        const line = position.line + 1;
        const findings = lastAuditResult.findings.filter(f => f.line === line);

        if (findings.length === 0) {
            return null;
        }

        const markdownContent = new vscode.MarkdownString();
        markdownContent.isTrusted = true;

        for (const finding of findings) {
            const severityIcon = finding.severity === 'critical' ? '🔴' :
                                finding.severity === 'high' ? '🟠' :
                                finding.severity === 'medium' ? '🟡' : '🔵';

            markdownContent.appendMarkdown(`### ${severityIcon} ${finding.title}\n\n`);
            markdownContent.appendMarkdown(`**Severity:** ${finding.severity.toUpperCase()}\n\n`);
            markdownContent.appendMarkdown(`${finding.description}\n\n`);

            if (finding.swc_id) {
                markdownContent.appendMarkdown(`**SWC ID:** [${finding.swc_id}](https://swcregistry.io/docs/${finding.swc_id})\n\n`);
            }

            if (finding.recommendation) {
                markdownContent.appendMarkdown(`**Recommendation:** ${finding.recommendation}\n\n`);
            }

            markdownContent.appendMarkdown(`*Detected by ${finding.tool} (${Math.round(finding.confidence * 100)}% confidence)*\n\n`);
            markdownContent.appendMarkdown('---\n\n');
        }

        return new vscode.Hover(markdownContent);
    }
}

/**
 * Code actions provider for quick fixes
 */
class MIESCCodeActionsProvider implements vscode.CodeActionProvider {

    // Common vulnerability fixes
    private readonly fixes: { [key: string]: { title: string; fix: string }[] } = {
        'reentrancy': [
            {
                title: 'Add ReentrancyGuard modifier',
                fix: '// Add: import "@openzeppelin/contracts/security/ReentrancyGuard.sol";\n// Inherit: contract MyContract is ReentrancyGuard\n// Add modifier: nonReentrant'
            },
            {
                title: 'Use Checks-Effects-Interactions pattern',
                fix: '// Move state changes before external calls'
            }
        ],
        'unchecked-call': [
            {
                title: 'Add return value check',
                fix: '(bool success, ) = target.call{value: amount}("");\nrequire(success, "Call failed");'
            }
        ],
        'tx-origin': [
            {
                title: 'Replace tx.origin with msg.sender',
                fix: '// Replace tx.origin with msg.sender for authentication'
            }
        ],
        'floating-pragma': [
            {
                title: 'Lock Solidity version',
                fix: 'pragma solidity 0.8.20; // Lock to specific version'
            }
        ],
        'missing-zero-check': [
            {
                title: 'Add zero address check',
                fix: 'require(addr != address(0), "Zero address not allowed");'
            }
        ],
        'unprotected-selfdestruct': [
            {
                title: 'Add access control',
                fix: 'require(msg.sender == owner, "Only owner can destroy");'
            }
        ],
        'integer-overflow': [
            {
                title: 'Use SafeMath or Solidity 0.8+',
                fix: '// Solidity 0.8+ has built-in overflow checks\n// For older versions: import "@openzeppelin/contracts/utils/math/SafeMath.sol";'
            }
        ],
        'delegatecall': [
            {
                title: 'Add trusted contract check',
                fix: 'require(trustedContracts[target], "Untrusted delegatecall target");'
            }
        ],
        'timestamp-dependence': [
            {
                title: 'Use block.number instead',
                fix: '// Use block.number for timing if acceptable\n// Or accept minor timestamp manipulation risk with require(block.timestamp > lastTime + minDelay);'
            }
        ],
        'dos-gas': [
            {
                title: 'Implement pull pattern',
                fix: '// Use pull-over-push pattern:\n// mapping(address => uint256) public pendingWithdrawals;\n// function withdraw() external { uint256 amount = pendingWithdrawals[msg.sender]; ... }'
            }
        ],
        'access-control': [
            {
                title: 'Add onlyOwner modifier',
                fix: 'modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }'
            },
            {
                title: 'Use OpenZeppelin Ownable',
                fix: '// import "@openzeppelin/contracts/access/Ownable.sol";\n// contract MyContract is Ownable { ... }'
            }
        ],
        'front-running': [
            {
                title: 'Add commit-reveal scheme',
                fix: '// Implement commit-reveal:\n// 1. commit(hash) - store keccak256(value, secret)\n// 2. reveal(value, secret) - verify and execute'
            }
        ],
        'weak-randomness': [
            {
                title: 'Use Chainlink VRF',
                fix: '// import "@chainlink/contracts/src/v0.8/vrf/VRFConsumerBaseV2.sol";\n// Use Chainlink VRF for secure randomness'
            }
        ],
        'arbitrary-send': [
            {
                title: 'Validate recipient address',
                fix: 'require(allowedRecipients[to], "Recipient not allowed");\n// Or: require(to == msg.sender, "Can only withdraw to self");'
            }
        ],
        'uninitialized-storage': [
            {
                title: 'Initialize storage pointer',
                fix: '// Declare storage variables with explicit storage location\nDataStruct storage myData = storageMapping[key];'
            }
        ],
        'shadowing': [
            {
                title: 'Rename shadowed variable',
                fix: '// Rename the local variable to avoid shadowing state variable'
            }
        ],
        'deprecated': [
            {
                title: 'Update deprecated function',
                fix: '// Common updates:\n// sha3() -> keccak256()\n// throw -> revert()\n// constant -> view or pure\n// var -> explicit type'
            }
        ]
    };

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // Get diagnostics for this range
        const diagnostics = context.diagnostics.filter(d => d.source === 'MIESC');

        for (const diagnostic of diagnostics) {
            const vulnType = this.getVulnerabilityType(diagnostic);

            if (vulnType && this.fixes[vulnType]) {
                for (const fixTemplate of this.fixes[vulnType]) {
                    const action = new vscode.CodeAction(
                        `MIESC: ${fixTemplate.title}`,
                        vscode.CodeActionKind.QuickFix
                    );

                    action.diagnostics = [diagnostic];

                    // Create comment with fix suggestion
                    action.edit = new vscode.WorkspaceEdit();
                    const lineStart = new vscode.Position(diagnostic.range.start.line, 0);
                    const comment = `// MIESC Fix: ${fixTemplate.title}\n// ${fixTemplate.fix.split('\n').join('\n// ')}\n`;
                    action.edit.insert(document.uri, lineStart, comment);

                    actions.push(action);
                }
            }

            // Add generic "Acknowledge" action
            const acknowledgeAction = new vscode.CodeAction(
                'MIESC: Mark as reviewed',
                vscode.CodeActionKind.QuickFix
            );
            acknowledgeAction.diagnostics = [diagnostic];
            acknowledgeAction.edit = new vscode.WorkspaceEdit();
            const lineEnd = document.lineAt(diagnostic.range.start.line).range.end;
            acknowledgeAction.edit.insert(
                document.uri,
                lineEnd,
                ' // MIESC-REVIEWED: acknowledged'
            );
            actions.push(acknowledgeAction);
        }

        return actions;
    }

    private getVulnerabilityType(diagnostic: vscode.Diagnostic): string | null {
        const message = diagnostic.message.toLowerCase();

        if (message.includes('reentrancy') || message.includes('reentrant')) {
            return 'reentrancy';
        }
        if (message.includes('unchecked') && (message.includes('call') || message.includes('return'))) {
            return 'unchecked-call';
        }
        if (message.includes('tx.origin')) {
            return 'tx-origin';
        }
        if (message.includes('pragma') && message.includes('float')) {
            return 'floating-pragma';
        }
        if (message.includes('zero') && message.includes('address')) {
            return 'missing-zero-check';
        }
        if (message.includes('selfdestruct')) {
            return 'unprotected-selfdestruct';
        }
        if (message.includes('overflow') || message.includes('underflow')) {
            return 'integer-overflow';
        }
        if (message.includes('delegatecall')) {
            return 'delegatecall';
        }
        if (message.includes('timestamp') || message.includes('block.timestamp') || message.includes('now')) {
            return 'timestamp-dependence';
        }
        if (message.includes('denial of service') || message.includes('dos') || message.includes('gas limit')) {
            return 'dos-gas';
        }
        if (message.includes('access control') || message.includes('unauthorized') || message.includes('missing modifier')) {
            return 'access-control';
        }
        if (message.includes('front-run') || message.includes('frontrun') || message.includes('sandwich')) {
            return 'front-running';
        }
        if (message.includes('random') && (message.includes('weak') || message.includes('predict') || message.includes('blockhash'))) {
            return 'weak-randomness';
        }
        if (message.includes('arbitrary') && message.includes('send')) {
            return 'arbitrary-send';
        }
        if (message.includes('uninitialized') && message.includes('storage')) {
            return 'uninitialized-storage';
        }
        if (message.includes('shadow')) {
            return 'shadowing';
        }
        if (message.includes('deprecated') || message.includes('sha3') || message.includes('throw')) {
            return 'deprecated';
        }

        return null;
    }
}
