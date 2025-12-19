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
        vscode.workspace.onDidSaveTextDocument(async (document) => {
            if (document.languageId === 'solidity') {
                await quickScan();
            }
        });
    }

    // Register tree view providers
    vscode.window.registerTreeDataProvider('miesc.findings', new FindingsTreeProvider());
    vscode.window.registerTreeDataProvider('miesc.layers', new LayersTreeProvider());

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
 * Deep audit - All 7 layers
 */
async function deepAudit() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== 'solidity') {
        vscode.window.showWarningMessage('Open a Solidity file to run deep audit');
        return;
    }

    await runAudit(editor.document.uri.fsPath, [1, 2, 3, 4, 5, 6, 7]);
}

/**
 * Run the audit using MIESC API
 */
async function runAudit(filePath: string, layers: number[], showNotification: boolean = true) {
    const config = vscode.workspace.getConfiguration('miesc');
    const serverUrl = config.get<string>('serverUrl') || 'http://localhost:8000';
    const timeout = (config.get<number>('timeout') || 300) * 1000;

    updateStatusBar('$(sync~spin) Auditing...');
    outputChannel.appendLine(`\n--- Audit Started: ${path.basename(filePath)} ---`);
    outputChannel.appendLine(`Layers: ${layers.join(', ')}`);

    try {
        const response = await axios.post(`${serverUrl}/mcp/run_audit`, {
            contract_path: filePath,
            layers: layers,
            use_local_llm: config.get('useLocalLLM'),
            ollama_model: config.get('ollamaModel')
        }, {
            timeout: timeout
        });

        const result: MIESCAuditResult = response.data;
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

        if (error.code === 'ECONNREFUSED') {
            vscode.window.showErrorMessage(
                'MIESC server not running. Start the server or use CLI mode.',
                'Start Server'
            ).then(selection => {
                if (selection === 'Start Server') {
                    startServer();
                }
            });
        } else {
            vscode.window.showErrorMessage(`MIESC Error: ${error.message}`);
        }
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
        { label: 'Layer 1: Static Analysis', description: 'Slither, Solhint, Aderyn', picked: currentLayers.includes(1), layer: 1 },
        { label: 'Layer 2: Fuzzing', description: 'Echidna, Medusa', picked: currentLayers.includes(2), layer: 2 },
        { label: 'Layer 3: Symbolic Execution', description: 'Mythril, Manticore', picked: currentLayers.includes(3), layer: 3 },
        { label: 'Layer 4: Invariant Testing', description: 'Halmos, Kontrol', picked: currentLayers.includes(4), layer: 4 },
        { label: 'Layer 5: Formal Verification', description: 'SMTChecker, Certora', picked: currentLayers.includes(5), layer: 5 },
        { label: 'Layer 6: Property Testing', description: 'PropertyGPT, DA-GNN', picked: currentLayers.includes(6), layer: 6 },
        { label: 'Layer 7: AI Analysis', description: 'SmartLLM, ThreatModel', picked: currentLayers.includes(7), layer: 7 }
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
            new LayerItem('Layer 1', 'Static Analysis', 'Slither, Solhint, Aderyn'),
            new LayerItem('Layer 2', 'Fuzzing', 'Echidna, Medusa'),
            new LayerItem('Layer 3', 'Symbolic Execution', 'Mythril, Manticore'),
            new LayerItem('Layer 4', 'Invariant Testing', 'Halmos, Kontrol'),
            new LayerItem('Layer 5', 'Formal Verification', 'SMTChecker'),
            new LayerItem('Layer 6', 'Property Testing', 'PropertyGPT'),
            new LayerItem('Layer 7', 'AI Analysis', 'SmartLLM')
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
