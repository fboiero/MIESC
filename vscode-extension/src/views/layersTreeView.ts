/**
 * Layers Tree View Provider
 *
 * Displays the 7 analysis layers and their status.
 */

import * as vscode from 'vscode';

export interface LayerInfo {
    number: number;
    name: string;
    description: string;
    tools: string[];
    status: 'idle' | 'running' | 'completed' | 'failed' | 'skipped';
    findingsCount: number;
    executionTime?: number;
}

export class LayerTreeItem extends vscode.TreeItem {
    constructor(
        public readonly layer: LayerInfo,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState
    ) {
        super(`Layer ${layer.number}: ${layer.name}`, collapsibleState);

        this.tooltip = `${layer.description}\n\nTools: ${layer.tools.join(', ')}`;
        this.description = this.getDescription();
        this.iconPath = this.getStatusIcon();
        this.contextValue = 'layer';
    }

    private getDescription(): string {
        const parts: string[] = [];

        if (this.layer.status === 'completed') {
            parts.push(`${this.layer.findingsCount} findings`);
            if (this.layer.executionTime) {
                parts.push(`${this.layer.executionTime.toFixed(1)}s`);
            }
        } else if (this.layer.status === 'running') {
            parts.push('Running...');
        } else if (this.layer.status === 'failed') {
            parts.push('Failed');
        } else if (this.layer.status === 'skipped') {
            parts.push('Skipped');
        }

        return parts.join(' | ');
    }

    private getStatusIcon(): vscode.ThemeIcon {
        switch (this.layer.status) {
            case 'running':
                return new vscode.ThemeIcon('sync~spin', new vscode.ThemeColor('charts.blue'));
            case 'completed':
                return new vscode.ThemeIcon('check', new vscode.ThemeColor('charts.green'));
            case 'failed':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('charts.red'));
            case 'skipped':
                return new vscode.ThemeIcon('circle-slash', new vscode.ThemeColor('disabledForeground'));
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }
}

export class ToolTreeItem extends vscode.TreeItem {
    constructor(
        public readonly toolName: string,
        public readonly layerNumber: number
    ) {
        super(toolName, vscode.TreeItemCollapsibleState.None);
        this.tooltip = `${toolName} (Layer ${layerNumber})`;
        this.iconPath = new vscode.ThemeIcon('tools');
        this.contextValue = 'tool';
    }
}

export class LayersTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | null | void> =
        new vscode.EventEmitter<vscode.TreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | null | void> =
        this._onDidChangeTreeData.event;

    private layers: LayerInfo[] = [
        {
            number: 1,
            name: 'Static Analysis',
            description: 'Pattern-based vulnerability detection',
            tools: ['Slither', 'Solhint', 'Aderyn', 'Gas Analyzer'],
            status: 'idle',
            findingsCount: 0,
        },
        {
            number: 2,
            name: 'Fuzzing',
            description: 'Property-based testing with random inputs',
            tools: ['Echidna', 'Foundry Fuzz', 'Medusa'],
            status: 'idle',
            findingsCount: 0,
        },
        {
            number: 3,
            name: 'Symbolic Execution',
            description: 'Path exploration and constraint solving',
            tools: ['Mythril', 'Manticore', 'Halmos'],
            status: 'idle',
            findingsCount: 0,
        },
        {
            number: 4,
            name: 'Formal Verification',
            description: 'Mathematical proofs of correctness',
            tools: ['SMTChecker', 'Certora', 'Wake'],
            status: 'idle',
            findingsCount: 0,
        },
        {
            number: 5,
            name: 'AI Analysis',
            description: 'LLM-powered vulnerability detection',
            tools: ['SmartLLM', 'GPTScan', 'LLMSmartAudit'],
            status: 'idle',
            findingsCount: 0,
        },
        {
            number: 6,
            name: 'ML Detection',
            description: 'Machine learning-based pattern recognition',
            tools: ['SmartBugs ML', 'DAGNN', 'Clone Detector'],
            status: 'idle',
            findingsCount: 0,
        },
        {
            number: 7,
            name: 'Correlation & Reporting',
            description: 'Finding correlation and report generation',
            tools: ['Correlation Engine', 'Severity Predictor', 'Report Generator'],
            status: 'idle',
            findingsCount: 0,
        },
    ];

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    updateLayerStatus(layerNumber: number, status: LayerInfo['status'], findingsCount?: number, executionTime?: number): void {
        const layer = this.layers.find((l) => l.number === layerNumber);
        if (layer) {
            layer.status = status;
            if (findingsCount !== undefined) {
                layer.findingsCount = findingsCount;
            }
            if (executionTime !== undefined) {
                layer.executionTime = executionTime;
            }
            this.refresh();
        }
    }

    resetAllLayers(): void {
        for (const layer of this.layers) {
            layer.status = 'idle';
            layer.findingsCount = 0;
            layer.executionTime = undefined;
        }
        this.refresh();
    }

    getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: vscode.TreeItem): Thenable<vscode.TreeItem[]> {
        if (!element) {
            // Root level - show all layers
            return Promise.resolve(
                this.layers.map(
                    (layer) =>
                        new LayerTreeItem(layer, vscode.TreeItemCollapsibleState.Collapsed)
                )
            );
        }

        if (element instanceof LayerTreeItem) {
            // Show tools for this layer
            return Promise.resolve(
                element.layer.tools.map(
                    (tool) => new ToolTreeItem(tool, element.layer.number)
                )
            );
        }

        return Promise.resolve([]);
    }

    /**
     * Get currently running layers
     */
    getRunningLayers(): number[] {
        return this.layers.filter((l) => l.status === 'running').map((l) => l.number);
    }

    /**
     * Get total findings across all layers
     */
    getTotalFindings(): number {
        return this.layers.reduce((sum, layer) => sum + layer.findingsCount, 0);
    }
}
