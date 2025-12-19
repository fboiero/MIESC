/**
 * Findings Tree View Provider
 *
 * Displays security findings in a hierarchical tree view.
 */

import * as vscode from 'vscode';
import { Finding } from '../services/miescClient';

export class FindingTreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly finding?: Finding,
        public readonly children?: FindingTreeItem[]
    ) {
        super(label, collapsibleState);

        if (finding) {
            this.tooltip = `${finding.title}\n${finding.description}`;
            this.description = `Line ${finding.location.line}`;
            this.command = {
                command: 'miesc.goToFinding',
                title: 'Go to Finding',
                arguments: [finding],
            };

            // Set icon based on severity
            this.iconPath = this.getSeverityIcon(finding.severity);

            // Set context value for conditional menu items
            this.contextValue = 'finding';
        }
    }

    private getSeverityIcon(severity: string): vscode.ThemeIcon {
        switch (severity) {
            case 'critical':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'high':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
            case 'medium':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            case 'low':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }
}

export class FindingsTreeProvider implements vscode.TreeDataProvider<FindingTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<FindingTreeItem | undefined | null | void> =
        new vscode.EventEmitter<FindingTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<FindingTreeItem | undefined | null | void> =
        this._onDidChangeTreeData.event;

    private findings: Finding[] = [];
    private groupBy: 'severity' | 'type' | 'layer' | 'file' = 'severity';

    constructor() {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    setFindings(findings: Finding[]): void {
        this.findings = findings;
        this.refresh();
    }

    clearFindings(): void {
        this.findings = [];
        this.refresh();
    }

    setGroupBy(groupBy: 'severity' | 'type' | 'layer' | 'file'): void {
        this.groupBy = groupBy;
        this.refresh();
    }

    getTreeItem(element: FindingTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: FindingTreeItem): Thenable<FindingTreeItem[]> {
        if (!element) {
            // Root level - show groups
            return Promise.resolve(this.getGroups());
        }

        if (element.children) {
            return Promise.resolve(element.children);
        }

        return Promise.resolve([]);
    }

    private getGroups(): FindingTreeItem[] {
        if (this.findings.length === 0) {
            return [
                new FindingTreeItem(
                    'No findings',
                    vscode.TreeItemCollapsibleState.None
                ),
            ];
        }

        const groups = new Map<string, Finding[]>();

        for (const finding of this.findings) {
            let key: string;
            switch (this.groupBy) {
                case 'severity':
                    key = finding.severity.toUpperCase();
                    break;
                case 'type':
                    key = finding.type;
                    break;
                case 'layer':
                    key = `Layer ${finding.layer}`;
                    break;
                case 'file':
                    key = finding.location.file;
                    break;
            }

            if (!groups.has(key)) {
                groups.set(key, []);
            }
            groups.get(key)!.push(finding);
        }

        // Sort groups by severity if grouping by severity
        const sortedKeys = Array.from(groups.keys());
        if (this.groupBy === 'severity') {
            const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
            sortedKeys.sort((a, b) => severityOrder.indexOf(a) - severityOrder.indexOf(b));
        } else {
            sortedKeys.sort();
        }

        return sortedKeys.map((key) => {
            const groupFindings = groups.get(key)!;
            const children = groupFindings.map(
                (finding) =>
                    new FindingTreeItem(
                        finding.title,
                        vscode.TreeItemCollapsibleState.None,
                        finding
                    )
            );

            const groupItem = new FindingTreeItem(
                `${key} (${groupFindings.length})`,
                vscode.TreeItemCollapsibleState.Expanded,
                undefined,
                children
            );

            // Set icon for group based on severity
            if (this.groupBy === 'severity') {
                groupItem.iconPath = this.getGroupIcon(key);
            }

            return groupItem;
        });
    }

    private getGroupIcon(severity: string): vscode.ThemeIcon {
        switch (severity) {
            case 'CRITICAL':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'HIGH':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
            case 'MEDIUM':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            case 'LOW':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
            default:
                return new vscode.ThemeIcon('folder');
        }
    }

    /**
     * Get findings statistics
     */
    getStatistics(): { total: number; critical: number; high: number; medium: number; low: number; info: number } {
        const stats = {
            total: this.findings.length,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };

        for (const finding of this.findings) {
            switch (finding.severity) {
                case 'critical':
                    stats.critical++;
                    break;
                case 'high':
                    stats.high++;
                    break;
                case 'medium':
                    stats.medium++;
                    break;
                case 'low':
                    stats.low++;
                    break;
                case 'info':
                    stats.info++;
                    break;
            }
        }

        return stats;
    }
}
