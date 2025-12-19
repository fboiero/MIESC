/**
 * MIESC Client Service
 *
 * Handles communication with the MIESC REST API server.
 */

import axios, { AxiosInstance, AxiosResponse } from 'axios';
import * as vscode from 'vscode';

export interface Finding {
    id: string;
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    location: {
        file: string;
        line: number;
        column?: number;
        endLine?: number;
        endColumn?: number;
    };
    tool: string;
    layer: number;
    cwe?: string;
    swc?: string;
    remediation?: string;
    confidence: number;
}

export interface AuditResult {
    audit_id: string;
    contract_path: string;
    status: 'completed' | 'failed' | 'running';
    started_at: string;
    completed_at?: string;
    layers_run: number[];
    findings: Finding[];
    metrics: {
        total_findings: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        execution_time_seconds: number;
    };
    tools_used: string[];
}

export interface LayerStatus {
    layer: number;
    name: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    tools: string[];
    findings_count: number;
    execution_time?: number;
}

export interface AuditProgress {
    audit_id: string;
    progress_percent: number;
    current_layer: number;
    current_tool: string;
    layers: LayerStatus[];
    findings_so_far: number;
}

export class MIESCClient {
    private client: AxiosInstance;
    private baseUrl: string;
    private outputChannel: vscode.OutputChannel;

    constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
        this.baseUrl = vscode.workspace.getConfiguration('miesc').get('serverUrl', 'http://localhost:8000');

        this.client = axios.create({
            baseURL: this.baseUrl,
            timeout: vscode.workspace.getConfiguration('miesc').get('timeout', 300) * 1000,
            headers: {
                'Content-Type': 'application/json',
            },
        });

        // Log requests
        this.client.interceptors.request.use((config) => {
            this.outputChannel.appendLine(`[MIESC] ${config.method?.toUpperCase()} ${config.url}`);
            return config;
        });

        // Handle errors
        this.client.interceptors.response.use(
            (response) => response,
            (error) => {
                this.outputChannel.appendLine(`[MIESC] Error: ${error.message}`);
                throw error;
            }
        );
    }

    /**
     * Check if the MIESC server is running
     */
    async healthCheck(): Promise<boolean> {
        try {
            const response = await this.client.get('/health');
            return response.status === 200;
        } catch {
            return false;
        }
    }

    /**
     * Start a new audit
     */
    async startAudit(contractPath: string, layers?: number[]): Promise<string> {
        const payload: any = {
            contract_path: contractPath,
        };

        if (layers && layers.length > 0) {
            payload.layers = layers;
        }

        const response: AxiosResponse<{ audit_id: string }> = await this.client.post(
            '/api/v1/audit',
            payload
        );

        return response.data.audit_id;
    }

    /**
     * Get audit status and results
     */
    async getAuditResult(auditId: string): Promise<AuditResult> {
        const response: AxiosResponse<AuditResult> = await this.client.get(
            `/api/v1/audit/${auditId}`
        );
        return response.data;
    }

    /**
     * Get audit progress
     */
    async getAuditProgress(auditId: string): Promise<AuditProgress> {
        const response: AxiosResponse<AuditProgress> = await this.client.get(
            `/api/v1/audit/${auditId}/progress`
        );
        return response.data;
    }

    /**
     * Cancel a running audit
     */
    async cancelAudit(auditId: string): Promise<void> {
        await this.client.post(`/api/v1/audit/${auditId}/cancel`);
    }

    /**
     * Get available tools
     */
    async getAvailableTools(): Promise<{ layer: number; tools: string[] }[]> {
        const response = await this.client.get('/api/v1/tools');
        return response.data.tools;
    }

    /**
     * Get audit history
     */
    async getAuditHistory(limit: number = 10): Promise<AuditResult[]> {
        const response: AxiosResponse<{ audits: AuditResult[] }> = await this.client.get(
            `/api/v1/audits?limit=${limit}`
        );
        return response.data.audits;
    }

    /**
     * Analyze code snippet (without saving to file)
     */
    async analyzeSnippet(code: string, layers?: number[]): Promise<AuditResult> {
        const payload: any = {
            code: code,
        };

        if (layers && layers.length > 0) {
            payload.layers = layers;
        }

        const response: AxiosResponse<AuditResult> = await this.client.post(
            '/api/v1/analyze',
            payload
        );

        return response.data;
    }

    /**
     * Get remediation suggestions for a finding
     */
    async getRemediation(findingId: string): Promise<{ remediation: string; fixed_code?: string }> {
        const response = await this.client.get(`/api/v1/remediation/${findingId}`);
        return response.data;
    }

    /**
     * Update base URL from settings
     */
    updateBaseUrl(): void {
        this.baseUrl = vscode.workspace.getConfiguration('miesc').get('serverUrl', 'http://localhost:8000');
        this.client.defaults.baseURL = this.baseUrl;
    }
}
