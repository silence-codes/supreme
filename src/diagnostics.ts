import * as vscode from 'vscode';
import { TrivyService } from './trivy';

export class DiagnosticsManager {
    private collection: vscode.DiagnosticCollection;
    private trivyService: TrivyService;
    private diagnosticMap: Map<string, vscode.Diagnostic[]> = new Map();

    constructor(context: vscode.ExtensionContext, trivyService: TrivyService) {
        this.collection = vscode.languages.createDiagnosticCollection('supreme');
        this.trivyService = trivyService;
        context.subscriptions.push(this.collection);
    }

    public async scanFile(document: vscode.TextDocument) {
        // Only scan if not a git-scheme or other virtual doc
        if (document.uri.scheme !== 'file') return;

        const result = await this.trivyService.scanFile(document.uri.fsPath);
        this.updateDiagnostics(document.uri, result ? result.Issues : []);
        return result ? result.Issues : [];
    }

    public updateDiagnostics(uri: vscode.Uri, issues: any[]) {
        const diagnostics: vscode.Diagnostic[] = [];

        issues.forEach(issue => {
            // If we have line numbers, use them. Otherwise, default to top of file (0,0)
            let range = new vscode.Range(0, 0, 0, 0);

            if (issue.StartLine) {
                // Lines are 1-based in Trivy, 0-based in VS Code
                const startL = issue.StartLine - 1;
                const endL = issue.EndLine ? issue.EndLine - 1 : startL;
                // Try to highlight full line
                range = new vscode.Range(startL, 0, endL, 1000);
            }

            const severity = this.mapSeverity(issue.Severity);

            const diagnostic = new vscode.Diagnostic(
                range,
                `[Supreme] ${issue.ID}: ${issue.Name}\n${issue.Description}`,
                severity
            );

            diagnostic.source = 'Supreme Security';
            diagnostic.code = issue.ID;

            diagnostics.push(diagnostic);
        });

        this.collection.set(uri, diagnostics);
    }

    public clear(document: vscode.TextDocument) {
        this.collection.delete(document.uri);
    }

    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'CRITICAL': return vscode.DiagnosticSeverity.Error;
            case 'HIGH': return vscode.DiagnosticSeverity.Error;
            case 'MEDIUM': return vscode.DiagnosticSeverity.Warning;
            case 'LOW': return vscode.DiagnosticSeverity.Information;
            default: return vscode.DiagnosticSeverity.Hint;
        }
    }
}
