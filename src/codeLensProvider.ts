import * as vscode from 'vscode';
import { UnifiedIssue } from './trivy';

export class SecurityCodeLensProvider {
    private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
    public readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

    // Cache: Uri.toString() -> Issues[]
    private issuesMap: Map<string, UnifiedIssue[]> = new Map();

    constructor() {}

    public updateIssues(uri: vscode.Uri, issues: UnifiedIssue[]) {
        this.issuesMap.set(uri.toString(), issues);
        this._onDidChangeCodeLenses.fire();
    }

    public clear(uri: vscode.Uri) {
        this.issuesMap.delete(uri.toString());
        this._onDidChangeCodeLenses.fire();
    }

    public clearAll() {
        this.issuesMap.clear();
        this._onDidChangeCodeLenses.fire();
    }

    public provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken): vscode.ProviderResult<vscode.CodeLens[]> {
        const issues = this.issuesMap.get(document.uri.toString());
        if (!issues || issues.length === 0) return [];

        const lenses: vscode.CodeLens[] = [];

        issues.forEach(issue => {
            // Determine range
            let range = new vscode.Range(0, 0, 0, 0);
            if (issue.StartLine) {
                // VS Code uses 0-based lines
                range = new vscode.Range(issue.StartLine - 1, 0, issue.StartLine - 1, 0);
            }

            // Create command
            const command: vscode.Command = {
                title: `⚡ Supreme: ${issue.Severity} - ${issue.Name}`,
                command: 'supreme.explainIssue',
                tooltip: "Click to see details and remediation",
                arguments: [issue]
            };

            lenses.push(new vscode.CodeLens(range, command));
        });

        return lenses;
    }
}
