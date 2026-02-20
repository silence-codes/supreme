import * as vscode from 'vscode';
import { ScanResult, ScanIssue } from './pythonBridge';

export class CodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
    public readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

    private issuesMap: Map<string, ScanIssue[]> = new Map();

    public updateIssues(results: ScanResult[]) {
        this.issuesMap.clear();
        results.forEach(file => {
            // Normalize path for map lookup (VS Code URIs usually are consistent)
            // Ideally we use vscode.Uri.file(path).toString()
            const uri = vscode.Uri.file(file.Target).toString();
            this.issuesMap.set(uri, file.Issues);
        });
        this._onDidChangeCodeLenses.fire();
    }

    public provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken): vscode.CodeLens[] | Thenable<vscode.CodeLens[]> {
        const uri = document.uri.toString();
        const issues = this.issuesMap.get(uri);

        if (!issues || issues.length === 0) {
            return [];
        }

        const lenses: vscode.CodeLens[] = [];

        // Group by line to avoid clutter? Or just one lens per issue?
        // Let's group by line.
        const lineMap: Map<number, ScanIssue[]> = new Map();

        issues.forEach(issue => {
            const line = (issue.StartLine || 1) - 1; // 0-indexed
            if (!lineMap.has(line)) {
                lineMap.set(line, []);
            }
            lineMap.get(line)?.push(issue);
        });

        lineMap.forEach((lineIssues, line) => {
            const range = new vscode.Range(line, 0, line, 0);
            const count = lineIssues.length;
            const severity = lineIssues.some(i => i.Severity === 'CRITICAL' || i.Severity === 'HIGH') ? '🔴' : 'Vk';
            const title = `${severity} ${count} Supreme Issue${count > 1 ? 's' : ''}: ${lineIssues[0].Name}`;

            const cmd = {
                title: title,
                tooltip: lineIssues.map(i => `[${i.Severity}] ${i.Name}: ${i.Description}`).join('\n'),
                command: '', // Could open a details view?
                arguments: []
            };

            lenses.push(new vscode.CodeLens(range, cmd));
        });

        return lenses;
    }
}
