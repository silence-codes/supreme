import * as vscode from 'vscode';
import { ScanResult } from './pythonBridge';
import { generateReportHtml } from './report';

export class ScanHistoryItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly date: Date,
        public readonly results: ScanResult[],
        public readonly collapsibleState: vscode.TreeItemCollapsibleState
    ) {
        super(label, collapsibleState);
        this.tooltip = `Scan on ${this.date.toLocaleString()}`;
        this.description = this.date.toLocaleString();
        this.command = {
            command: 'supreme2l.showHistoryReport',
            title: 'Show Report',
            arguments: [this]
        };
        this.iconPath = new vscode.ThemeIcon('history');
    }
}

export class TreeProvider implements vscode.TreeDataProvider<ScanHistoryItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<ScanHistoryItem | undefined | null | void> = new vscode.EventEmitter<ScanHistoryItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<ScanHistoryItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private history: ScanHistoryItem[] = [];

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    addScan(results: ScanResult[]) {
        const date = new Date();
        const stats = this.getStats(results);
        const label = `Scan (${stats.total} found)`;
        const item = new ScanHistoryItem(label, date, results, vscode.TreeItemCollapsibleState.None);
        this.history.unshift(item); // Add to top
        this.refresh();
    }

    getTreeItem(element: ScanHistoryItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: ScanHistoryItem): Thenable<ScanHistoryItem[]> {
        if (element) {
            return Promise.resolve([]); // No children for now
        }
        return Promise.resolve(this.history);
    }

    private getStats(results: ScanResult[]) {
        let total = 0;
        results.forEach(f => total += f.Issues.length);
        return { total };
    }

    getHistory(): any[] {
        return this.history.map(item => ({
            date: item.date,
            summary: this.getStats(item.results)
        }));
    }
}
