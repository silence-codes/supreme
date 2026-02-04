import * as vscode from 'vscode';

export class StatusBarManager {
    private statusBarItem: vscode.StatusBarItem;

    constructor(context: vscode.ExtensionContext) {
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.statusBarItem.command = 'supreme.startScan'; // Default action: start scan or open dashboard? Let's start scan or maybe open sidebar
        this.statusBarItem.text = "$(zap) Supreme: Ready";
        this.statusBarItem.tooltip = "Supreme Security Scanner";
        this.statusBarItem.show();
        
        context.subscriptions.push(this.statusBarItem);
    }

    public setScanning() {
        this.statusBarItem.text = "$(sync~spin) Supreme: Scanning...";
        this.statusBarItem.backgroundColor = undefined;
        this.statusBarItem.show();
    }

    public setResults(total: number, critical: number, high: number) {
        if (total === 0) {
            this.statusBarItem.text = "$(check) Supreme: Safe";
            this.statusBarItem.backgroundColor = undefined;
            this.statusBarItem.color = '#2ecc71'; // Greenish
        } else {
            this.statusBarItem.text = `$(warning) Supreme: ${total} Issues`;
            if (critical > 0) {
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                this.statusBarItem.color = undefined;
            } else if (high > 0) {
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
                this.statusBarItem.color = undefined;
            } else {
                this.statusBarItem.backgroundColor = undefined;
                this.statusBarItem.color = undefined;
            }
        }
        this.statusBarItem.tooltip = `Scan Results: ${total} Total (${critical} Critical, ${high} High)`;
        this.statusBarItem.show();
    }

    public setReady() {
        this.statusBarItem.text = "$(zap) Supreme: Ready";
        this.statusBarItem.backgroundColor = undefined;
        this.statusBarItem.color = undefined;
        this.statusBarItem.show();
    }
}
