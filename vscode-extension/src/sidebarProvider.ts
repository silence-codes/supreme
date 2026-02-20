import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

export class SidebarProvider implements vscode.WebviewViewProvider {
    private _view?: vscode.WebviewView;
    private pendingMessages: any[] = [];

    private isScanning: boolean = false;

    constructor(private readonly _extensionUri: vscode.Uri) { }

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken,
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri],
        };

        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

        webviewView.webview.onDidReceiveMessage(data => {
            switch (data.type) {
                case 'startScan': {
                    vscode.commands.executeCommand('supreme2l.startScan');
                    break;
                }
                case 'stopScan': {
                    vscode.commands.executeCommand('supreme2l.stopScan');
                    break;
                }
                case 'export': {
                    vscode.commands.executeCommand('supreme2l.exportReport');
                    break;
                }
                case 'installTools': {
                    vscode.commands.executeCommand('supreme2l.installTools');
                    break;
                }
                case 'ready': {
                    this.sendInitialState();
                    break;
                }
            }
        });

        // Send any pending messages that were queued before webview was ready
        this.pendingMessages.forEach(msg => webviewView.webview.postMessage(msg));
        this.pendingMessages = [];
    }

    private sendInitialState() {
        this.postMessage({ type: 'state', isScanning: this.isScanning });
    }

    private postMessage(message: any) {
        if (this._view) {
            this._view.webview.postMessage(message);
        } else {
            this.pendingMessages.push(message);
        }
    }

    public setScanningState(isScanning: boolean) {
        this.isScanning = isScanning;
        this.postMessage({ type: 'state', isScanning: this.isScanning });
    }

    public updateStats(total: number, critical: number, high: number, medium: number, low: number) {
        // Calculate Score (Weighted Deduction: Start at 100)
        // Critical = -10, High = -5, Medium = -2, Low = -1
        let rawScore = 100 - (critical * 10) - (high * 5) - (medium * 2) - (low * 1);
        if (rawScore < 0) rawScore = 0;
        const score = Math.round(rawScore);

        this.postMessage({ type: 'stats', total, critical, high, score });
    }

    public setHistoryData(history: any[]) {
        // Generate SVG Chart points
        // Take last 7 scans
        const data = history.slice(0, 7).reverse();
        if (data.length < 2) {
            this.postMessage({ type: 'chart', svg: '' });
            return;
        }

        const width = 200;
        const height = 60;
        const max = Math.max(...data.map(d => (d.summary ? d.summary.total : 0))) || 1;

        const points = data.map((d, i) => {
            const x = (i / (data.length - 1)) * width;
            const val = d.summary ? d.summary.total : 0;
            const y = height - (val / max) * height;
            return `${x},${y}`;
        }).join(' ');

        const svg = `<svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
            <polyline fill="none" stroke="#9b59b6" stroke-width="2" points="${points}"/>
            <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#9b59b6" stop-opacity="0.3"/>
                <stop offset="100%" stop-color="#9b59b6" stop-opacity="0"/>
            </linearGradient>
            <polygon fill="url(#grad)" points="0,${height} ${points} ${width},${height}"/>
        </svg>`;

        this.postMessage({ type: 'chart', svg });
    }

    private _getHtmlForWebview(webview: vscode.Webview) {
        const htmlPath = path.join(this._extensionUri.fsPath, 'resources', 'webview.html');

        let htmlContent = '';
        try {
            htmlContent = fs.readFileSync(htmlPath, 'utf-8');
        } catch (e) {
            return `<html><body>Error loading UI</body></html>`;
        }

        return htmlContent;
    }
}
