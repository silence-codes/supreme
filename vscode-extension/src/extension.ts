import * as vscode from 'vscode';
import * as fs from 'fs';
import { CONFIG } from './config';
import { PythonBridge, ScanResult } from './pythonBridge';
import { SidebarProvider } from './sidebarProvider';
import { TreeProvider, ScanHistoryItem } from './treeProvider';
import { CodeLensProvider } from './codeLensProvider';
import { generateReportHtml } from './report';

export function activate(context: vscode.ExtensionContext) {
    console.log('Supreme 2 Light extension is now active!');

    // Initialize Python Bridge
    PythonBridge.setExtensionPath(context.extensionPath);

    // Initialize Providers
    const sidebarProvider = new SidebarProvider(context.extensionUri);
    const treeProvider = new TreeProvider();
    const codeLensProvider = new CodeLensProvider();

    // Register Providers
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(CONFIG.VIEWS.DASHBOARD, sidebarProvider),
        vscode.window.registerTreeDataProvider(CONFIG.VIEWS.RESULTS, treeProvider),
        vscode.languages.registerCodeLensProvider({ scheme: 'file' }, codeLensProvider)
    );

    // Register Commands
    context.subscriptions.push(
        vscode.commands.registerCommand(CONFIG.COMMANDS.START_SCAN, async () => {
            // Check installation first
            const isInstalled = await PythonBridge.checkInstallation();
            if (!isInstalled) {
                const selection = await vscode.window.showWarningMessage(
                    "Supreme 2 Light is not detected. Install it via pip?",
                    "Install", "Cancel"
                );
                if (selection === 'Install') {
                    vscode.commands.executeCommand(CONFIG.COMMANDS.INSTALL_TOOLS);
                }
                return;
            }

            // Start Scan
            sidebarProvider.setScanningState(true);

            try {
                // Determine target: workspace root or current file
                let target = '';
                if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
                    target = vscode.workspace.workspaceFolders[0].uri.fsPath;
                } else if (
                    vscode.window.activeTextEditor &&
                    vscode.window.activeTextEditor.document.uri.scheme === 'file'
                ) {
                    const editorPath = vscode.window.activeTextEditor.document.uri.fsPath;
                    if (editorPath && fs.existsSync(editorPath)) {
                        target = editorPath;
                    }
                } else {
                    const picked = await vscode.window.showOpenDialog({
                        canSelectFiles: true,
                        canSelectFolders: true,
                        canSelectMany: false,
                        openLabel: "Scan selected path"
                    });

                    if (!picked || picked.length === 0) {
                        vscode.window.showErrorMessage("No workspace, file, or path selected to scan.");
                        sidebarProvider.setScanningState(false);
                        return;
                    }

                    target = picked[0].fsPath;
                }

                vscode.window.withProgress({
                    location: vscode.ProgressLocation.Notification,
                    title: "Supreme 2 Light Scanning",
                    cancellable: true
                }, async (progress, token) => {
                    token.onCancellationRequested(() => {
                        PythonBridge.stopScan();
                    });

                    progress.report({ message: "Initializing..." });

                    try {
                        const results = await PythonBridge.runScan(target, (msg) => {
                            progress.report({ message: msg });
                        });

                        // Scan Complete
                        sidebarProvider.setScanningState(false);

                        // Update stats
                        const total = results.reduce((acc, r) => acc + r.Issues.length, 0);
                        const critical = results.reduce((acc, r) => acc + r.Issues.filter(i => i.Severity === 'CRITICAL').length, 0);
                        const high = results.reduce((acc, r) => acc + r.Issues.filter(i => i.Severity === 'HIGH').length, 0);
                        const medium = results.reduce((acc, r) => acc + r.Issues.filter(i => i.Severity === 'MEDIUM').length, 0);
                        const low = results.reduce((acc, r) => acc + r.Issues.filter(i => i.Severity === 'LOW').length, 0);
                        sidebarProvider.updateStats(total, critical, high, medium, low);

                        treeProvider.addScan(results);
                        codeLensProvider.updateIssues(results);

                        // Update chart
                        sidebarProvider.setHistoryData(treeProvider.getHistory());

                        // Show Report
                        const panel = vscode.window.createWebviewPanel(
                            'supreme2lReport',
                            'Supreme Report',
                            vscode.ViewColumn.One,
                            { enableScripts: true }
                        );
                        panel.webview.html = generateReportHtml(results, panel.webview);

                        vscode.window.showInformationMessage(`Scan complete. Found ${total} issues.`);
                    } catch (e: any) {
                        vscode.window.showErrorMessage(`Scan failed: ${e.message}`);
                        sidebarProvider.setScanningState(false);
                    }
                });

            } catch (e: any) {
                sidebarProvider.setScanningState(false);
                vscode.window.showErrorMessage(`Error starting scan: ${e.message}`);
            }
        }),

        vscode.commands.registerCommand(CONFIG.COMMANDS.STOP_SCAN, () => {
            PythonBridge.stopScan();
            sidebarProvider.setScanningState(false);
        }),

        vscode.commands.registerCommand(CONFIG.COMMANDS.EXPORT_REPORT, async () => {
            vscode.window.showInformationMessage("Export functionality coming soon!");
        }),

        vscode.commands.registerCommand(CONFIG.COMMANDS.INSTALL_TOOLS, () => {
            PythonBridge.installTools();
        }),

        vscode.commands.registerCommand('supreme2l.showHistoryReport', (item: ScanHistoryItem) => {
            const panel = vscode.window.createWebviewPanel(
                'supreme2lReport',
                `Report: ${item.date.toLocaleString()}`,
                vscode.ViewColumn.One,
                { enableScripts: true }
            );
            panel.webview.html = generateReportHtml(item.results, panel.webview);
        })
    );

    // Status Bar
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
    statusBarItem.text = "$(shield) Supreme 2 Light";
    statusBarItem.command = CONFIG.COMMANDS.START_SCAN;
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
}

export function deactivate() {
    PythonBridge.stopScan();
}
