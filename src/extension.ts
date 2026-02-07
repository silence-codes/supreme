import * as vscode from 'vscode';
import * as path from 'path';
import { TrivyService, HistoryEntry } from './trivy';
import { generateReportHtml } from './report';
import { VulnerabilityTreeProvider, SeverityFilter } from './vulnerabilityTreeProvider';
import { SidebarProvider } from './sidebarProvider';
import { DiagnosticsManager } from './diagnostics';
import { StatusBarManager } from './statusBar';
import { SecurityCodeLensProvider } from './codeLensProvider';
import { LicenseService } from './services/licenseService';
import * as fs from 'fs';
import * as os from 'os';
import axios from 'axios';
import { getApiUrl, CONFIG } from './config';

export async function activate(context: vscode.ExtensionContext) {
    console.log('Supreme Security is active!');

    const licenseService = new LicenseService(context);
    let isLicensed = await licenseService.isValid();

    // Dynamic license update callback
    licenseService.setOnLicenseChange((licensed: boolean) => {
        isLicensed = licensed;
        sidebarProvider.setLicenseState(licensed);
        if (licensed) {
            const key = licenseService.getStoredKey();
            if (key) sidebarProvider.updateLicenseState(key);
        }
    });

    if (!isLicensed) {
        vscode.window.showWarningMessage("Supreme Security is not activated. Please run 'Supreme: Activate License' with a valid key.", "Activate Now")
            .then(sel => {
                if (sel === "Activate Now") {
                    vscode.commands.executeCommand('supreme.activate');
                }
            });
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    const rootPath = workspaceFolders ? workspaceFolders[0].uri.fsPath : undefined;

    // Managers - TrivyService is shared
    const trivyService = new TrivyService(context);
    const sidebarProvider = new SidebarProvider(context.extensionUri);

    // Initial State Sync
    sidebarProvider.setLicenseState(isLicensed);
    if (isLicensed) {
        const key = licenseService.getStoredKey();
        if (key) sidebarProvider.updateLicenseState(key);
    }

    const treeProvider = new VulnerabilityTreeProvider(context, rootPath, trivyService);
    const diagnosticsManager = new DiagnosticsManager(context, trivyService);
    const statusBarManager = new StatusBarManager(context);
    const codeLensProvider = new SecurityCodeLensProvider();

    // Registrations
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('supreme-dashboard', sidebarProvider),
        vscode.window.registerTreeDataProvider('supreme-results', treeProvider),
        vscode.languages.registerCodeLensProvider({ scheme: 'file' }, codeLensProvider as any)
    );

    // On Save (Gated) - uses cached license check
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (document) => {
            // Use cached check to avoid HTTP request on every save
            if (!isLicensed) return;

            if (rootPath && document.uri.fsPath.startsWith(rootPath)) {
                if (document.lineCount > 5000) return;

                const issues = await diagnosticsManager.scanFile(document);
                codeLensProvider.updateIssues(document.uri, issues || []);
            }
        })
    );

    // CodeLens Command (Gated)
    let explainCommand = vscode.commands.registerCommand('supreme.explainIssue', async (issue: any) => {
        if (!await licenseService.isValid()) {
            vscode.window.showErrorMessage("Feature requires activation.");
            return;
        }
        const detail = `severity: ${issue.Severity}\npackage: ${issue.Name}\n\n${issue.Description}\n\n${issue.Url || ''}`;
        const selection = await vscode.window.showWarningMessage(
            `[${issue.Severity}] ${issue.Name}`,
            { modal: true, detail: detail },
            "Open Report", "Close"
        );

        if (selection === "Open Report") {
            vscode.commands.executeCommand('supreme.startScan');
        }
    });
    context.subscriptions.push(explainCommand);

    // Initial State
    const history = trivyService.getHistory();
    if (history.length > 0) {
        const last = history[0];
        statusBarManager.setResults(last.summary.total, last.summary.critical, last.summary.high);

        setTimeout(() => {
            sidebarProvider.updateStats(
                last.summary ? last.summary.total : 0,
                last.summary ? last.summary.critical : 0,
                last.summary ? last.summary.high : 0,
                last.summary ? (last.summary.medium || 0) : 0,
                last.summary ? (last.summary.low || 0) : 0
            );
            sidebarProvider.setHistoryData(history);
        }, 1500);
    } else {
        statusBarManager.setReady();
    }

    if (isLicensed) {
        setTimeout(async () => {
            const key = await licenseService.getStoredKey();
            if (key) sidebarProvider.updateLicenseState(key);
        }, 2000);
    }

    // --- Commands ---

    let activateCommand = vscode.commands.registerCommand('supreme.activate', async (argKey?: string) => {
        let key = argKey;

        if (!key) {
            key = await vscode.window.showInputBox({
                prompt: "Enter your Supreme Security License Key",
                placeHolder: "Format: xxxxxxxxxxxxxxxx",
                ignoreFocusOut: true
            });
        }

        if (key) {
            const success = await licenseService.activate(key);
            if (success) {
                sidebarProvider.setScanningState(false, true); // Update UI
                sidebarProvider.updateLicenseState(key);
            }
        }
    });

    let exportCommand = vscode.commands.registerCommand('supreme.exportReport', async () => {
        if (!await licenseService.isValid()) { vscode.window.showErrorMessage("Activation required."); return; }

        const history = trivyService.getHistory();
        if (history.length === 0) {
            vscode.window.showInformationMessage("No scan history to export.");
            return;
        }
        const lastScan = history[0];
        const defaultUri = vscode.Uri.file(path.join(rootPath || '', `supreme-report-${lastScan.id}.json`));

        const uri = await vscode.window.showSaveDialog({
            defaultUri: defaultUri,
            filters: { 'JSON': ['json'] }
        });

        if (uri) {
            fs.writeFileSync(uri.fsPath, JSON.stringify(lastScan, null, 2));
            vscode.window.showInformationMessage(`Report exported successfully.`);
        }
    });

    let historyCommand = vscode.commands.registerCommand('supreme.openReport', async (entry: HistoryEntry) => {
        if (!await licenseService.isValid()) { vscode.window.showErrorMessage("Activation required."); return; }
        const panel = vscode.window.createWebviewPanel(
            'supremeReport',
            `Supreme Report (${entry.date})`,
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                enableCommandUris: true
            }
        );
        panel.webview.html = generateReportHtml(entry.results, panel.webview);
    });

    let deleteScanCommand = vscode.commands.registerCommand('supreme.deleteScan', async (item: any) => {
        if (!await licenseService.isValid()) return;
        if (item && item.entry) {
            trivyService.deleteHistoryEntry(item.entry.id);
            treeProvider.refresh();
            sidebarProvider.setHistoryData(trivyService.getHistory());
        }
    });

    let clearHistoryCommand = vscode.commands.registerCommand('supreme.clearHistory', async () => {
        if (!await licenseService.isValid()) {
            const answer = await vscode.window.showWarningMessage("Supreme Security License Invalid/Expired", "Activate");
            if (answer === "Activate") {
                vscode.commands.executeCommand('supreme.activate');
            }
            return;
        }
        const answer = await vscode.window.showWarningMessage("Clear all scan history?", "Yes", "No");
        if (answer === "Yes") {
            trivyService.clearHistory();
            treeProvider.refresh();
            sidebarProvider.updateStats(0, 0, 0, 0, 0);
            sidebarProvider.setHistoryData([]);
            statusBarManager.setReady();
        }
    });

    // Filter History Command
    let filterHistoryCommand = vscode.commands.registerCommand('supreme.filterHistory', async () => {
        const currentFilter = treeProvider.getSeverityFilter();
        const options: vscode.QuickPickItem[] = [
            { label: 'All Severities', description: 'Show all issues', picked: currentFilter === 'ALL' },
            { label: 'Critical Only', description: 'Show only CRITICAL issues', picked: currentFilter === 'CRITICAL' },
            { label: 'High Only', description: 'Show only HIGH issues', picked: currentFilter === 'HIGH' },
            { label: 'Critical + High', description: 'Show CRITICAL and HIGH issues', picked: currentFilter === 'CRITICAL+HIGH' }
        ];

        const selection = await vscode.window.showQuickPick(options, {
            placeHolder: 'Select severity filter for history view',
            title: 'Filter History by Severity'
        });

        if (selection) {
            let filter: SeverityFilter = 'ALL';
            if (selection.label === 'Critical Only') filter = 'CRITICAL';
            else if (selection.label === 'High Only') filter = 'HIGH';
            else if (selection.label === 'Critical + High') filter = 'CRITICAL+HIGH';

            treeProvider.setSeverityFilter(filter);
            vscode.window.showInformationMessage(`History filter set to: ${selection.label}`);
        }
    });

    let scanTargetCommand = vscode.commands.registerCommand('supreme.scanTarget', async (uri: vscode.Uri) => {
        if (!isLicensed) { vscode.window.showErrorMessage("Activation required."); return; }
        const target = uri ? uri.fsPath : rootPath;
        if (!target) return;

        vscode.commands.executeCommand('supreme.startScan', target);
    });

    let scanCommand = vscode.commands.registerCommand('supreme.startScan', async (manualTarget?: string) => {
        if (!isLicensed) {
            vscode.window.showErrorMessage("Supreme Security is not activated. Please buy a license.", "Buy License", "Enter Key")
                .then(sel => {
                    if (sel === "Buy License") {
                        vscode.env.openExternal(vscode.Uri.parse(CONFIG.WEBSITE_URL));
                    } else if (sel === "Enter Key") {
                        vscode.commands.executeCommand('supreme.activate');
                    }
                });
            return;
        }

        const target = typeof manualTarget === 'string' ? manualTarget : rootPath;

        if (!target) {
            vscode.window.showErrorMessage("No workspace open.");
            return;
        }

        // Reset any previous cancellation state before starting a new scan
        trivyService.resetCancelState();

        sidebarProvider.setScanningState(true);
        statusBarManager.setScanning();

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Supreme Security: Scanning...",
            cancellable: true
        }, async (progress, token) => {

            // Handle cancellation from notification button
            token.onCancellationRequested(() => {
                trivyService.cancelScan();
                sidebarProvider.setScanningState(false);
                statusBarManager.setReady();
                vscode.window.showInformationMessage('Scan cancelled.');
            });

            progress.report({ message: "Initializing Engine..." });
            try {
                await trivyService.checkAndInstallTrivy();
            } catch (err: any) {
                vscode.window.showErrorMessage(`Engine initialization failed: ${err.message}`);
                sidebarProvider.setScanningState(false);
                statusBarManager.setReady();
                return;
            }

            progress.report({ message: "Analyzing..." });

            try {
                const results = await trivyService.runScan(target);

                results.forEach(res => {
                    if (!path.isAbsolute(res.Target) && rootPath) {
                        res.Target = path.join(rootPath, res.Target);
                    }
                });

                let total = 0, crit = 0, high = 0, med = 0, low = 0;
                results.forEach(res => res.Issues.forEach(i => {
                    total++;
                    if (i.Severity === 'CRITICAL') crit++;
                    else if (i.Severity === 'HIGH') high++;
                    else if (i.Severity === 'MEDIUM') med++;
                    else if (i.Severity === 'LOW') low++;
                }));

                sidebarProvider.updateStats(total, crit, high, med, low);
                sidebarProvider.setHistoryData(trivyService.getHistory());
                sidebarProvider.setScanningState(false);

                statusBarManager.setResults(total, crit, high);

                treeProvider.refresh();

                const panel = vscode.window.createWebviewPanel(
                    'supremeReport',
                    'Supreme Security Report',
                    vscode.ViewColumn.One,
                    {
                        enableScripts: true,
                        enableCommandUris: true
                    }
                );

                panel.webview.html = generateReportHtml(results, panel.webview);

            } catch (err: any) {
                if (err.message === 'Scan cancelled by user') {
                    // Already handled by cancellation
                    return;
                }
                vscode.window.showErrorMessage(`Analysis failed: ${err.message}`);
                sidebarProvider.setScanningState(false);
                statusBarManager.setReady();
            }
        });
    });

    // Stop Scan Command
    let stopScanCommand = vscode.commands.registerCommand('supreme.stopScan', () => {
        if (trivyService.isScanning()) {
            trivyService.cancelScan();
            sidebarProvider.setScanningState(false);
            statusBarManager.setReady();
            vscode.window.showInformationMessage('Scan stopped.');
        }
    });

    // Update Database Command
    let updateDatabaseCommand = vscode.commands.registerCommand('supreme.updateDatabase', async () => {
        // Check if license is valid
        const isLicensed = await licenseService.isValid();

        if (!isLicensed) {
            const action = await vscode.window.showWarningMessage(
                'Database updates require an active license. Subscribe to get full access to vulnerability scanning.',
                'Get License'
            );
            if (action === 'Get License') {
                vscode.env.openExternal(vscode.Uri.parse('https://supreme.silence.codes/dashboard'));
            }
            sidebarProvider.sendDbUpdateResult(false, 'License required');
            return;
        }

        try {
            const result = await trivyService.updateDatabase();
            const timestamp = trivyService.getLastDbUpdate();
            sidebarProvider.sendDbUpdateResult(result.success, result.message, timestamp || undefined);
        } catch (err: any) {
            sidebarProvider.sendDbUpdateResult(false, 'Update failed');
        }
    });

    // Send initial DB timestamp
    const initialDbTimestamp = trivyService.getLastDbUpdate();
    if (initialDbTimestamp) {
        sidebarProvider.sendDbLastUpdate(initialDbTimestamp);
    }

    // Install CLI Command
    let installCliCommand = vscode.commands.registerCommand('supreme.installCli', async () => {
        const cliSource = path.join(context.extensionPath, 'cli', 'supreme-cli.js');

        if (!fs.existsSync(cliSource)) {
            vscode.window.showErrorMessage('CLI script not found in extension.');
            return;
        }

        const targetDir = process.platform === 'win32'
            ? path.join(process.env.LOCALAPPDATA || '', 'Supreme', 'bin')
            : path.join(os.homedir(), '.local', 'bin');

        const targetPath = process.platform === 'win32'
            ? path.join(targetDir, 'supreme.cmd')
            : path.join(targetDir, 'supreme');

        try {
            // Create target directory if needed
            if (!fs.existsSync(targetDir)) {
                fs.mkdirSync(targetDir, { recursive: true });
            }

            if (process.platform === 'win32') {
                // On Windows, create a batch file
                const batchContent = `@echo off\nnode "${cliSource}" %*`;
                fs.writeFileSync(targetPath, batchContent);
                vscode.window.showInformationMessage(
                    `CLI installed to ${targetPath}. Add ${targetDir} to your PATH if not already.`
                );
            } else {
                // On Unix, create symlink
                if (fs.existsSync(targetPath)) {
                    fs.unlinkSync(targetPath);
                }
                fs.symlinkSync(cliSource, targetPath);
                fs.chmodSync(cliSource, '755');

                vscode.window.showInformationMessage(
                    `CLI installed! Run 'supreme --help' to get started.\nLocation: ${targetPath}`
                );
            }

            // Show instructions
            const instructions = await vscode.window.showInformationMessage(
                'Supreme CLI installed successfully!',
                'Show Usage'
            );
            if (instructions === 'Show Usage') {
                const terminal = vscode.window.createTerminal('Supreme CLI');
                terminal.show();
                terminal.sendText('supreme --help');
            }
        } catch (err: any) {
            vscode.window.showErrorMessage(`Failed to install CLI: ${err.message}`);
        }
    });

    context.subscriptions.push(activateCommand, scanCommand, stopScanCommand, historyCommand, deleteScanCommand, clearHistoryCommand, exportCommand, scanTargetCommand, filterHistoryCommand, updateDatabaseCommand, installCliCommand);
}

export function deactivate() { }
