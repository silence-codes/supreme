import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { getPythonPath, getGlobalPythonPath, getGlobalVenvPath } from './config';

export interface ScanIssue {
    ID: string;
    Name: string;
    Severity: string;
    Description: string;
    Type: string;
    StartLine?: number;
    CodeSnippet?: string;
    CWE?: string;
    CWELink?: string;
}

export interface ScanResult {
    Target: string;
    Issues: ScanIssue[];
}

// ... (interfaces remain same)

export class PythonBridge {
    private static childProcess: cp.ChildProcess | null = null;
    private static outputChannel = vscode.window.createOutputChannel("Supreme 2 Light");
    private static extensionPath: string = "";

    static setExtensionPath(path: string) {
        this.extensionPath = path;
    }

    static async checkInstallation(): Promise<boolean> {
        const python = getPythonPath();
        return new Promise((resolve) => {
            const checkProcess = cp.spawn(python, ['-m', 'supreme2l', '--version']);
            let stdout = '';
            let stderr = '';

            checkProcess.stdout?.on('data', (chunk) => {
                stdout += chunk.toString();
            });

            checkProcess.stderr?.on('data', (chunk) => {
                stderr += chunk.toString();
            });

            checkProcess.on('error', (err) => {
                this.outputChannel.appendLine(`Installation check failed with ${python}: ${err.message}`);
                resolve(false);
            });

            checkProcess.on('close', (code) => {
                if (code === 0) {
                    this.outputChannel.appendLine(`Supreme 2 Light found: ${stdout.trim()}`);
                    resolve(true);
                    return;
                }

                const details = stderr.trim() || stdout.trim();
                this.outputChannel.appendLine(`Installation check failed with ${python} (code ${code}). ${details}`);
                resolve(false);
            });
        });
    }

    static async installTools() {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        const activeEditorPath = vscode.window.activeTextEditor?.document.uri.fsPath;
        let installTarget = workspaceFolder || (activeEditorPath ? path.dirname(activeEditorPath) : "");

        if (!installTarget) {
            const picked = await vscode.window.showOpenDialog({
                canSelectFiles: false,
                canSelectFolders: true,
                canSelectMany: false,
                openLabel: "Select project folder for install"
            });
            if (!picked || picked.length === 0) {
                vscode.window.showWarningMessage("Install canceled: no target folder selected.");
                return;
            }
            installTarget = picked[0].fsPath;
        }

        const terminal = vscode.window.createTerminal({
            name: "Supreme 2 Light Installer",
            cwd: installTarget
        });
        terminal.show();

        const sendExecutable = (executablePath: string, args: string[]) => {
            const quoteArg = (arg: string) => `"${arg.replace(/"/g, '\\"')}"`;
            const formattedArgs = args
                .map((arg) => quoteArg(arg))
                .join(' ');

            if (process.platform === 'win32') {
                // Use cmd wrapper so paths work reliably from both PowerShell and CMD terminals.
                terminal.sendText(`cmd /d /c ""${executablePath}" ${formattedArgs}"`);
            } else {
                terminal.sendText(`"${executablePath}" ${formattedArgs}`);
            }
        };

        // 1. Check if supreme2l is installed reachable via getPythonPath()
        const isInstalled = await this.checkInstallation();
        // Force reinstall if needed, or check version? 
        // For now, if installed, assume user might want to update or is fine. 
        // But if we just shipped a fix, we might want to force update?
        // Let's rely on "Install Tools" command always trying to update supreme2l package first.

        const pythonPath = getGlobalPythonPath();

        // Define wheel path
        const wheelName = "supreme2l-1.0.9-py3-none-any.whl";
        const wheelPath = this.extensionPath
            ? path.join(this.extensionPath, 'resources', wheelName)
            : "";

        // If simple check passed, we might still want to ensure we have the LATEST version from our bundle.
        // So we proceed to venv setup/update regardless if triggered manually via installTools.

        // 2. Setup/Ensure Venv
        const venvPath = getGlobalVenvPath();
        terminal.sendText(`echo "Setting up/Updating Supreme 2 Light environment at ${venvPath}..."`);
        terminal.sendText(`echo "Project target: ${installTarget}"`);

        if (!fs.existsSync(pythonPath)) {
            let systemPython = 'python3';
            if (process.platform === 'win32') systemPython = 'python';
            terminal.sendText(`${systemPython} -m venv "${venvPath}"`);
        }

        // 3. Install/Update supreme2l from bundled wheel
        if (wheelPath && fs.existsSync(wheelPath)) {
            terminal.sendText(`echo "Installing Supreme 2 Light v1.0.9 from bundle..."`);
            // Force reinstall to ensure we get the new version even if 1.0.0 is present
            sendExecutable(pythonPath, ['-m', 'pip', 'install', '--force-reinstall', wheelPath]);
        } else {
            terminal.sendText(`echo "Warning: Bundled wheel not found at ${wheelPath}. Trying PyPI..."`);
            sendExecutable(pythonPath, ['-m', 'pip', 'install', '--upgrade', 'supreme2l']);
        }

        // 4. Run supreme2l install
        sendExecutable(pythonPath, ['-m', 'supreme2l', 'install', '--smart', '--yes', '--target', installTarget]);

        // 5. Notify
        terminal.sendText(`echo "Installation complete! You can now Scan."`);
    }

    static async runScan(target: string, onProgress?: (msg: string) => void): Promise<ScanResult[]> {
        if (this.childProcess) {
            throw new Error("Scan already running");
        }

        const python = getPythonPath();
        // Create a temporary directory for this scan
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 's2l-scan-'));

        // Build arguments
        // s2l scan <target> --format json -o <tmpDir>
        // CLI treats -o as a directory and generates a file inside it
        const args = ['-m', 'supreme2l', 'scan', target, '--format', 'json', '--output', tmpDir, '--no-install'];

        let scanCwd = process.cwd();
        try {
            if (fs.existsSync(target)) {
                const stat = fs.statSync(target);
                scanCwd = stat.isDirectory() ? target : path.dirname(target);
            }
        } catch {
            // Keep process cwd fallback.
        }

        this.outputChannel.appendLine(`Starting scan: ${python} ${args.join(' ')}`);
        this.outputChannel.appendLine(`Scan CWD: ${scanCwd}`);
        if (onProgress) onProgress("Initializing scan...");

        return new Promise((resolve, reject) => {
            this.childProcess = cp.spawn(python, args, { cwd: scanCwd });

            this.childProcess.stdout?.on('data', (data) => {
                const output = data.toString();
                this.outputChannel.append(output);
                if (onProgress) {
                    if (output.includes('Scanning')) onProgress("Scanning files...");
                    if (output.includes('Analyzing')) onProgress("Analyzing results...");
                }
            });

            this.childProcess.stderr?.on('data', (data) => {
                this.outputChannel.append(`ERR: ${data.toString()}`);
            });

            this.childProcess.on('close', (code) => {
                this.childProcess = null;
                if (code === 0) {
                    try {
                        const files = fs.readdirSync(tmpDir).filter((f) => f.endsWith('.json'));
                        const preferred = files
                            .filter((f) => f.startsWith('supreme2l-scan-'))
                            .sort((a, b) => a.localeCompare(b))
                            .reverse();
                        const fallback = files.filter((f) => f !== 'scan_history.json');
                        const candidates = [...preferred, ...fallback.filter((f) => !preferred.includes(f))];

                        let parsedReport: any = null;
                        for (const fileName of candidates) {
                            const fullPath = path.join(tmpDir, fileName);
                            try {
                                const raw = fs.readFileSync(fullPath, 'utf-8');
                                const parsed = JSON.parse(raw);
                                if (!Array.isArray(parsed) && parsed && Array.isArray(parsed.findings)) {
                                    parsedReport = parsed;
                                    break;
                                }
                            } catch {
                                // Ignore malformed file and continue with next candidate.
                            }
                        }

                        if (parsedReport) {
                            const results = this.parseResults(parsedReport, target);

                            try {
                                fs.rmSync(tmpDir, { recursive: true, force: true });
                            } catch (e) {
                                console.error(`Failed to clean up temp files: ${e}`);
                            }

                            resolve(results);
                        } else {
                            reject(new Error("No JSON report generated in output directory"));
                        }
                    } catch (e) {
                        reject(new Error(`Failed to parse results: ${e}`));
                    }
                } else {
                    reject(new Error(`Scan failed with code ${code}`));
                }
            });
        });
    }

    static stopScan() {
        if (this.childProcess) {
            this.childProcess.kill();
            this.childProcess = null;
            this.outputChannel.appendLine("Scan stopped by user.");
        }
    }

    private static parseResults(json: any, targetRoot: string): ScanResult[] {
        // Supreme 2 Light JSON structure:
        // {
        //   "metadata": { ... },
        //   "summary": { ... },
        //   "findings": [
        //     {
        //       "file": "path/to/file",
        //       "line": 10,
        //       "message": "...",
        //       "severity": "HIGH",
        //       "tool": "bandit",
        //       "rule_id": "B101",
        //       ...
        //     }
        //   ]
        // }

        const findings = json.findings || [];
        const resultMap: Map<string, ScanIssue[]> = new Map();

        for (const finding of findings) {
            const file = finding.file || "unknown";
            const cweValue = typeof finding.cwe_id === 'number'
                ? `CWE-${finding.cwe_id}`
                : (typeof finding.cwe === 'string' && finding.cwe ? finding.cwe : undefined);

            const issue: ScanIssue = {
                ID: finding.rule_id || cweValue || "UNKNOWN",
                Name: finding.message || finding.issue || "Unknown Issue",
                Severity: (finding.severity || "INFO").toUpperCase(),
                Description: finding.description || finding.message || finding.issue || "No description available",
                Type: finding.tool || finding.scanner || "S2L",
                StartLine: finding.line,
                CodeSnippet: finding.code,
                CWE: cweValue,
                CWELink: finding.cwe_link
            };

            if (!resultMap.has(file)) {
                resultMap.set(file, []);
            }
            resultMap.get(file)?.push(issue);
        }

        const results: ScanResult[] = [];
        resultMap.forEach((issues, file) => {
            // Make path relative if possible? Or keep absolute?
            // VS Code usually prefers absolute or relative to workspace. 
            // S2L output might depend. Let's assume S2L returns what was passed or relative.
            // basic.py says: 'file': self.file_path
            results.push({
                Target: file,
                Issues: issues
            });
        });

        return results;
    }
}
