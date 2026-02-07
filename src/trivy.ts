import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as https from 'https';
import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import * as crypto from 'crypto';
import axios from 'axios';
import AdmZip = require('adm-zip');
import {
    findJsonLocation,
    findGoModLocation,
    findRequirementsTxtLocation,
    findGemfileLocation,
    findCargoTomlLocation,
    findPomXmlLocation,
    findPackageLockLocation,
    findYarnLockLocation,
    findCargoLockLocation,
    findGoSumLocation
} from './utils/locator';
import { getApiUrl } from './config';

const execAsync = promisify(exec);

export interface Vulnerability {
    VulnerabilityID?: string;
    PkgName?: string;
    InstalledVersion?: string;
    FixedVersion?: string;
    Severity: string;
    Title?: string;
    Description?: string;
    PrimaryURL?: string;
    References?: string[];
    ID?: string;
    RuleID?: string;
    Message?: string;
    Category?: string;
    Layer?: {
        DiffID: string;
    };
    PkgPath?: string;
}

export interface TrivyResult {
    Target: string;
    Vulnerabilities?: any[];
    Misconfigurations?: any[];
    Secrets?: any[];
}

export interface UnifiedIssue {
    ID: string;
    Name: string;
    Severity: string;
    Description: string;
    Url?: string;
    Type: 'Vulnerability' | 'Misconfiguration' | 'Secret';
    FixedVersion?: string;
    PkgPath?: string;
    StartLine?: number;
    EndLine?: number;
    CodeSnippet?: string;
}

export interface ScanResult {
    Target: string;
    Issues: UnifiedIssue[];
}

export interface HistoryEntry {
    id: string;
    date: string;
    results: ScanResult[];
    summary: { total: number; critical: number; high: number; medium: number; low: number };
}

export class TrivyService {
    private context: vscode.ExtensionContext;
    private config: { version: string, checksums: { [key: string]: string } } | null = null;
    private currentScanProcess: ReturnType<typeof spawn> | null = null;
    private currentDownloadRequest: ReturnType<typeof https.get> | null = null;
    private isCancelled: boolean = false;
    private isDownloading: boolean = false;
    private hasScannedThisSession: boolean = false; // For auto-skip DB update

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    public cancelScan(): void {
        this.isCancelled = true;
        if (this.currentScanProcess) {
            this.currentScanProcess.kill('SIGTERM');
            this.currentScanProcess = null;
        }
        // Also cancel any ongoing download
        if (this.currentDownloadRequest) {
            this.currentDownloadRequest.destroy();
            this.currentDownloadRequest = null;
        }
        this.isDownloading = false;
    }

    /** Reset cancellation state so a new scan can proceed */
    public resetCancelState(): void {
        this.isCancelled = false;
    }

    public isScanning(): boolean {
        return this.currentScanProcess !== null || this.isDownloading;
    }

    private getTrivyExecutablePath(): string {
        const platform = os.platform();
        const ext = platform === 'win32' ? '.exe' : '';
        return path.join(this.context.globalStorageUri.fsPath, `trivy${ext}`);
    }

    private async fetchTrivyConfig(): Promise<void> {
        if (this.config) return;
        if (this.isCancelled) throw new Error('Cancelled');

        try {
            const finalUrl = getApiUrl();
            const response = await axios.get(`${finalUrl}/api/tools/trivy`, { timeout: 15000 });
            this.config = {
                version: response.data.version,
                checksums: response.data.checksums
            };
        } catch (error: any) {
            if (this.isCancelled) throw new Error('Cancelled');
            console.error("Failed to fetch Security Config, falling back to default:", error);
            // Fallback to a known safe version if API fails
            this.config = {
                version: "0.48.3",
                checksums: {
                    'trivy_0.48.3_Linux-64bit.tar.gz': '61f6d5c0fb6ed451c8bab8b13acb5d701f1b532bd6b629f3163f8f57bb10e564',
                    'trivy_0.48.3_Linux-ARM64.tar.gz': '01e814fbb0b2aaaa4510b6c29e9a37103fe9818f70be816c3ecbb39e836a61b5',
                    'trivy_0.48.3_macOS-64bit.tar.gz': '4fc0d1f2ec55869ab4772bd321451023ada4589cc8f9114dae71c7656b2be725',
                    'trivy_0.48.3_macOS-ARM64.tar.gz': '6553a995a97bd7f57c486b7bd38cc297aeeb1125c2eb647cff0866ad6eeef48d',
                    'trivy_0.48.3_windows-64bit.zip': '0d68f69c2605fe7060d64c0dd907df730818fd56107043616fbe274bfdd2d032'
                }
            };
        }
    }

    public async checkAndInstallTrivy(): Promise<void> {
        // Reset cancellation state for a fresh operation
        this.isCancelled = false;
        await this.fetchTrivyConfig();
        if (this.isCancelled) throw new Error('Cancelled');

        const trivyPath = this.getTrivyExecutablePath();
        if (!fs.existsSync(this.context.globalStorageUri.fsPath)) {
            fs.mkdirSync(this.context.globalStorageUri.fsPath, { recursive: true });
        }
        if (fs.existsSync(trivyPath)) return;
        await this.downloadTrivy(trivyPath);
    }

    private async downloadTrivy(destPath: string): Promise<void> {
        if (!this.config) throw new Error("Security configuration not loaded");

        this.isDownloading = true;

        try {
            const platform = os.platform();
            const arch = os.arch();
            let assetName = "";
            if (platform === 'linux') assetName = arch === 'x64' ? `trivy_${this.config.version}_Linux-64bit.tar.gz` : `trivy_${this.config.version}_Linux-ARM64.tar.gz`;
            else if (platform === 'darwin') assetName = arch === 'x64' ? `trivy_${this.config.version}_macOS-64bit.tar.gz` : `trivy_${this.config.version}_macOS-ARM64.tar.gz`;
            else if (platform === 'win32') assetName = `trivy_${this.config.version}_windows-64bit.zip`;
            else throw new Error(`Unsupported platform: ${platform}`);

            const url = `https://github.com/aquasecurity/trivy/releases/download/v${this.config.version}/${assetName}`;
            const tempDir = os.tmpdir();
            const tempArchive = path.join(tempDir, assetName);

            // Download with progress
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: `Downloading Security Engine v${this.config.version}`,
                cancellable: true
            }, async (progress, token) => {
                token.onCancellationRequested(() => {
                    this.cancelScan();
                });

                await this.downloadFile(url, tempArchive, (percent, downloaded, total) => {
                    const mb = (b: number) => (b / 1024 / 1024).toFixed(1);
                    progress.report({
                        message: `${percent}% (${mb(downloaded)}/${mb(total)} MB)`,
                        increment: percent
                    });
                });
            });

            // Verify Checksum
            const expectedHash = this.config.checksums[assetName];
            if (!expectedHash) {
                throw new Error(`No checksum defined for ${assetName}. Security check failed.`);
            }

            const calculatedHash = await this.computeFileHash(tempArchive);
            if (calculatedHash !== expectedHash) {
                fs.unlinkSync(tempArchive);
                throw new Error(`Checksum verification failed for ${assetName}\nExpected: ${expectedHash}\nActual: ${calculatedHash}`);
            }

            const extractDir = path.join(tempDir, 'supreme_security_engine_extract');
            if (!fs.existsSync(extractDir)) fs.mkdirSync(extractDir);

            if (assetName.endsWith('.tar.gz')) {
                await execAsync(`tar -xzf "${tempArchive}" -C "${extractDir}"`);
            } else if (assetName.endsWith('.zip')) {
                // RELIABLE: Use adm-zip instead of shell commands to avoid path/permission issues
                try {
                    const zip = new AdmZip(tempArchive);
                    zip.extractAllTo(extractDir, true);
                } catch (e: any) {
                    throw new Error(`Failed to extract ZIP: ${e.message}`);
                }
            }
            const binName = platform === 'win32' ? 'trivy.exe' : 'trivy';

            // RECURSIVE SEARCH for the binary (it might be in a subfolder)
            const findBinary = (dir: string, file: string): string | null => {
                let files: string[] = [];
                try {
                    files = fs.readdirSync(dir);
                } catch (e) { return null; }

                for (const f of files) {
                    const fullPath = path.join(dir, f);
                    try {
                        const stat = fs.statSync(fullPath);
                        if (stat.isDirectory()) {
                            const found = findBinary(fullPath, file);
                            if (found) return found;
                        } else if (f.toLowerCase() === file.toLowerCase()) {
                            return fullPath;
                        }
                    } catch (e) { continue; }
                }
                return null;
            };

            const foundPath = findBinary(extractDir, binName);
            if (!foundPath) {
                // Debug info: List top-level files
                const debugFiles = fs.readdirSync(extractDir).join(', ');
                throw new Error(`Binary ${binName} not found in extracted archive. Top-level contents: [${debugFiles}]. Check if Antivirus deleted it.`);
            }

            fs.copyFileSync(foundPath, destPath);
            if (platform !== 'win32') fs.chmodSync(destPath, '755');
            fs.unlinkSync(tempArchive);
            fs.rmSync(extractDir, { recursive: true, force: true });
            vscode.window.showInformationMessage('Security Engine ready!');
        } finally {
            this.isDownloading = false;
        }
    }

    private downloadFile(url: string, dest: string, progressCallback?: (percent: number, downloaded: number, total: number) => void): Promise<void> {
        const DOWNLOAD_TIMEOUT_MS = 2 * 60 * 1000; // 2 minutes timeout for download

        return new Promise((resolve, reject) => {
            if (this.isCancelled) {
                reject(new Error('Cancelled'));
                return;
            }

            const file = fs.createWriteStream(dest);

            const request = https.get(url, (response) => {
                if (response.statusCode === 302 || response.statusCode === 301) {
                    file.close();
                    this.downloadFile(response.headers.location!, dest, progressCallback).then(resolve).catch(reject);
                    return;
                }

                const totalSize = parseInt(response.headers['content-length'] || '0', 10);
                let downloadedBytes = 0;
                let lastReportTime = Date.now();

                response.on('data', (chunk) => {
                    downloadedBytes += chunk.length;

                    // Report progress every 500ms to avoid UI flooding
                    const now = Date.now();
                    if (progressCallback && totalSize > 0 && (now - lastReportTime > 500)) {
                        const percent = Math.round((downloadedBytes / totalSize) * 100);
                        progressCallback(percent, downloadedBytes, totalSize);
                        lastReportTime = now;
                    }
                });

                response.pipe(file);

                file.on('finish', () => {
                    file.close();
                    this.currentDownloadRequest = null;
                    // Report 100% on completion
                    if (progressCallback && totalSize > 0) {
                        progressCallback(100, totalSize, totalSize);
                    }
                    resolve();
                });
            });

            this.currentDownloadRequest = request;

            // Timeout handler
            const timeout = setTimeout(() => {
                request.destroy();
                this.currentDownloadRequest = null;
                fs.unlink(dest, () => { });
                reject(new Error('Download timed out after 2 minutes'));
            }, DOWNLOAD_TIMEOUT_MS);

            request.on('error', (err) => {
                clearTimeout(timeout);
                this.currentDownloadRequest = null;
                fs.unlink(dest, () => { });
                reject(err);
            });

            file.on('error', (err) => {
                clearTimeout(timeout);
                request.destroy();
                this.currentDownloadRequest = null;
                fs.unlink(dest, () => { });
                reject(err);
            });

            // Clear timeout on success
            file.on('finish', () => {
                clearTimeout(timeout);
            });
        });
    }

    public async scanFile(filePath: string): Promise<ScanResult | null> {
        // Normalize path for cross-platform compatibility (Windows uses backslashes)
        const normalizedPath = path.normalize(filePath);
        const trivyPath = this.getTrivyExecutablePath();

        // Settings
        const config = vscode.workspace.getConfiguration('supreme');
        const ignoreLow = config.get<boolean>('severity.ignoreLow');
        const ignoreMedium = config.get<boolean>('severity.ignoreMedium');

        if (path.basename(normalizedPath).startsWith('.')) return null;

        // SECURE: Use spawn instead of exec to prevent command injection
        const args = ['fs', normalizedPath, '--scanners', 'vuln,misconfig,secret', '--format', 'json', '--quiet'];

        try {
            const stdout = await this.runTrivySpawn(trivyPath, args);
            if (!stdout) return null;

            const rawResults = JSON.parse(stdout);
            let trivyResults: TrivyResult[] = [];

            if (rawResults.Results) trivyResults = rawResults.Results;
            else if (Array.isArray(rawResults)) trivyResults = rawResults;

            if (trivyResults.length === 0) return null;

            const issues: UnifiedIssue[] = [];
            const res = trivyResults[0];

            const processIssues = async (list: any[], type: 'Vulnerability' | 'Misconfiguration' | 'Secret') => {
                if (!list) return;
                for (const item of list) {
                    // Filter by severity
                    if (ignoreLow && item.Severity === 'LOW') continue;
                    if (ignoreMedium && item.Severity === 'MEDIUM') continue;

                    let startLine = item.StartLine || (item.Location ? item.Location.StartLine : undefined);
                    let endLine = item.EndLine || (item.Location ? item.Location.EndLine : undefined);

                    // Heuristic: If no line number, try to find package name in file
                    if (!startLine && item.PkgName && fs.existsSync(normalizedPath)) {
                        const filename = path.basename(normalizedPath);
                        let loc;
                        // Manifest files
                        if (filename === 'package.json') {
                            loc = await findJsonLocation(normalizedPath, item.PkgName);
                        } else if (filename === 'go.mod') {
                            loc = await findGoModLocation(normalizedPath, item.PkgName);
                        } else if (filename === 'requirements.txt') {
                            loc = await findRequirementsTxtLocation(normalizedPath, item.PkgName);
                        } else if (filename === 'Gemfile') {
                            loc = await findGemfileLocation(normalizedPath, item.PkgName);
                        } else if (filename === 'Cargo.toml') {
                            loc = await findCargoTomlLocation(normalizedPath, item.PkgName);
                        } else if (filename === 'pom.xml') {
                            loc = await findPomXmlLocation(normalizedPath, item.PkgName);
                        }
                        // Lock files (for transitive dependencies)
                        else if (filename === 'package-lock.json') {
                            loc = await findPackageLockLocation(normalizedPath, item.PkgName);
                        } else if (filename === 'yarn.lock') {
                            loc = await findYarnLockLocation(normalizedPath, item.PkgName);
                        } else if (filename === 'Cargo.lock') {
                            loc = await findCargoLockLocation(normalizedPath, item.PkgName);
                        } else if (filename === 'go.sum') {
                            loc = await findGoSumLocation(normalizedPath, item.PkgName);
                        }

                        if (loc) {
                            startLine = loc.startLine;
                            endLine = loc.endLine;
                        }
                    }

                    // Read code snippet for the issue
                    let snippet: string | undefined;
                    if (startLine && fs.existsSync(normalizedPath)) {
                        snippet = await this.readSnippet(normalizedPath, startLine, endLine);
                    }

                    issues.push({
                        ID: item.VulnerabilityID || item.ID || item.RuleID || 'UNKNOWN',
                        Name: item.PkgName || item.Title || item.RuleID || 'Issue',
                        Severity: item.Severity,
                        Description: item.Description || item.Message || '',
                        Url: item.PrimaryURL,
                        Type: type,
                        FixedVersion: item.FixedVersion,
                        PkgPath: item.PkgPath,
                        StartLine: startLine,
                        EndLine: endLine,
                        CodeSnippet: snippet
                    });
                }
            };

            await processIssues(res.Vulnerabilities || [], 'Vulnerability');
            await processIssues(res.Misconfigurations || [], 'Misconfiguration');
            await processIssues(res.Secrets || [], 'Secret');

            return {
                Target: normalizedPath,
                Issues: issues
            };
        } catch (e) {
            console.error(e);
            return null;
        }
    }

    public async runScan(targetPath: string): Promise<ScanResult[]> {
        // Reset cancellation flag so a fresh scan can proceed
        this.isCancelled = false;
        const trivyPath = this.getTrivyExecutablePath();

        // Settings
        const config = vscode.workspace.getConfiguration('supreme');
        const excludePaths = config.get<string[]>('excludePaths') || [];
        const ignoreLow = config.get<boolean>('severity.ignoreLow');
        const ignoreMedium = config.get<boolean>('severity.ignoreMedium');
        const skipDbUpdate = config.get<boolean>('skipDbUpdate') || false;

        vscode.window.showInformationMessage("Supreme: Analyzing codebase... (first run may take a few minutes to download vulnerability database)");

        // SECURE: Use spawn instead of exec
        const args = ['fs', targetPath, '--scanners', 'vuln,misconfig,secret', '--format', 'json'];

        // Check if Trivy DB exists (to avoid first-run error)
        // Trivy stores DB in different locations on different OS
        const possibleDbPaths = [
            path.join(os.homedir(), '.cache', 'trivy', 'db'),           // Linux default
            path.join(os.homedir(), 'Library', 'Caches', 'trivy', 'db'), // macOS
            path.join(process.env.LOCALAPPDATA || '', 'trivy', 'db'),   // Windows
            path.join(os.homedir(), '.trivy', 'db')                     // Alternative
        ];

        let dbExists = false;
        for (const dbPath of possibleDbPaths) {
            try {
                if (fs.existsSync(dbPath) && fs.readdirSync(dbPath).length > 0) {
                    dbExists = true;
                    break;
                }
            } catch (e) {
                // Ignore errors
            }
        }

        if (dbExists) {
            // Only skip DB update if DB already exists
            args.push('--skip-db-update');
            args.push('--offline-scan');
        } else {
            // First run - allow DB download
            vscode.window.showInformationMessage("Supreme: First run - downloading vulnerability database (this may take a few minutes)...");
        }

        try {
            const stdout = await this.runTrivySpawn(trivyPath, args);
            const rawResults = JSON.parse(stdout);

            let trivyResults: TrivyResult[] = [];
            if (rawResults.Results) trivyResults = rawResults.Results;
            else if (Array.isArray(rawResults)) trivyResults = rawResults;

            // Transform
            const results: ScanResult[] = await Promise.all(trivyResults.map(async res => {
                const issues: UnifiedIssue[] = [];
                const fullPath = path.isAbsolute(res.Target) ? res.Target : path.join(targetPath, res.Target);

                // EXCLUSION CHECK
                const relativePath = path.relative(targetPath, fullPath);
                const isDotFile = path.basename(fullPath).startsWith('.');
                const isExcluded = isDotFile || excludePaths.some(ex => {
                    const cleanEx = ex.replace(/\*\*/g, '').replace(/\*/g, '');
                    return relativePath.includes(cleanEx);
                });

                if (isExcluded && excludePaths.length > 0) {
                    return { Target: fullPath, Issues: [] };
                }

                const processIssues = async (list: any[], type: 'Vulnerability' | 'Misconfiguration' | 'Secret') => {
                    if (!list) return;
                    for (const item of list) {
                        // SEVERITY FILTER
                        if (ignoreLow && item.Severity === 'LOW') continue;
                        if (ignoreMedium && item.Severity === 'MEDIUM') continue;

                        let startLine = item.StartLine || (item.Location ? item.Location.StartLine : undefined);
                        let endLine = item.EndLine || (item.Location ? item.Location.EndLine : undefined);

                        // Heuristic line finding
                        if (!startLine && item.PkgName && fs.existsSync(fullPath)) {
                            const filename = path.basename(fullPath);
                            let loc;
                            // Manifest files
                            if (filename === 'package.json') {
                                loc = await findJsonLocation(fullPath, item.PkgName);
                            } else if (filename === 'go.mod') {
                                loc = await findGoModLocation(fullPath, item.PkgName);
                            } else if (filename === 'requirements.txt') {
                                loc = await findRequirementsTxtLocation(fullPath, item.PkgName);
                            } else if (filename === 'Gemfile') {
                                loc = await findGemfileLocation(fullPath, item.PkgName);
                            } else if (filename === 'Cargo.toml') {
                                loc = await findCargoTomlLocation(fullPath, item.PkgName);
                            } else if (filename === 'pom.xml') {
                                loc = await findPomXmlLocation(fullPath, item.PkgName);
                            }
                            // Lock files (for transitive dependencies)
                            else if (filename === 'package-lock.json') {
                                loc = await findPackageLockLocation(fullPath, item.PkgName);
                            } else if (filename === 'yarn.lock') {
                                loc = await findYarnLockLocation(fullPath, item.PkgName);
                            } else if (filename === 'Cargo.lock') {
                                loc = await findCargoLockLocation(fullPath, item.PkgName);
                            } else if (filename === 'go.sum') {
                                loc = await findGoSumLocation(fullPath, item.PkgName);
                            }

                            if (loc) {
                                startLine = loc.startLine;
                                endLine = loc.endLine;
                            }
                        }

                        let snippet = undefined;
                        if (startLine && fullPath && fs.existsSync(fullPath)) {
                            snippet = await this.readSnippet(fullPath, startLine, endLine);
                        }

                        issues.push({
                            ID: item.VulnerabilityID || item.ID || item.RuleID || 'UNKNOWN',
                            Name: item.PkgName || item.Title || item.RuleID || 'Issue',
                            Severity: item.Severity,
                            Description: item.Description || item.Message || '',
                            Url: item.PrimaryURL,
                            Type: type,
                            FixedVersion: item.FixedVersion,
                            PkgPath: item.PkgPath,
                            StartLine: startLine,
                            EndLine: endLine,
                            CodeSnippet: snippet
                        });
                    }
                };

                await processIssues(res.Vulnerabilities || [], 'Vulnerability');
                await processIssues(res.Misconfigurations || [], 'Misconfiguration');
                await processIssues(res.Secrets || [], 'Secret');

                return {
                    Target: fullPath, // Use absolute path for history to work correctly
                    Issues: issues
                };
            }));

            const cleanResults = results.filter(r => r.Issues.length > 0);
            await this.saveHistory(cleanResults);

            // Mark that we've scanned this session for auto DB skip
            this.hasScannedThisSession = true;

            return cleanResults;
        } catch (error: any) {
            console.error("Scan failed", error);
            throw new Error(`Security scan failed: ${error.message}`);
        }
    }

    // Helper to run spawn as a promise with cancellation support and timeout
    private runTrivySpawn(command: string, args: string[]): Promise<string> {
        const SCAN_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes timeout

        return new Promise((resolve, reject) => {
            const child = spawn(command, args, { maxBuffer: 1024 * 1024 * 100 } as any);
            this.currentScanProcess = child;

            let stdout = '';
            let stderr = '';

            // Timeout handler
            const timeout = setTimeout(() => {
                if (this.currentScanProcess) {
                    console.error('Trivy scan timed out after 5 minutes');
                    vscode.window.showErrorMessage('Scan timed out after 5 minutes. Try scanning a smaller directory or check your network connection.');
                    this.currentScanProcess.kill('SIGTERM');
                    this.currentScanProcess = null;
                    reject(new Error('Scan timed out after 5 minutes'));
                }
            }, SCAN_TIMEOUT_MS);

            child.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            child.stderr.on('data', (data) => {
                const chunk = data.toString();
                stderr += chunk;
                // Log progress to console for debugging
                console.log('[Trivy]', chunk.trim());
            });

            child.on('close', (code) => {
                clearTimeout(timeout);
                this.currentScanProcess = null;

                if (this.isCancelled) {
                    reject(new Error('Scan cancelled by user'));
                    return;
                }

                if (code === 0) {
                    resolve(stdout);
                } else {
                    console.error('Trivy stderr:', stderr);
                    reject(new Error(`Security Engine exited with code ${code}: ${stderr.slice(-500)}`));
                }
            });

            child.on('error', (err) => {
                clearTimeout(timeout);
                this.currentScanProcess = null;
                reject(err);
            });
        });
    }

    private static readonly MAX_SNIPPET_CHARS = 2000;

    private async readSnippet(filePath: string, start: number, end: number): Promise<string> {
        try {
            const fileContent = await fs.promises.readFile(filePath, 'utf-8');
            const lines = fileContent.split('\n');
            const contextStart = Math.max(0, start - 3);
            const contextEnd = Math.min(lines.length, (end || start) + 2);

            let snippet = '';
            for (let i = contextStart; i < contextEnd; i++) {
                const lineNum = i + 1;
                const isTarget = lineNum >= start && lineNum <= (end || start);
                const prefix = isTarget ? '>' : ' ';
                snippet += `${prefix} ${lineNum.toString().padEnd(4)} | ${lines[i]}\n`;

                // Limit snippet size to prevent memory issues
                if (snippet.length >= TrivyService.MAX_SNIPPET_CHARS) {
                    return snippet.substring(0, TrivyService.MAX_SNIPPET_CHARS) + '\n... (truncated)';
                }
            }
            return snippet;
        } catch (e) {
            return "Unable to read file content.";
        }
    }

    private static HISTORY_KEY = 'supreme.scanHistory';
    private static DB_LAST_UPDATE_KEY = 'supreme.dbLastUpdate';

    public async saveHistory(results: ScanResult[]): Promise<void> {
        let history = this.getHistory();

        // Calculate summary for charts
        let t = 0, c = 0, h = 0, m = 0, l = 0;
        results.forEach(r => r.Issues.forEach(i => {
            t++;
            if (i.Severity === 'CRITICAL') c++;
            if (i.Severity === 'HIGH') h++;
            if (i.Severity === 'MEDIUM') m++;
            if (i.Severity === 'LOW') l++;
        }));

        const newEntry: HistoryEntry = {
            id: Date.now().toString(),
            date: new Date().toLocaleString(),
            results: results,
            summary: { total: t, critical: c, high: h, medium: m, low: l }
        };

        history.unshift(newEntry);
        if (history.length > 20) history = history.slice(0, 20);

        await this.context.globalState.update(TrivyService.HISTORY_KEY, history);
    }

    public getHistory(): HistoryEntry[] {
        return this.context.globalState.get<HistoryEntry[]>(TrivyService.HISTORY_KEY) || [];
    }

    public deleteHistoryEntry(id: string): void {
        const history = this.getHistory();
        const newHistory = history.filter(h => h.id !== id);
        this.writeHistory(newHistory);
    }

    public clearHistory(): void {
        this.writeHistory([]);
    }

    public async updateDatabase(): Promise<{ success: boolean; message: string }> {
        try {
            await this.checkAndInstallTrivy();
            const trivyPath = this.getTrivyExecutablePath();

            if (!fs.existsSync(trivyPath)) {
                return { success: false, message: 'Scanner not installed' };
            }

            return new Promise((resolve) => {
                const args = ['--quiet', 'image', '--download-db-only'];
                const child = spawn(trivyPath, args);

                let stderr = '';
                child.stderr.on('data', (data) => {
                    stderr += data.toString();
                });

                child.on('close', (code) => {
                    if (code === 0) {
                        this.setLastDbUpdate(new Date().toISOString());
                        resolve({ success: true, message: 'Database updated' });
                    } else {
                        // Check if already up to date
                        if (stderr.includes('DB Repository: ghcr.io') || stderr.includes('already latest')) {
                            this.setLastDbUpdate(new Date().toISOString());
                            resolve({ success: true, message: 'Already up to date' });
                        } else {
                            resolve({ success: false, message: 'Update failed' });
                        }
                    }
                });

                child.on('error', () => {
                    resolve({ success: false, message: 'Failed to run update' });
                });

                // Timeout after 60 seconds
                setTimeout(() => {
                    child.kill();
                    resolve({ success: false, message: 'Update timed out' });
                }, 60000);
            });
        } catch (err) {
            return { success: false, message: 'Update error' };
        }
    }

    public getLastDbUpdate(): string | null {
        return this.context.globalState.get<string>(TrivyService.DB_LAST_UPDATE_KEY) || null;
    }

    public setLastDbUpdate(timestamp: string): void {
        this.context.globalState.update(TrivyService.DB_LAST_UPDATE_KEY, timestamp);
    }

    private writeHistory(history: HistoryEntry[]): void {
        this.context.globalState.update(TrivyService.HISTORY_KEY, history);
    }

    public getHistoryEntry(id: string): HistoryEntry | undefined {
        const history = this.getHistory();
        return history.find(h => h.id === id);
    }

    private computeFileHash(filePath: string): Promise<string> {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(filePath);
            stream.on('error', err => reject(err));
            stream.on('data', chunk => hash.update(chunk));
            stream.on('end', () => resolve(hash.digest('hex')));
        });
    }
}
