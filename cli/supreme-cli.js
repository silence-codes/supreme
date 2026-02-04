#!/usr/bin/env node

/**
 * Supreme Security CLI
 * Usage: supreme scan [options] <path>
 * 
 * Options:
 *   --ci                  CI mode (non-interactive, exit codes based on findings)
 *   --format <format>     Output format: json, table, sarif (default: table)
 *   --severity <levels>   Filter by severity: critical,high,medium,low (default: all)
 *   --fail-on <level>     Exit with code 1 if issues of this severity or higher found
 *   --license <key>       License key for validation
 *   --skip-license        Skip license validation (limited functionality)
 *   --help                Show help
 *   --version             Show version
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const os = require('os');

// Constants
const VERSION = '1.0.0';
const API_URL = process.env.SUPREME_API_URL || 'https://api.supreme-security.com';
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

// Colors for terminal output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    green: '\x1b[32m',
    cyan: '\x1b[36m',
    gray: '\x1b[90m',
    bold: '\x1b[1m'
};

// Parse arguments
function parseArgs(args) {
    const options = {
        command: null,
        path: null,
        ci: false,
        format: 'table',
        severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        failOn: null,
        license: process.env.SUPREME_LICENSE_KEY || null,
        skipLicense: false,
        help: false,
        version: false
    };

    let i = 0;
    while (i < args.length) {
        const arg = args[i];

        if (arg === 'scan') {
            options.command = 'scan';
        } else if (arg === '--ci') {
            options.ci = true;
        } else if (arg === '--format' && args[i + 1]) {
            options.format = args[++i];
        } else if (arg === '--severity' && args[i + 1]) {
            options.severity = args[++i].toUpperCase().split(',');
        } else if (arg === '--fail-on' && args[i + 1]) {
            options.failOn = args[++i].toUpperCase();
        } else if (arg === '--license' && args[i + 1]) {
            options.license = args[++i];
        } else if (arg === '--skip-license') {
            options.skipLicense = true;
        } else if (arg === '--help' || arg === '-h') {
            options.help = true;
        } else if (arg === '--version' || arg === '-v') {
            options.version = true;
        } else if (!arg.startsWith('-') && !options.path && options.command) {
            options.path = arg;
        }
        i++;
    }

    return options;
}

// Show help
function showHelp() {
    console.log(`
${colors.bold}Supreme Security CLI${colors.reset} v${VERSION}

${colors.cyan}Usage:${colors.reset}
  supreme scan [options] <path>

${colors.cyan}Commands:${colors.reset}
  scan <path>           Scan a directory or file for vulnerabilities

${colors.cyan}Options:${colors.reset}
  --ci                  CI mode (non-interactive, structured output)
  --format <format>     Output format: json, table, sarif (default: table)
  --severity <levels>   Filter: critical,high,medium,low (default: all)
  --fail-on <level>     Exit 1 if issues >= this severity found
  --license <key>       License key (or set SUPREME_LICENSE_KEY env var)
  --skip-license        Skip license check (limited to 10 issues shown)
  --help, -h            Show this help
  --version, -v         Show version

${colors.cyan}Examples:${colors.reset}
  supreme scan ./src
  supreme scan --ci --format json ./project
  supreme scan --ci --fail-on high ./src
  SUPREME_LICENSE_KEY=xxx supreme scan --ci ./

${colors.cyan}Exit Codes:${colors.reset}
  0  No issues found (or below --fail-on threshold)
  1  Issues found above --fail-on threshold
  2  Error (scan failed, invalid arguments, etc.)

${colors.cyan}Environment Variables:${colors.reset}
  SUPREME_LICENSE_KEY   License key for validation
  SUPREME_API_URL       API URL (default: https://api.supreme-security.com)
`);
}

// Find Trivy binary
function findTrivyBinary() {
    const platform = os.platform();
    const isWin = platform === 'win32';
    const trivyExe = isWin ? 'trivy.exe' : 'trivy';

    // VS Code stores extension data in globalStorage
    // Path pattern: ~/.vscode/extensions/globalStorage/silenceaillc.supreme/trivy
    const vscodeDataDirs = isWin ? [
        path.join(process.env.APPDATA || '', 'Code', 'User', 'globalStorage'),
        path.join(process.env.APPDATA || '', 'Code - Insiders', 'User', 'globalStorage'),
        path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Microsoft VS Code', 'resources', 'app', 'extensions')
    ] : [
        path.join(os.homedir(), '.config', 'Code', 'User', 'globalStorage'),
        path.join(os.homedir(), '.config', 'Code - Insiders', 'User', 'globalStorage'),
        path.join(os.homedir(), '.vscode-server', 'data', 'User', 'globalStorage')
    ];

    // Check VS Code globalStorage directories
    for (const dataDir of vscodeDataDirs) {
        if (fs.existsSync(dataDir)) {
            try {
                const entries = fs.readdirSync(dataDir);
                for (const entry of entries) {
                    // Look for silenceaillc.supreme or supreme
                    if (entry.includes('supreme') || entry.includes('silenceaillc')) {
                        const trivyPath = path.join(dataDir, entry, trivyExe);
                        if (fs.existsSync(trivyPath)) {
                            return trivyPath;
                        }
                    }
                }
            } catch (e) {
                // Ignore errors
            }
        }
    }

    // Check VS Code extension directories (legacy/fallback)
    const vscodeExtDirs = isWin ? [
        path.join(os.homedir(), '.vscode', 'extensions'),
        path.join(os.homedir(), '.vscode-insiders', 'extensions')
    ] : [
        path.join(os.homedir(), '.vscode', 'extensions'),
        path.join(os.homedir(), '.vscode-server', 'extensions')
    ];

    for (const extDir of vscodeExtDirs) {
        if (fs.existsSync(extDir)) {
            try {
                const dirs = fs.readdirSync(extDir);
                for (const dir of dirs) {
                    if (dir.startsWith('silenceaillc.supreme-') || dir.includes('supreme')) {
                        const trivyPath = path.join(extDir, dir, 'bin', trivyExe);
                        if (fs.existsSync(trivyPath)) {
                            return trivyPath;
                        }
                    }
                }
            } catch (e) {
                // Ignore errors
            }
        }
    }

    // Check common system-wide installation paths
    const systemPaths = isWin ? [
        path.join(process.env.LOCALAPPDATA || '', 'Programs', 'trivy', 'trivy.exe'),
        path.join(process.env.ProgramFiles || '', 'trivy', 'trivy.exe'),
        'C:\\ProgramData\\chocolatey\\bin\\trivy.exe'
    ] : [
        '/usr/local/bin/trivy',
        '/usr/bin/trivy',
        '/opt/homebrew/bin/trivy',
        path.join(os.homedir(), '.local', 'bin', 'trivy')
    ];

    for (const p of systemPaths) {
        if (fs.existsSync(p)) {
            return p;
        }
    }

    // Try to find in PATH
    try {
        const cmd = isWin ? 'where trivy 2>nul' : 'which trivy 2>/dev/null';
        const result = require('child_process').execSync(cmd, { encoding: 'utf8' });
        if (result.trim()) {
            return result.trim().split('\n')[0].trim();
        }
    } catch (e) {
        // Not found in PATH
    }

    return null;
}

// Validate license
async function validateLicense(licenseKey) {
    return new Promise((resolve) => {
        if (!licenseKey) {
            resolve({ valid: false, reason: 'No license key provided' });
            return;
        }

        const url = new URL(`${API_URL}/api/license/validate`);
        const protocol = url.protocol === 'https:' ? https : http;

        const postData = JSON.stringify({
            license_key: licenseKey,
            machine_id: `cli-${os.hostname()}`
        });

        const req = protocol.request(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            },
            timeout: 10000
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const json = JSON.parse(data);
                    resolve({ valid: json.valid === true, reason: json.message || '' });
                } catch (e) {
                    resolve({ valid: false, reason: 'Invalid response from server' });
                }
            });
        });

        req.on('error', () => {
            // Allow offline usage with warning
            resolve({ valid: true, reason: 'Offline mode - license not verified', offline: true });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ valid: true, reason: 'Timeout - license not verified', offline: true });
        });

        req.write(postData);
        req.end();
    });
}

// Run Trivy scan
function runScan(trivyPath, targetPath, options) {
    return new Promise((resolve, reject) => {
        const args = [
            'fs',
            targetPath,
            '--scanners', 'vuln,misconfig,secret',
            '--format', 'json'
        ];

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
            args.push('--skip-db-update');
            args.push('--offline-scan');
        } else {
            if (!options.ci) {
                console.log('First run - downloading vulnerability database...');
            }
        }

        const child = spawn(trivyPath, args);
        let stdout = '';
        let stderr = '';

        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        child.on('close', (code) => {
            if (code !== 0 && !stdout) {
                reject(new Error(`Scan failed: ${stderr}`));
                return;
            }

            try {
                const results = JSON.parse(stdout);
                resolve(results);
            } catch (e) {
                reject(new Error(`Failed to parse scan results: ${e.message}`));
            }
        });

        child.on('error', (err) => {
            reject(err);
        });
    });
}

// Process results
function processResults(rawResults, options) {
    const issues = [];

    const results = rawResults.Results || rawResults;
    if (!Array.isArray(results)) {
        return issues;
    }

    for (const result of results) {
        const target = result.Target || 'unknown';

        // Vulnerabilities
        if (result.Vulnerabilities) {
            for (const vuln of result.Vulnerabilities) {
                if (options.severity.includes(vuln.Severity)) {
                    issues.push({
                        type: 'vulnerability',
                        id: vuln.VulnerabilityID,
                        severity: vuln.Severity,
                        package: vuln.PkgName,
                        version: vuln.InstalledVersion,
                        fixedVersion: vuln.FixedVersion,
                        title: vuln.Title || vuln.Description?.substring(0, 100),
                        target: target
                    });
                }
            }
        }

        // Misconfigurations
        if (result.Misconfigurations) {
            for (const misconfig of result.Misconfigurations) {
                if (options.severity.includes(misconfig.Severity)) {
                    issues.push({
                        type: 'misconfiguration',
                        id: misconfig.ID,
                        severity: misconfig.Severity,
                        title: misconfig.Title,
                        message: misconfig.Message,
                        target: target
                    });
                }
            }
        }

        // Secrets
        if (result.Secrets) {
            for (const secret of result.Secrets) {
                issues.push({
                    type: 'secret',
                    id: secret.RuleID,
                    severity: 'HIGH',
                    title: secret.Title,
                    match: secret.Match?.substring(0, 50) + '...',
                    target: target
                });
            }
        }
    }

    return issues;
}

// Format output
function formatOutput(issues, options) {
    if (options.format === 'json') {
        return JSON.stringify({
            version: VERSION,
            timestamp: new Date().toISOString(),
            summary: {
                total: issues.length,
                critical: issues.filter(i => i.severity === 'CRITICAL').length,
                high: issues.filter(i => i.severity === 'HIGH').length,
                medium: issues.filter(i => i.severity === 'MEDIUM').length,
                low: issues.filter(i => i.severity === 'LOW').length
            },
            issues: issues
        }, null, 2);
    }

    if (options.format === 'sarif') {
        return JSON.stringify({
            $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            version: '2.1.0',
            runs: [{
                tool: {
                    driver: {
                        name: 'Supreme Security',
                        version: VERSION,
                        informationUri: 'https://supreme.silence.codes'
                    }
                },
                results: issues.map(issue => ({
                    ruleId: issue.id,
                    level: issue.severity === 'CRITICAL' || issue.severity === 'HIGH' ? 'error' : 'warning',
                    message: { text: issue.title || issue.message || issue.id },
                    locations: [{
                        physicalLocation: {
                            artifactLocation: { uri: issue.target }
                        }
                    }]
                }))
            }]
        }, null, 2);
    }

    // Table format (default)
    if (issues.length === 0) {
        return `${colors.green}✓ No security issues found${colors.reset}`;
    }

    let output = `\n${colors.bold}Supreme Security Scan Results${colors.reset}\n`;
    output += `${'─'.repeat(60)}\n\n`;

    const summary = {
        CRITICAL: issues.filter(i => i.severity === 'CRITICAL').length,
        HIGH: issues.filter(i => i.severity === 'HIGH').length,
        MEDIUM: issues.filter(i => i.severity === 'MEDIUM').length,
        LOW: issues.filter(i => i.severity === 'LOW').length
    };

    output += `${colors.bold}Summary:${colors.reset} `;
    output += `${colors.red}${summary.CRITICAL} Critical${colors.reset} | `;
    output += `${colors.yellow}${summary.HIGH} High${colors.reset} | `;
    output += `${colors.cyan}${summary.MEDIUM} Medium${colors.reset} | `;
    output += `${colors.gray}${summary.LOW} Low${colors.reset}\n\n`;

    // Group by severity
    for (const severity of SEVERITY_ORDER) {
        const sevIssues = issues.filter(i => i.severity === severity);
        if (sevIssues.length === 0) continue;

        const color = severity === 'CRITICAL' ? colors.red :
            severity === 'HIGH' ? colors.yellow :
                severity === 'MEDIUM' ? colors.cyan : colors.gray;

        output += `${color}${colors.bold}[${severity}]${colors.reset}\n`;

        for (const issue of sevIssues.slice(0, options.skipLicense ? 10 : 100)) {
            output += `  ${issue.id}: ${issue.title || issue.package || issue.message}\n`;
            if (issue.package) {
                output += `    ${colors.gray}Package: ${issue.package}@${issue.version}`;
                if (issue.fixedVersion) {
                    output += ` → ${issue.fixedVersion}`;
                }
                output += `${colors.reset}\n`;
            }
            output += `    ${colors.gray}Location: ${issue.target}${colors.reset}\n`;
        }
        output += '\n';
    }

    if (options.skipLicense && issues.length > 10) {
        output += `${colors.yellow}⚠ Showing 10 of ${issues.length} issues. Activate license for full results.${colors.reset}\n`;
    }

    return output;
}

// Determine exit code
function getExitCode(issues, failOn) {
    if (!failOn || issues.length === 0) {
        return 0;
    }

    const failIndex = SEVERITY_ORDER.indexOf(failOn);
    if (failIndex === -1) {
        return 0;
    }

    const targetSeverities = SEVERITY_ORDER.slice(0, failIndex + 1);
    const hasFailingIssues = issues.some(i => targetSeverities.includes(i.severity));

    return hasFailingIssues ? 1 : 0;
}

// Main
async function main() {
    const args = process.argv.slice(2);
    const options = parseArgs(args);

    if (options.version) {
        console.log(`Supreme Security CLI v${VERSION}`);
        process.exit(0);
    }

    if (options.help || !options.command) {
        showHelp();
        process.exit(options.help ? 0 : 2);
    }

    if (options.command === 'scan') {
        if (!options.path) {
            console.error(`${colors.red}Error: Please specify a path to scan${colors.reset}`);
            console.error('Usage: supreme scan <path>');
            process.exit(2);
        }

        // Resolve path
        const targetPath = path.resolve(options.path);
        if (!fs.existsSync(targetPath)) {
            console.error(`${colors.red}Error: Path does not exist: ${targetPath}${colors.reset}`);
            process.exit(2);
        }

        // Find Trivy
        const trivyPath = findTrivyBinary();
        if (!trivyPath) {
            console.error(`${colors.red}Error: Trivy scanner not found${colors.reset}`);
            console.error('Please ensure the Supreme Security VS Code extension is installed,');
            console.error('or install Trivy manually: https://trivy.dev');
            process.exit(2);
        }

        // Validate license
        if (!options.skipLicense) {
            if (!options.ci) {
                process.stdout.write('Validating license... ');
            }
            const licenseResult = await validateLicense(options.license);
            if (!licenseResult.valid) {
                if (!options.ci) {
                    console.log(`${colors.yellow}⚠ ${licenseResult.reason}${colors.reset}`);
                    console.log('Running in limited mode. Use --skip-license to suppress this warning.\n');
                }
                options.skipLicense = true;
            } else if (licenseResult.offline) {
                if (!options.ci) {
                    console.log(`${colors.yellow}⚠ ${licenseResult.reason}${colors.reset}\n`);
                }
            } else {
                if (!options.ci) {
                    console.log(`${colors.green}✓ License valid${colors.reset}\n`);
                }
            }
        }

        // Run scan
        if (!options.ci) {
            console.log(`Scanning ${targetPath}...`);
        }

        try {
            const rawResults = await runScan(trivyPath, targetPath, options);
            const issues = processResults(rawResults, options);
            const output = formatOutput(issues, options);

            console.log(output);

            const exitCode = getExitCode(issues, options.failOn);
            process.exit(exitCode);
        } catch (err) {
            console.error(`${colors.red}Error: ${err.message}${colors.reset}`);
            process.exit(2);
        }
    }
}

main().catch(err => {
    console.error(`${colors.red}Fatal error: ${err.message}${colors.reset}`);
    process.exit(2);
});
