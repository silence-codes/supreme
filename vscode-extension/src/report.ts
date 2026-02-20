import * as vscode from 'vscode';
import { ScanResult, ScanIssue } from './pythonBridge';

// Helper function to escape HTML to prevent XSS
function escapeHtml(unsafe: string): string {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

export function generateReportHtml(results: ScanResult[], webview: vscode.Webview): string {
    const style = `
        :root {
            --glass-bg: rgba(30, 30, 30, 0.6);
            --glass-border: rgba(255, 255, 255, 0.1);
            --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
            --primary-color: #9b59b6;
            --text-color: #e0e0e0;
            --code-bg: #0d0d0d;
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #050505;
            background-image: 
                radial-gradient(circle at 15% 50%, rgba(155, 89, 182, 0.08), transparent 25%), 
                radial-gradient(circle at 85% 30%, rgba(52, 152, 219, 0.08), transparent 25%);
            background-attachment: fixed;
            color: var(--text-color);
            padding: 40px 20px;
            margin: 0;
            line-height: 1.6;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
        }

        h1 {
            font-size: 2.5rem;
            font-weight: 200;
            color: #fff;
            margin-bottom: 0.5rem;
            letter-spacing: -1px;
        }

        .subtitle {
            color: #888;
            margin-bottom: 3rem;
            font-size: 1.1rem;
            font-weight: 300;
            display: flex;
            gap: 15px;
            align-items: center;
        }

        .card {
            background: var(--glass-bg);
            border-radius: 12px;
            box-shadow: var(--glass-shadow);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            border: 1px solid var(--glass-border);
            margin-bottom: 2rem;
            padding: 1.5rem;
            overflow: hidden;
            position: relative;
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; bottom: 0; width: 4px;
            background: #555; 
        }
        .card.severity-CRITICAL::before { background: #ff5252; box-shadow: 0 0 10px #ff5252; }
        .card.severity-HIGH::before { background: #ffb142; }
        .card.severity-MEDIUM::before { background: #ffda79; }
        .card.severity-LOW::before { background: #34ace0; }
        .card.severity-INFO::before { background: #636e72; }

        .card-header {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: flex-start;
            gap: 15px;
            margin-bottom: 1rem;
        }

        .issue-main {
            flex: 1;
            min-width: 250px;
        }

        .issue-title {
            font-size: 1.4rem;
            font-weight: 600;
            color: #fff;
            margin-top: 8px;
            word-break: break-word;
            line-height: 1.3;
        }

        .badges {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }

        .badge-type { background: rgba(255, 255, 255, 0.1); color: #aaa; }

        .severity-badge {
            background: #333;
            color: #fff;
        }
        .severity-badge.CRITICAL { color: #ff5252; background: rgba(255, 82, 82, 0.15); }
        .severity-badge.HIGH { color: #ffb142; background: rgba(255, 177, 66, 0.15); }
        .severity-badge.MEDIUM { color: #ffda79; background: rgba(255, 218, 121, 0.15); }
        .severity-badge.LOW { color: #34ace0; background: rgba(52, 172, 224, 0.15); }
        .severity-badge.INFO { color: #636e72; background: rgba(99, 110, 114, 0.15); }

        .description {
            color: #ccc;
            margin-bottom: 1.5rem;
            font-size: 1rem;
            word-wrap: break-word;
        }

        .code-block {
            background: var(--code-bg);
            padding: 1rem;
            border-radius: 6px;
            border: 1px solid #222;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            color: #d4d4d4;
            margin: 1.5rem 0;
            white-space: pre;
            box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
        }

        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 20px;
            padding-top: 1.5rem;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }

        .meta-item {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .meta-label {
            font-size: 0.7rem;
            text-transform: uppercase;
            color: #666;
            font-weight: 600;
            letter-spacing: 1px;
        }

        .meta-value {
            font-size: 0.9rem;
            color: #eee;
            word-break: break-all;
            font-family: monospace;
        }

        a.meta-value {
            color: #a29bfe;
            text-decoration: none;
            transition: opacity 0.2s;
        }
        a.meta-value:hover {
            opacity: 0.8;
            text-decoration: underline;
        }
    `;

    let content = '';
    let totalIssues = 0;

    results.forEach(target => {
        if (!target.Issues || target.Issues.length === 0) return;

        target.Issues.forEach(issue => {
            totalIssues++;
            const filePath = target.Target;
            const commandUri = `command:vscode.open?${encodeURIComponent(JSON.stringify(vscode.Uri.file(filePath)))}`;

            // Encode code snippet safely
            const safeCode = issue.CodeSnippet
                ? issue.CodeSnippet.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
                : null;

            const codeHtml = safeCode
                ? `<div class="code-block">${safeCode}</div>`
                : `<div style="font-style:italic; color:#666; margin: 10px 0; font-size:0.9em;">No code snippet available (Line ${issue.StartLine || 'unknown'})</div>`;

            const cweHtml = issue.CWE
                ? `<div class="meta-item"><span class="meta-label">CWE</span><a href="${issue.CWELink || '#'}" class="meta-value">${issue.CWE}</a></div>`
                : '';

            content += `
                <div class="card severity-${issue.Severity}">
                    <div class="card-header">
                        <div class="issue-main">
                            <div class="badges">
                                <span class="badge badge-type">${escapeHtml(issue.Type)}</span>
                                <span class="badge severity-badge ${issue.Severity}">${issue.Severity}</span>
                            </div>
                            <div class="issue-title">${escapeHtml(issue.Name)}</div>
                        </div>
                    </div>
                    
                    <div class="description">${escapeHtml(issue.Description || 'No description available.')}</div>
                    
                    ${codeHtml}

                    <div class="meta-grid">
                        <div class="meta-item">
                            <span class="meta-label">Identifier</span>
                            <span class="meta-value">${escapeHtml(issue.ID)}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Location</span>
                            <a href="${commandUri}" class="meta-value" title="Open File">${filePath}${issue.StartLine ? `:${issue.StartLine}` : ''}</a>
                        </div>
                        ${cweHtml}
                    </div>
                </div>
            `;
        });
    });

    if (totalIssues === 0) {
        content = `
            <div style="text-align:center; margin-top: 100px; opacity: 0.7;">
                <h2 style="color: #2ecc71; margin-top: 20px;">All systems operational</h2>
                <p>No vulnerabilities found.</p>
            </div>`;
    }

    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Supreme Report</title>
            <style>${style}</style>
        </head>
        <body>
            <div class="container">
                <h1>Supreme Report</h1>
                <div class="subtitle">
                    <span>${new Date().toLocaleString()}</span>
                    <span>&bull;</span>
                    <span>${totalIssues} issues detected</span>
                </div>
                ${content}
            </div>
        </body>
        </html>
    `;
}
