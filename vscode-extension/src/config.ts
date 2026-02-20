import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

import * as os from 'os';

export const CONFIG = {
    COMMANDS: {
        START_SCAN: 'supreme2l.startScan',
        STOP_SCAN: 'supreme2l.stopScan',
        EXPORT_REPORT: 'supreme2l.exportReport',
        INSTALL_TOOLS: 'supreme2l.installTools'
    },
    VIEWS: {
        DASHBOARD: 'supreme2l-dashboard',
        RESULTS: 'supreme2l-results'
    },
    SETTINGS: {
        PYTHON_PATH: 'supreme2l.pythonPath',
        EXCLUDE_PATHS: 'supreme2l.excludePaths',
        SEVERITY_FILTER: 'supreme2l.severityFilter'
    }
};

export function getGlobalVenvPath(): string {
    return path.join(os.homedir(), '.supreme2l', 'venv');
}

export function getGlobalPythonPath(): string {
    const venvPath = getGlobalVenvPath();
    const isWin = process.platform === 'win32';
    return path.join(venvPath, isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python');
}

export function getPythonPath(): string {
    const config = vscode.workspace.getConfiguration();
    const settingPath = config.get<string>(CONFIG.SETTINGS.PYTHON_PATH);
    if (settingPath) {
        return settingPath;
    }

    // 1. Check Global Managed Venv
    const globalPython = getGlobalPythonPath();
    if (fs.existsSync(globalPython)) {
        return globalPython;
    }

    // 2. Check if the Python extension has a selected interpreter
    const pythonConfig = vscode.workspace.getConfiguration('python');
    const pythonInterpreter = pythonConfig.get<string>('defaultInterpreterPath');
    if (pythonInterpreter && pythonInterpreter !== 'python' && fs.existsSync(pythonInterpreter)) {
        return pythonInterpreter;
    }

    // 3. Try to auto-detect venv in workspace root
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders && workspaceFolders.length > 0) {
        const rootPath = workspaceFolders[0].uri.fsPath;
        const venvPaths = [
            path.join(rootPath, '.venv', 'bin', 'python'),
            path.join(rootPath, '.venv', 'Scripts', 'python.exe'),
            path.join(rootPath, 'venv', 'bin', 'python'),
            path.join(rootPath, 'venv', 'Scripts', 'python.exe'),
        ];

        for (const p of venvPaths) {
            if (fs.existsSync(p)) {
                return p;
            }
        }
    }

    return 'python3';
}

export function getExcludePaths(): string[] {
    const config = vscode.workspace.getConfiguration();
    return config.get<string[]>(CONFIG.SETTINGS.EXCLUDE_PATHS) || [];
}
