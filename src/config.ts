
import * as vscode from 'vscode';

export const CONFIG = {
    API: {
        PRODUCTION_URL: 'https://supreme.silence.codes',
        LOCAL_URL: 'http://localhost:3001',
        ENDPOINTS: {
            VALIDATE_LICENSE: '/api/license/validate',
        }
    },
    WEBSITE_URL: 'https://supreme.silence.codes',
    STORAGE: {
        LICENSE_KEY: 'supreme.licenseKey',
    },
    DEFAULTS: {
        TRIVY_VERSION: "0.48.3",
    }
};

export function getApiUrl(): string {
    const config = vscode.workspace.getConfiguration('supreme');
    const serverUrl = config.get<string>('serverUrl');

    // Explicit override takes precedence
    if (serverUrl) {
        // Security Check: Only allow localhost if developerMode is enabled
        const isDevMode = config.get<boolean>('developerMode');
        if (serverUrl.includes('localhost') && !isDevMode) {
            vscode.window.showWarningMessage('Supreme: Localhost server URL ignored because Developer Mode is disabled.');
            return CONFIG.API.PRODUCTION_URL;
        }
        return serverUrl;
    }

    return CONFIG.API.PRODUCTION_URL;
}
