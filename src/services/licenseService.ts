import * as vscode from 'vscode';
import axios, { AxiosResponse } from 'axios';
import { CONFIG, getApiUrl } from '../config';

const LICENSE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const HTTP_TIMEOUT_MS = 10000; // 10 seconds
const OFFLINE_GRACE_PERIOD_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 1000; // 1 second

// Utility: Delay function
function delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Utility: Retry with exponential backoff
async function fetchWithRetry<T>(
    requestFn: () => Promise<AxiosResponse<T>>,
    maxRetries: number = MAX_RETRIES
): Promise<AxiosResponse<T>> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            return await requestFn();
        } catch (err: any) {
            lastError = err;

            // Don't retry on 4xx errors (client errors)
            if (err.response && err.response.status >= 400 && err.response.status < 500) {
                throw err;
            }

            // Last attempt - don't delay, just throw
            if (attempt === maxRetries - 1) {
                throw err;
            }

            // Exponential backoff: 1s, 2s, 4s
            const delayMs = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);
            console.log(`License request failed (attempt ${attempt + 1}/${maxRetries}), retrying in ${delayMs}ms...`);
            await delay(delayMs);
        }
    }

    throw lastError;
}

interface LicenseCache {
    isValid: boolean;
    expiresAt: string | null;
    cachedAt: number;
    lastOnlineCheck: number;
}

export class LicenseService {
    private cache: LicenseCache | null = null;
    private onLicenseChange: ((isLicensed: boolean) => void) | null = null;

    constructor(private context: vscode.ExtensionContext) {
        // Clear cache on startup to force re-validation
        // This ensures deleted licenses are detected immediately
        this.cache = null;
        // Don't load from storage - always verify with server on startup
    }

    public async clearCache(): Promise<void> {
        this.cache = null;
        await this.context.globalState.update('supreme.licenseCache', undefined);
        await this.context.globalState.update(CONFIG.STORAGE.LICENSE_KEY, undefined);
    }

    public setOnLicenseChange(callback: (isLicensed: boolean) => void) {
        this.onLicenseChange = callback;
    }

    private getValidationUrl(): string {
        return `${getApiUrl()}${CONFIG.API.ENDPOINTS.VALIDATE_LICENSE}`;
    }

    private getMachineId(): string {
        return vscode.env.machineId;
    }

    private async saveCache(cache: LicenseCache): Promise<void> {
        this.cache = cache;
        await this.context.globalState.update('supreme.licenseCache', cache);
    }

    async activate(key: string): Promise<boolean> {
        try {
            const apiUrl = this.getValidationUrl();
            const machineId = this.getMachineId();
            const res = await fetchWithRetry(() =>
                axios.post(apiUrl, { key, machine_id: machineId }, { timeout: HTTP_TIMEOUT_MS })
            );

            if (res.data.valid) {
                await this.context.globalState.update(CONFIG.STORAGE.LICENSE_KEY, key);

                // Update cache
                const now = Date.now();
                await this.saveCache({
                    isValid: true,
                    expiresAt: res.data.expiresAt,
                    cachedAt: now,
                    lastOnlineCheck: now
                });

                // Notify listeners
                if (this.onLicenseChange) {
                    this.onLicenseChange(true);
                }

                vscode.window.showInformationMessage(`Supreme Security Activated! Expires: ${res.data.expiresAt}`);
                return true;
            } else {
                vscode.window.showErrorMessage(`Activation failed: ${res.data.error}`);
                return false;
            }
        } catch (error: any) {
            console.error('License activation error:', error);
            const msg = error.response?.data?.error || error.message || "Unknown error";
            vscode.window.showErrorMessage(`Activation server unreachable: ${msg}. Check supreme.serverUrl setting.`);
            return false;
        }
    }

    async isValid(): Promise<boolean> {
        const key = this.context.globalState.get<string>(CONFIG.STORAGE.LICENSE_KEY);
        if (!key) return false;

        const now = Date.now();

        // Check if cache is still valid
        if (this.cache && this.cache.isValid) {
            const cacheAge = now - this.cache.cachedAt;

            // If cache is fresh, use it
            if (cacheAge < LICENSE_CACHE_TTL_MS) {
                return true;
            }
        }

        // Try to verify with backend
        try {
            const apiUrl = this.getValidationUrl();
            const machineId = this.getMachineId();
            const res = await fetchWithRetry(() =>
                axios.post(apiUrl, { key, machine_id: machineId }, { timeout: HTTP_TIMEOUT_MS })
            );

            const isValid = res.data.valid === true;

            await this.saveCache({
                isValid,
                expiresAt: res.data.expiresAt || null,
                cachedAt: now,
                lastOnlineCheck: now
            });

            return isValid;
        } catch (error) {
            // Network error - check offline grace period
            console.warn('License check failed due to network:', error);

            if (this.cache && this.cache.isValid) {
                const offlineTime = now - this.cache.lastOnlineCheck;

                // Allow offline usage for 24 hours after last successful check
                if (offlineTime < OFFLINE_GRACE_PERIOD_MS) {
                    console.log('Using cached license (offline mode)');
                    return true;
                }
            }

            return false;
        }
    }

    getStoredKey(): string | undefined {
        return this.context.globalState.get<string>(CONFIG.STORAGE.LICENSE_KEY);
    }

    getCachedExpiry(): string | null {
        return this.cache?.expiresAt || null;
    }
}

