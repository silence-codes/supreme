# Supreme Security Scanner

## Overview
Supreme is an advanced, all-in-one security scanner for Visual Studio Code. It detects vulnerabilities in dependencies, misconfigurations, and exposed secrets in your code.

## Features
- **Deep Scan**: Checks for CVEs, Misconfigurations, and Secrets.
- **CLI Tool**: Automated scanning for CI/CD pipelines (`supreme scan --ci`).
- **Offline Mode**: Fully functional offline scanning with cached database.
- **Interactive Dashboard**: View security score and critical stats.
- **Scan History**: Review past scan results and track improvements.
- **Glassmorphism Reports**: Beautiful, detailed HTML reports with code snippets.
- **Zero Configuration**: Auto-installs necessary engines.
- **Cancellable Operations**: Stop scans or downloads at any time.
- **Clean Uninstall**: All history is removed when you uninstall the extension.

## Usage

### VS Code Extension
1. Open the **Supreme** sidebar.
2. Click the large **Start Scan** button on the dashboard.
3. View results in the list below or open the full HTML report.
4. Export reports to JSON for your team.
5. Use the **Stop** button to cancel ongoing scans or downloads.
6. **Update Database**: Click the update button to refresh vulnerability data (requires license).

### CLI Tool (CI/CD)
The extension includes a CLI tool for automation.
1. Install CLI: `Ctrl+Shift+P` -> `Supreme: Install CLI Tool`
2. Run scan: `supreme scan --ci ./src`
3. CI/CD Example:
   ```bash
   # Exit with code 1 if critical issues found
   supreme scan --ci --fail-on critical ./src
   ```
4. Formats: `table` (default), `json`, `sarif`.

## Requirements
- Internet connection (initial setup only, to download engine and DB).
- Active license for database updates.

## License Activation
1. Purchase a license from the Supreme website.
2. Enter your license key in the sidebar activation field.
3. Your license is bound to your machine for security.

## Support
For issues and feature requests, please visit our GitHub repository.