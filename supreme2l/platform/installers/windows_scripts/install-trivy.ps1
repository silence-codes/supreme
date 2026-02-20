# PowerShell installer for trivy
# Downloads and installs trivy from GitHub releases

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\trivy",
    [switch]$Debug
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    if ($Debug -or $Level -eq "ERROR") {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$timestamp] [$Level] $Message"
    }
}

try {
    Write-Log "Starting trivy installation..." "INFO"

    # Get pinned release info from tool-versions.lock
    $version = "0.68.1"
    $tag = "v$version"
    Write-Log "Fetching release information for version $version..."

    $release = $null
    $headers = @{ "User-Agent" = "supreme2l-Installer" }

    try {
        $releaseUrl = "https://api.github.com/repos/aquasecurity/trivy/releases/tags/$tag"
        $release = Invoke-RestMethod -Uri $releaseUrl -Headers $headers
    } catch {
        # Fallback to non-prefixed tag if needed
        $releaseUrl = "https://api.github.com/repos/aquasecurity/trivy/releases/tags/$version"
        $release = Invoke-RestMethod -Uri $releaseUrl -Headers $headers
    }

    if (-not $release) {
        throw "Could not fetch release information for trivy $version"
    }

    Write-Log "Installing version: $version"

    # Find Windows 64-bit ZIP asset
    $asset = $release.assets | Where-Object { $_.name -match "(?i)trivy.*windows.*64bit.*\.zip" } | Select-Object -First 1

    if (-not $asset) {
        throw "Could not find Windows 64-bit ZIP in release assets"
    }

    Write-Log "Found asset: $($asset.name)"
    $downloadUrl = $asset.browser_download_url

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        Write-Log "Creating install directory: $InstallDir"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download ZIP file
    $zipPath = "$env:TEMP\trivy-$version.zip"
    Write-Log "Downloading from: $downloadUrl"
    Write-Host "Downloading trivy $version..." -ForegroundColor Cyan

    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
    Write-Log "Download complete: $zipPath"

    # Extract ZIP
    Write-Log "Extracting to: $InstallDir"
    Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
    Write-Log "Extraction complete"

    # Clean up ZIP
    Remove-Item $zipPath -Force
    Write-Log "Cleaned up temporary ZIP file"

    # Find the trivy executable
    $exePath = Get-ChildItem -Path $InstallDir -Filter "trivy*.exe" -Recurse | Select-Object -First 1 | ForEach-Object { $_.FullName }

    if (-not $exePath) {
        throw "Could not find trivy executable after extraction"
    }

    Write-Log "Found executable: $exePath"

    # Add install dir to user PATH if missing
    $installDirPath = Split-Path $exePath
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    $pathDirs = $userPath -split ';'
    if ($pathDirs -notcontains $installDirPath) {
        $newUserPath = ($pathDirs + $installDirPath) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        Write-Host "`nAdded to user PATH: $installDirPath" -ForegroundColor Green
    }

    # Verify installation
    if (Test-Path $exePath) {
        Write-Host "`nSUCCESS: trivy installed successfully!" -ForegroundColor Green
        Write-Host "   Location: $exePath" -ForegroundColor Gray

        # Test execution
        try {
            Write-Host "`n   Testing installation..." -ForegroundColor Cyan
            $versionOutput = & $exePath --version 2>&1 | Select-Object -First 1
            Write-Host "   Version: $versionOutput" -ForegroundColor Green
        } catch {
            Write-Log "Version check failed" "INFO"
        }

        exit 0
    } else {
        throw "Installation verification failed: trivy.exe not found"
    }

} catch {
    Write-Log "Installation failed: $_" "ERROR"
    Write-Host "`nERROR: Installation failed: $_" -ForegroundColor Red
    Write-Host "`nPlease install manually from: https://github.com/aquasecurity/trivy/releases" -ForegroundColor Yellow
    exit 1
}
