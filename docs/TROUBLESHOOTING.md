# 🔧 Supreme 2 Light Troubleshooting Guide

Solutions to common problems and errors.

---

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Tool Installation Problems](#tool-installation-problems)
3. [Scanning Issues](#scanning-issues)
4. [Performance Problems](#performance-problems)
5. [Configuration Issues](#configuration-issues)
6. [IDE Integration Issues](#ide-integration-issues)
7. [Platform-Specific Issues](#platform-specific-issues)
8. [Error Messages](#error-messages)

---

## Installation Issues

### "Command not found: s2l"

**Symptoms:**
```bash
$ s2l --version
bash: s2l: command not found
```

**Solutions:**

**Linux/macOS:**
```bash
# Add pip install directory to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify
which s2l
s2l --version
```

**Windows:**
```powershell
# Check if Python Scripts directory is in PATH
echo %PATH%

# Add to PATH (replace XX with your Python version)
setx PATH "%PATH%;C:\Users\YourName\AppData\Local\Programs\Python\Python3XX\Scripts"

# Restart terminal and verify
s2l --version
```

---

### "No module named 's2l'"

**Symptoms:**
```python
ModuleNotFoundError: No module named 's2l'
```

**Solutions:**

```bash
# Check if installed
pip show s2l-security

# If not installed
pip install s2l-security

# If using virtual environment
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate      # Windows
pip install s2l-security
```

---

### "Permission denied" during installation

**Symptoms:**
```bash
ERROR: Could not install packages due to an EnvironmentError: [Errno 13] Permission denied
```

**Solutions:**

**Linux/macOS (Recommended):**
```bash
# Install for current user only (no sudo needed)
pip install --user s2l-security
```

**Alternative (Not Recommended):**
```bash
# System-wide install (requires sudo)
sudo pip install s2l-security
```

**Windows:**
```powershell
# Run PowerShell as Administrator
pip install s2l-security
```

---

## Tool Installation Problems

### "Tool not found: bandit"

**Symptoms:**
```
⚠️  bandit not found
Install with: pip install bandit
```

**Solutions:**

```bash
# Install specific tool
s2l install --tool bandit

# Or manually
pip install bandit

# Verify
which bandit  # Linux/macOS
where bandit  # Windows
bandit --version
```

---

### Auto-install fails

**Symptoms:**
```
❌ Failed to install eslint
Error: npm: command not found
```

**Solutions:**

**Missing npm:**
```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs

# macOS
brew install node

# Windows
# Download from nodejs.org
```

**Missing gem (Ruby):**
```bash
# Ubuntu/Debian
sudo apt install ruby-full

# macOS
brew install ruby

# Windows
# Download from rubyinstaller.org
```

**Missing composer (PHP):**
```bash
# Download and install
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer
```

---

### Tools install but aren't found

**Symptoms:**
```bash
s2l install --all --yes
# ✅ All tools installed

s2l scan .
# ⚠️  bandit not found
```

**Solutions:**

```bash
# Check PATH
echo $PATH

# Find where tool was installed
pip show bandit | grep Location
which bandit

# Add to PATH
export PATH="$HOME/.local/bin:$PATH"  # Linux/macOS

# Make permanent
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

---

## Scanning Issues

### Scan hangs or freezes

**Symptoms:**
- Scan starts but never completes
- Process uses 100% CPU
- No progress for > 5 minutes

**Solutions:**

**Reduce workers:**
```bash
# Use fewer workers
s2l scan . --workers 2

# Or set in config
# .s2l.yml
workers: 2
```

**Check system load:**
```bash
# Linux/macOS
top
htop
uptime

# Look for high load average or memory usage
```

**Kill hung scan:**
```bash
# Find process
ps aux | grep s2l

# Kill it
kill -9 <PID>

# Or
pkill -9 s2l
```

**Check for problematic files:**
```bash
# Scan in verbose mode
s2l scan . --verbose

# Look for file that scan hangs on
# Add it to exclusions in .s2l.yml
```

---

### "No files to scan"

**Symptoms:**
```
📁 Found 0 scannable files
✅ No files to scan
```

**Solutions:**

**Check file extensions:**
```bash
# See what files exist
find . -type f | head -20

# Check if extensions are supported
s2l install --check
```

**Check exclusions:**
```yaml
# .s2l.yml - might be excluding too much
exclude:
  paths:
    # - src/  # Don't exclude your code!
    - node_modules/
    - venv/
```

**Scan specific directory:**
```bash
s2l scan ./src
s2l scan ./backend
```

---

### Too many false positives

**Symptoms:**
- Scan reports issues in test files
- Vendor/library code flagged
- Acceptable patterns marked as issues

**Solutions:**

**Exclude test files:**
```yaml
# .s2l.yml
exclude:
  files:
    - "*.test.js"
    - "*.spec.ts"
    - "test_*.py"
    - "*_test.go"
```

**Exclude vendor code:**
```yaml
exclude:
  paths:
    - vendor/
    - third_party/
    - node_modules/
    - .venv/
```

**Adjust severity threshold:**
```yaml
fail_on: critical  # Only fail on CRITICAL issues
```

**Suppress specific issues:**
```python
# Python (bandit)
password = "test123"  # nosec B105

# JavaScript (ESLint)
eval(code);  // eslint-disable-line no-eval
```

---

## Performance Problems

### Scan is very slow

**Symptoms:**
- Small project takes > 5 minutes
- Scan slower than expected

**Solutions:**

**Enable caching:**
```bash
# Quick scan (uses cache)
s2l scan . --quick

# Check cache status
ls -lah ~/.s2l/cache/
```

**Reduce workers:**
```bash
# Too many workers can be slower
s2l scan . --workers 4
```

**Exclude large directories:**
```yaml
# .s2l.yml
exclude:
  paths:
    - node_modules/     # Can have 100,000+ files
    - dist/
    - build/
    - .git/
```

**Use specific scanners:**
```yaml
# Only scan for critical issues
scanners:
  enabled: [bandit, eslint]  # Only these two
```

**Check disk I/O:**
```bash
# Slow disk can cause issues
df -h        # Check free space
iostat -x 1  # Check I/O wait
```

---

### High memory usage

**Symptoms:**
- System slows during scan
- Out of memory errors
- Swap usage increases

**Solutions:**

**Reduce workers:**
```bash
s2l scan . --workers 2
```

**Disable cache:**
```bash
s2l scan . --no-cache
```

**Scan in batches:**
```bash
# Scan subdirectories separately
s2l scan ./backend
s2l scan ./frontend
s2l scan ./scripts
```

---

### CPU usage too high

**Symptoms:**
- System becomes unresponsive
- Other applications lag
- Fans run loudly

**Solutions:**

**Supreme 2 Light auto-adjusts workers based on system load:**
```
⚠️  High CPU usage: 85.3%
Using 2 workers (reduced due to system load)
```

**Manual override:**
```bash
# Force fewer workers
s2l scan . --workers 1

# Set permanently
# .s2l.yml
workers: 2
```

**Run during idle time:**
```bash
# Schedule for off-hours (Linux/macOS)
crontab -e
# Add: 0 2 * * * cd /path/to/project && s2l scan .
```

---

## Configuration Issues

### Config file not loaded

**Symptoms:**
- Changes to `.s2l.yml` ignored
- Exclusions not working
- Scan uses default config

**Solutions:**

**Check file location:**
```bash
# Must be in project root
ls -la .s2l.yml

# Or in parent directories (Supreme 2 Light walks up)
```

**Check YAML syntax:**
```bash
# Validate YAML
python3 -c "import yaml; yaml.safe_load(open('.s2l.yml'))"

# Common issues:
# - Tabs instead of spaces
# - Missing colons
# - Incorrect indentation
```

**Verify config loaded:**
```bash
# Supreme 2 Light should show "Using config: .s2l.yml"
s2l scan . --verbose
```

---

### Exclusions not working

**Symptoms:**
- `node_modules/` still scanned
- Test files still checked
- Excluded paths showing in results

**Solutions:**

**Check exclusion syntax:**
```yaml
# CORRECT
exclude:
  paths:
    - node_modules/
    - .venv/

# WRONG
exclude:
  - node_modules/  # Missing "paths:" key
```

**Path must match:**
```yaml
# If your structure is:
# project/
#   frontend/node_modules/

# Use:
exclude:
  paths:
    - frontend/node_modules/  # Specific path
    # or
    - node_modules/            # Matches anywhere
```

**File patterns need wildcards:**
```yaml
exclude:
  files:
    - "*.min.js"    # CORRECT
    - "min.js"      # WRONG - won't match app.min.js
```

---

## IDE Integration Issues

### Claude Code auto-scan not working

**Symptoms:**
- Save file, no scan happens
- No Supreme 2 Light output in Claude

**Solutions:**

**Check config:**
```yaml
# .s2l.yml
ide:
  claude_code:
    enabled: true      # Must be true
    auto_scan: true    # Must be true
```

**Check file pattern:**
```json
// .claude/agents/s2l/agent.json
{
  "triggers": {
    "file_save": {
      "patterns": [
        "*.py",   // Your file extension must be listed
        "*.js",
        // ...
      ]
    }
  }
}
```

**Restart Claude Code:**
```bash
# Close and reopen Claude Code
# Agent configurations are loaded on startup
```

---

### Slash command not found

**Symptoms:**
```
/s2l-scan
Unknown command: s2l-scan
```

**Solutions:**

**Check command file exists:**
```bash
ls .claude/commands/s2l-scan.md
```

**Recreate command:**
```bash
s2l init --ide claude-code --force
```

**Restart Claude Code:**
- Close Claude Code
- Reopen project
- Try `/s2l-scan` again

---

## Platform-Specific Issues

### Windows: PowerShell Execution Policy blocks npm

**Symptoms:**
```powershell
npm install -g eslint
# Error: cannot be loaded because running scripts is disabled on this system
```

**Why this happens:**
- Fresh Windows 11 installations have execution policy set to `Restricted`
- This blocks `.ps1` scripts including `npm.ps1`
- **Common in enterprise environments** with default security policies

**Solutions:**

**Option 1: Use npm.cmd (RECOMMENDED)**
```powershell
# Use .cmd version instead of npm
npm.cmd install -g eslint
npm.cmd uninstall -g eslint
npm.cmd list -g
```
✅ **Supreme 2 Light automatically uses `npm.cmd` internally** - installations work fine!

**Option 2: Adjust execution policy (requires Admin)**
```powershell
# Check current policy
Get-ExecutionPolicy

# Set to RemoteSigned (allows local scripts)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Now npm works normally
npm install -g eslint
```

**Option 3: Use Supreme 2 Light (bypasses the issue)**
```powershell
# Supreme 2 Light handles this automatically
s2l install eslint  # Works even with Restricted policy
```

**For IT administrators:**
- Set execution policy via Group Policy: `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`
- Or deploy with: `Set-ExecutionPolicy RemoteSigned -Scope LocalMachine`

---

### Windows: "Access denied" errors

**Symptoms:**
```
PermissionError: [WinError 5] Access is denied
```

**Solutions:**

**Run as Administrator:**
- Right-click PowerShell
- "Run as Administrator"
- Run s2l commands

**Check antivirus:**
- Some antivirus software blocks Python scripts
- Add s2l to whitelist

**Use WSL2 instead:**
```powershell
# Install WSL2 (best Windows experience)
wsl --install
# Then use Supreme 2 Light in WSL Ubuntu
```

---

### macOS: "Permission denied" for system tools

**Symptoms:**
```
sudo: a terminal is required to read the password
```

**Solutions:**

**Use Homebrew:**
```bash
# Don't use sudo
brew install shellcheck yamllint

# For Python tools
pip3 install --user bandit
```

**Grant terminal permissions:**
- System Preferences → Security & Privacy → Privacy
- Full Disk Access → Add Terminal.app

---

### Linux: Tools not in PATH

**Symptoms:**
```bash
s2l install --all --yes
# ✅ Tools installed

which eslint
# (nothing)
```

**Solutions:**

```bash
# Add npm global bin to PATH
export PATH="$PATH:$(npm config get prefix)/bin"

# Add gem bin to PATH
export PATH="$PATH:$(gem environment gemdir)/bin"

# Make permanent
echo 'export PATH="$PATH:$(npm config get prefix)/bin"' >> ~/.bashrc
source ~/.bashrc
```

---

## Error Messages

### "ModuleNotFoundError: No module named 'click'"

**Solution:**
```bash
pip install click rich bandit yamllint
# Or reinstall s2l
pip install --force-reinstall s2l-security
```

---

### "SyntaxError: invalid syntax"

**Symptoms:**
```python
SyntaxError: invalid syntax
  File "s2l/cli.py", line 50
    match severity:
          ^
```

**Solution:**
```bash
# Supreme 2 Light requires Python 3.10+
python3 --version

# Upgrade Python
sudo apt install python3.11  # Ubuntu
brew install python@3.11     # macOS
```

---

### "subprocess.CalledProcessError"

**Symptoms:**
```
subprocess.CalledProcessError: Command '['bandit', ...]' returned non-zero exit status 1
```

**Solution:**

This is usually normal - it means the scanner found issues.

**If scan fails entirely:**
```bash
# Run scanner directly to see error
bandit -f json yourfile.py

# Check scanner installation
bandit --version
```

---

### "OSError: [Errno 24] Too many open files"

**Symptoms:**
```
OSError: [Errno 24] Too many open files
```

**Solutions:**

**Increase file limit (Linux/macOS):**
```bash
# Temporary
ulimit -n 4096

# Permanent (add to ~/.bashrc)
echo 'ulimit -n 4096' >> ~/.bashrc
```

**Reduce workers:**
```bash
s2l scan . --workers 2
```

---

## Getting Help

### Enable Verbose Mode

```bash
s2l scan . --verbose
```

Shows detailed information about what Supreme 2 Light is doing.

### Check System Status

```bash
# Check Supreme 2 Light version
s2l --version

# Check installed tools
s2l install --check

# Check Python version
python3 --version

# Check PATH
echo $PATH
```

### Collect Diagnostic Info

```bash
# Create diagnostic report
cat > s2l-diagnostics.txt <<EOF
Supreme 2 Light Version: $(s2l --version)
Python Version: $(python3 --version)
OS: $(uname -a)
PATH: $PATH

Installed Tools:
$(s2l install --check)

Config File:
$(cat .s2l.yml 2>/dev/null || echo "No config file")
EOF

# Share s2l-diagnostics.txt when reporting issues
```

### Report Issues

1. Check [existing issues](https://github.com/Pantheon-Security/s2l/issues)
2. Create new issue with:
   - Supreme 2 Light version
   - Python version
   - Operating system
   - Complete error message
   - Steps to reproduce
   - Diagnostic info (above)

---

## Common Workarounds

### Scan won't complete

```bash
# Use sequential mode (slower but more stable)
s2l scan . --workers 1 --no-cache
```

### Can't install all tools

```bash
# Install what you can
s2l install --all --yes

# Scan with available tools only
s2l scan .  # Works with whatever is installed
```

### Config changes not applying

```bash
# Force config reload
rm -rf ~/.s2l/cache/
s2l scan . --force
```

---

## Performance Tuning

### Optimize for Speed

```yaml
# .s2l.yml
workers: 8              # Use more cores
cache_enabled: true     # Enable caching

exclude:
  paths:
    - node_modules/    # Exclude large directories
    - vendor/
    - dist/
```

```bash
# Use quick mode
s2l scan . --quick
```

### Optimize for Accuracy

```yaml
scanners:
  enabled: []  # Scan with all available tools
  disabled: []

fail_on: critical  # Show all issues
```

```bash
# Force full scan
s2l scan . --force
```

---

**Last Updated**: 2025-11-15
**Supreme 2 Light Version**: 0.9.1.1

**Still having issues?** [Open a GitHub issue](https://github.com/Pantheon-Security/s2l/issues)
