# 📦 Supreme 2 Light Installation Guide

## Quick Install

### Prerequisites

- **Python**: 3.10 or higher
- **pip**: Python package manager
- **Internet connection**: For downloading tools

### One-Line Install

```bash
pip install s2l-security && s2l init && s2l install --all
```

This installs Supreme 2 Light, initializes your project, and installs all security tools.

---

## Post-Installation

### Verify Installation

```bash
# Check Supreme 2 Light version
s2l --version

# Check installed tools
s2l install --check

# Run a test scan
mkdir test-project
cd test-project
echo "print('Hello World')" > test.py
s2l scan .
```

### Initialize Your Project

```bash
cd your-project
s2l init
```

This creates:
- `.s2l.yml` - Configuration file
- `.claude/agents/s2l/agent.json` - IDE integration (if using Claude Code)

### First Scan

```bash
s2l scan .
```

---

## Auto-Approve Installation Flags

For MCP server operation and autonomous scanning, install commands must run non-interactively.

### Windows (winget)

```bash
winget install -e --id koalaman.shellcheck --accept-source-agreements --accept-package-agreements --silent
```

### Linux (apt)

```bash
sudo apt-get install -y --quiet shellcheck
```

### Linux (dnf)

```bash
sudo dnf install -y --quiet shellcheck
```

### macOS (Homebrew)

```bash
brew install shellcheck --force --quiet
```

### Cross-platform (pip)

```bash
pip install --quiet --no-input bandit
```

### Configuration

Add to `.supreme2l.yml`:

```yaml
scanner_installation:
  auto_approve: true
  quiet_mode: true
  retry_on_failure: 3
```

Default behavior already uses these values when the block is not set.

---

**Installation Support**: [GitHub Issues](https://github.com/Pantheon-Security/s2l/issues)
