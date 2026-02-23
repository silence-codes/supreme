# Supreme 2 Light - Security Scanning

## CRITICAL: Git Commit Rules

**ALWAYS ask for permission before making git commits.**

Before running `git commit`, `git push`, or any version bump:
1. Show the user what changes will be committed
2. Explain why the commit is needed
3. Wait for explicit approval ("yes", "go ahead", etc.)
4. Only then proceed with the commit

This applies even for bug fixes - the user must approve all commits.

## Project Overview

This project uses **Supreme 2 Light** - Multi-Language Security Scanner with 40+ specialized analyzers for automated security scanning.

## Supreme 2 Light Configuration

**Location**: `.s2l.yml`

### Quick Commands

```bash
# Run security scan
s2l scan .

# Quick scan (cached results)
s2l scan . --quick

# Check installed scanners
s2l install --check

# Install missing tools
s2l install --all
```

## Available Slash Commands

- `/s2l-scan` - Run security scan on project
- `/s2l-install` - Install missing security tools

## Integration Features

### Claude Code Integration

- **Auto-scan on save**: Automatically scans files when you save them
- **Inline annotations**: Security issues appear directly in your IDE
- **Smart detection**: Only scans relevant file types
- **Parallel processing**: Fast scanning with multi-core support

### 42 Language Support

Supreme 2 Light scans:
- Python, JavaScript, TypeScript, Go, Rust, Java, C/C++
- Shell scripts (bash, sh, zsh)
- Docker, Kubernetes, Terraform
- YAML, JSON, XML, TOML
- And 30+ more languages/formats

## Security Scanning

### Scan Reports

Reports are generated in `.s2l/reports/`:
- HTML dashboard (visual report)
- JSON data (for CI/CD integration)
- CLI output (terminal summary)

### Severity Levels

- **CRITICAL**: Immediate security threats
- **HIGH**: Significant vulnerabilities
- **MEDIUM**: Moderate issues
- **LOW**: Minor concerns
- **INFO**: Best practice suggestions

### Fail Thresholds

Configure scan to fail CI/CD on certain severity:

```bash
s2l scan . --fail-on high
```

## Configuration

Edit `.s2l.yml` to customize:

```yaml
version: 0.8.0
scanners:
  enabled: []     # Empty = all enabled
  disabled: []    # List scanners to disable
fail_on: high     # critical | high | medium | low
exclude:
  paths:
    - node_modules/
    - .venv/
    - dist/
workers: null     # null = auto-detect CPU cores
cache_enabled: true
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Supreme 2 Light Security Scan
  run: |
    pip install s2l-security
    s2l scan . --fail-on high --no-report
```

### GitLab CI

```yaml
security_scan:
  script:
    - pip install s2l-security
    - s2l scan . --fail-on high
```

## Troubleshooting

### Missing Scanners

If you see warnings about missing tools:

```bash
s2l install --check    # See what's missing
s2l install --all      # Install everything
```

### False Positives

Exclude files or directories in `.s2l.yml`:

```yaml
exclude:
  paths:
    - "tests/fixtures/"
    - "vendor/"
  files:
    - "*.min.js"
```

## Learn More

- **Documentation**: https://silenceai.net/docs
- **GitHub**: https://github.com/Pantheon-Security/s2l
- **Report Issues**: https://github.com/Pantheon-Security/s2l/issues

---

*This file provides context for Claude Code about Supreme 2 Light integration*
