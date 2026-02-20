# s2l Quick Start Guide

Get up and running with s2l security scanning in under 5 minutes.

## Installation

```bash
pip install s2l-security
```

## Your First Scan

```bash
cd your-project
s2l scan .
```

That's it! s2l will:
1. Detect all file types in your project
2. Run appropriate security scanners
3. Generate HTML and JSON reports
4. Show a summary in your terminal

## Understanding Results

### Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| CRITICAL | Immediate security threat | Fix now |
| HIGH | Significant vulnerability | Fix before commit |
| MEDIUM | Moderate issue | Should fix |
| LOW | Minor concern | Consider fixing |
| INFO | Best practice suggestion | Optional |

### Example Output

```
============================================================
🎯 PARALLEL SCAN COMPLETE
============================================================
📂 Files scanned: 156
🔍 Issues found: 12
⏱️  Total time: 8.32s
============================================================

Severity breakdown:
  CRITICAL: 1
  HIGH: 3
  MEDIUM: 6
  LOW: 2
```

## Quick Scan (Faster)

Use cached results for incremental scanning:

```bash
s2l scan . --quick
```

## View Reports

Reports are saved to `.s2l/reports/`:

```bash
# Open HTML report in browser
open .s2l/reports/s2l-scan-*.html

# View JSON for CI/CD
cat .s2l/reports/s2l-scan-*.json
```

## Install Missing Tools

s2l uses 43+ external tools. Check what's installed:

```bash
s2l install --check
```

Install everything:

```bash
s2l install --all
```

## IDE Integration

Set up your AI IDE (Claude Code, Gemini, Copilot, Cursor):

```bash
s2l init
```

This creates context files that teach your AI assistant:
- How to run security scans
- How to identify false positives
- How to fix real vulnerabilities

## Configuration

Create `.s2l.yml` in your project root:

```yaml
---
version: 2025.3.0.4
fail_on: high
exclude:
  paths:
    - node_modules/
    - .venv/
    - dist/
    - vendor/
  files:
    - "*.min.js"
```

## Handling False Positives

If you see many subprocess warnings (B404/B603), create `.bandit`:

```yaml
skips:
  - B404  # import subprocess
  - B603  # subprocess without shell
  - B101  # assert in tests
```

See [Handling False Positives](./handling-false-positives.md) for detailed guidance.

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    pip install s2l-security
    s2l scan . --fail-on high --no-report
```

### GitLab CI

```yaml
security:
  script:
    - pip install s2l-security
    - s2l scan . --fail-on high
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: s2l
        name: s2l Security Scan
        entry: s2l scan . --quick --fail-on critical
        language: system
        pass_filenames: false
```

## Common Commands

| Command | Description |
|---------|-------------|
| `s2l scan .` | Full project scan |
| `s2l scan . --quick` | Quick scan (cached) |
| `s2l scan src/` | Scan specific directory |
| `s2l scan . --fail-on high` | Fail if HIGH+ issues found |
| `s2l scan . --workers 8` | Use 8 parallel workers |
| `s2l install --check` | Check installed tools |
| `s2l install --all` | Install all tools |
| `s2l init` | Setup IDE integration |
| `s2l --version` | Show version |

## What Gets Scanned

s2l supports 43+ languages and formats:

- **Languages:** Python, JavaScript, TypeScript, Go, Rust, Java, C/C++, Ruby, PHP
- **Shell:** Bash, sh, zsh, PowerShell
- **Config:** YAML, JSON, TOML, XML, INI
- **Infrastructure:** Docker, Kubernetes, Terraform, Ansible, CloudFormation
- **Secrets:** .env files, API keys, credentials

## Next Steps

1. **Run your first scan:** `s2l scan .`
2. **Fix critical issues:** Address CRITICAL and HIGH findings
3. **Setup IDE:** `s2l init` for AI-powered scanning
4. **Handle FPs:** Create `.bandit` config if needed
5. **Add to CI/CD:** Automate scans in your pipeline

## Getting Help

- **Documentation:** [docs.silenceai.net](https://docs.silenceai.net)
- **Issues:** [GitHub Issues](https://github.com/pantheon-security/s2l/issues)
- **Guides:** See other guides in this directory

## Further Reading

- [Handling False Positives](./handling-false-positives.md)
- [IDE Integration](./ide-integration.md)
- [Configuration Reference](../configuration.md)
