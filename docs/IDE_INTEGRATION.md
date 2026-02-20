# 🤖 s2l IDE Integration Guide

Complete guide for integrating s2l with your IDE or code editor.

---

## Supported IDEs

| IDE | Status | Features |
|-----|--------|----------|
| Claude Code | ✅ Full Support | Auto-scan, slash commands, inline annotations |
| Cursor | 🚧 Basic Support | Configuration ready, full support coming in v0.8.0 |
| VS Code | 🚧 Basic Support | Configuration ready, extension coming in v0.8.0 |
| Gemini CLI | 🚧 Basic Support | Configuration ready, full support coming in v0.8.0 |

---

## Claude Code Integration

### Overview

s2l provides first-class integration with Claude Code, Anthropic's AI-powered code editor.

### Features

- 🔄 **Auto-scan on save** - Automatically scans files when you save them
- ⚡ **Slash command** - Run full scans with `/s2l-scan`
- 📝 **Inline annotations** - See security issues directly in your code
- ⚙️ **Configurable triggers** - Customize when scans run
- 🎯 **Severity filtering** - Show only issues above a certain threshold

---

## Setup

### Quick Setup

```bash
cd your-project
s2l init --ide claude-code
```

This automatically creates:
- `.claude/agents/s2l/agent.json` - Agent configuration
- `.claude/commands/s2l-scan.md` - Command documentation

### Manual Setup

If you need to manually configure or customize:

#### 1. Create Agent Configuration

Create `.claude/agents/s2l/agent.json`:

```json
{
  "name": "s2l Security Scanner",
  "description": "Security scanning agent for code quality and vulnerability detection",
  "version": "0.9.1.1",
  "triggers": {
    "file_save": {
      "enabled": true,
      "patterns": [
        "*.py",
        "*.js",
        "*.jsx",
        "*.ts",
        "*.tsx",
        "*.sh",
        "*.bash",
        "*.yml",
        "*.yaml",
        "*.go",
        "*.rb",
        "*.php",
        "*.rs",
        "*.java"
      ],
      "description": "Automatically scan files when saved"
    },
    "on_demand": {
      "enabled": true,
      "commands": ["/s2l-scan"],
      "description": "Run security scan on demand"
    }
  },
  "actions": {
    "scan_on_save": {
      "description": "Run s2l security scan when files are saved",
      "command": "s2l scan --quick {file_path}",
      "show_output": true,
      "notification": {
        "on_success": "✅ s2l: No issues found",
        "on_failure": "⚠️ s2l: Issues detected",
        "on_error": "❌ s2l: Scan failed"
      }
    },
    "full_scan": {
      "description": "Run full security scan on project",
      "command": "s2l scan .",
      "show_output": true,
      "notification": {
        "on_success": "✅ s2l: Project scan complete",
        "on_failure": "⚠️ s2l: Security issues found",
        "on_error": "❌ s2l: Scan failed"
      }
    }
  },
  "settings": {
    "inline_annotations": true,
    "severity_threshold": "medium",
    "auto_fix": false
  }
}
```

#### 2. Create Slash Command

Create `.claude/commands/s2l-scan.md`:

```markdown
# s2l Security Scan

Run comprehensive security scan on your project using s2l.

## Usage

\`\`\`
/s2l-scan
\`\`\`

## What it does

- Scans all files in project for security vulnerabilities
- Checks code quality across 42 different languages
- Reports issues with severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Generates detailed reports in \`.s2l/reports/\`

## Options

Configure scan behavior in \`.s2l.yml\`:

\`\`\`yaml
fail_on: high        # Fail on HIGH or CRITICAL issues
workers: 6           # Number of parallel workers
cache_enabled: true  # Use caching for speed
\`\`\`

## Examples

\`\`\`bash
# Quick scan (changed files only)
s2l scan . --quick

# Full scan (all files)
s2l scan .

# Scan specific directory
s2l scan ./src

# Fail on HIGH or above
s2l scan . --fail-on high
\`\`\`

## See also

- [s2l Documentation](../../../README.md)
- [Configuration Guide](../../../docs/CONFIGURATION.md)
- [Scanner Reference](../../../docs/SCANNERS.md)
\`\`\`

---

## Configuration

### Enable/Disable Auto-Scan

Edit `.s2l.yml`:

```yaml
ide:
  claude_code:
    enabled: true
    auto_scan: true          # Set to false to disable auto-scan
    inline_annotations: true # Show issues inline in code
```

### Customize File Patterns

Edit `.claude/agents/s2l/agent.json`:

```json
{
  "triggers": {
    "file_save": {
      "enabled": true,
      "patterns": [
        "*.py",      # Python files
        "*.js",      # JavaScript files
        "*.ts",      # TypeScript files
        "*.sh"       # Shell scripts
        // Add more patterns as needed
      ]
    }
  }
}
```

### Severity Threshold

Only show issues above a certain severity:

```json
{
  "settings": {
    "severity_threshold": "high"  // critical | high | medium | low
  }
}
```

---

## Usage

### Auto-Scan on Save

1. Edit any supported file (`.py`, `.js`, `.sh`, etc.)
2. Make changes
3. Save the file (`Ctrl+S` / `Cmd+S`)
4. s2l automatically scans the file
5. Issues appear in:
   - Claude Code output panel
   - Inline annotations (if enabled)
   - Terminal output

**Example:**

```python
# File: app.py
password = "admin123"  # Hard-coded password
```

**On Save:**
```
🐍 s2l v0.9.1.1 - Security Guardian

Scanning app.py...

⚠️ Issues found:
  [HIGH] Hard-coded password detected (line 2)
    password = "admin123"

✅ Scan complete: 1 issue found
```

### Manual Scan with Slash Command

In Claude Code chat:

```
/s2l-scan
```

**Output:**
```
🐍 s2l Full Project Scan

📁 Found 145 scannable files

📊 Scanning 145 files with 6 workers...
✅ Scanned 145 files

============================================================
🎯 SCAN COMPLETE
============================================================
📂 Files scanned: 145
🔍 Issues found: 23
  CRITICAL: 0
  HIGH: 2
  MEDIUM: 18
  LOW: 3
⏱️  Total time: 47.28s
============================================================

📁 Reports saved to: .s2l/reports/
```

### Quick Scan vs Full Scan

**Quick Scan** (auto-scan on save):
- Scans only the saved file
- Uses `--quick` mode
- Very fast (< 1 second)
- Uses cache

**Full Scan** (slash command):
- Scans entire project
- Uses parallel workers
- Takes 30s - 5min depending on project size
- Comprehensive results

---

## Inline Annotations

### Viewing Issues Inline

When `inline_annotations: true` in `.s2l.yml`, issues appear directly in your code:

```python
password = "admin123"  # ⚠️ s2l: Hard-coded password (HIGH)
                       # B105: hardcoded_password_string
```

### Annotation Format

```
# ⚠️ s2l: <issue_text> (<severity>)
# <issue_code>: <details>
```

### Disabling Inline Annotations

```yaml
# .s2l.yml
ide:
  claude_code:
    inline_annotations: false  # Disable inline annotations
```

---

## Advanced Configuration

### Custom Scan Command

Modify the scan command in `.claude/agents/s2l/agent.json`:

```json
{
  "actions": {
    "scan_on_save": {
      "command": "s2l scan --quick --fail-on high {file_path}",
      // Additional flags:
      // --workers N      - Use N workers
      // --fail-on LEVEL  - Exit code on severity
      // --no-cache       - Disable cache
      // --force          - Force full scan
    }
  }
}
```

### Notifications

Customize notifications:

```json
{
  "actions": {
    "scan_on_save": {
      "notification": {
        "on_success": "✅ Clean code!",
        "on_failure": "⚠️ Found {issue_count} issues",
        "on_error": "❌ Scan error"
      }
    }
  }
}
```

### Multiple Scan Actions

Add different scan modes:

```json
{
  "actions": {
    "quick_scan": {
      "description": "Quick scan (changed files)",
      "command": "s2l scan . --quick"
    },
    "full_scan": {
      "description": "Full project scan",
      "command": "s2l scan ."
    },
    "critical_only": {
      "description": "Show only CRITICAL issues",
      "command": "s2l scan . --fail-on critical"
    }
  }
}
```

Then use:
- `/s2l-quick` - Quick scan
- `/s2l-scan` - Full scan
- `/s2l-critical` - Critical issues only

---

## Troubleshooting

### Auto-Scan Not Working

**Check 1: Agent Enabled**
```yaml
# .s2l.yml
ide:
  claude_code:
    enabled: true  # Must be true
    auto_scan: true # Must be true
```

**Check 2: File Pattern Match**

File extension must be in the patterns list:

```json
// .claude/agents/s2l/agent.json
{
  "triggers": {
    "file_save": {
      "patterns": [
        "*.py",  // Your file must match one of these
        "*.js",
        // ...
      ]
    }
  }
}
```

**Check 3: s2l Installed**

```bash
s2l --version
# Should output: s2l v0.9.1.1
```

### Slash Command Not Found

**Solution**: Restart Claude Code after creating `.claude/commands/s2l-scan.md`

### Scan Too Slow

**Solution 1**: Reduce workers
```yaml
# .s2l.yml
workers: 2  # Use fewer workers
```

**Solution 2**: Enable quick mode by default
```json
// .claude/agents/s2l/agent.json
{
  "actions": {
    "scan_on_save": {
      "command": "s2l scan --quick {file_path}"
    }
  }
}
```

**Solution 3**: Exclude large directories
```yaml
# .s2l.yml
exclude:
  paths:
    - node_modules/
    - vendor/
    - dist/
    - build/
```

### Too Many Notifications

**Solution**: Disable notifications for success cases:

```json
{
  "actions": {
    "scan_on_save": {
      "notification": {
        "on_success": null,  // Disable success notifications
        "on_failure": "⚠️ Issues found"
      }
    }
  }
}
```

---

## Other IDEs

### Cursor

**Status**: Basic support (configuration created)
**Full Support**: Coming in v0.8.0

```bash
s2l init --ide cursor
```

Creates placeholder configuration in `.cursor/`.

### VS Code

**Status**: Basic support (configuration created)
**Extension**: Coming in v0.8.0

```bash
s2l init --ide vscode
```

Creates placeholder `tasks.json` and settings.

**Manual VS Code Integration**:

Create `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "s2l Scan",
      "type": "shell",
      "command": "s2l scan .",
      "group": {
        "kind": "test",
        "isDefault": true
      },
      "presentation": {
        "reveal": "always",
        "panel": "new"
      },
      "problemMatcher": []
    }
  ]
}
```

Run with: `Ctrl+Shift+B` (Windows/Linux) or `Cmd+Shift+B` (macOS)

### Gemini CLI

**Status**: Basic support (configuration created)
**Full Support**: Coming in v0.8.0

```bash
s2l init --ide gemini
```

---

## Best Practices

### 1. Start with Auto-Scan Disabled

When first integrating, disable auto-scan to avoid interruptions:

```yaml
ide:
  claude_code:
    auto_scan: false  # Enable later when comfortable
```

Use slash commands manually until familiar with the tool.

### 2. Set Appropriate Severity Threshold

Don't overwhelm yourself with LOW/INFO issues:

```json
{
  "settings": {
    "severity_threshold": "medium"  // Only show MEDIUM+
  }
}
```

### 3. Exclude Test Files

Test files often have intentional "bad" code:

```yaml
exclude:
  files:
    - "*.test.js"
    - "*.spec.ts"
    - "test_*.py"
```

### 4. Use Quick Mode for Auto-Scan

Fast feedback on saves:

```json
{
  "actions": {
    "scan_on_save": {
      "command": "s2l scan --quick {file_path}"
    }
  }
}
```

### 5. Schedule Full Scans

Run full scans periodically (daily/weekly) instead of on every save:

```bash
# Cron job (Linux/macOS)
0 9 * * * cd /path/to/project && s2l scan . -o /tmp/s2l-daily

# Windows Task Scheduler
# Schedule s2l scan . --output C:\reports\s2l
```

---

## Examples

### Example 1: Python Project

`.s2l.yml`:
```yaml
version: 0.9.1

scanners:
  enabled: [bandit]  # Only Python scanner

ide:
  claude_code:
    enabled: true
    auto_scan: true
    inline_annotations: true

fail_on: high
workers: 4
```

Agent action:
```json
{
  "scan_on_save": {
    "command": "s2l scan --quick --fail-on high {file_path}"
  }
}
```

### Example 2: Full-Stack Project

`.s2l.yml`:
```yaml
version: 0.9.1

scanners:
  enabled: [bandit, eslint, shellcheck]

ide:
  claude_code:
    enabled: true
    auto_scan: true

exclude:
  paths:
    - node_modules/
    - venv/
    - dist/
    - build/
```

Agent with multiple actions:
```json
{
  "actions": {
    "quick_scan": {
      "command": "s2l scan --quick {file_path}"
    },
    "backend_scan": {
      "command": "s2l scan ./backend"
    },
    "frontend_scan": {
      "command": "s2l scan ./frontend"
    }
  }
}
```

---

## Roadmap

### v0.8.0 (Q1 2026)
- ✅ Complete VS Code extension
- ✅ Full Cursor integration
- ✅ Gemini CLI full support
- ✅ Auto-fix capabilities
- ✅ Issue suppression UI

### v1.0.0 (Q2 2026)
- ✅ JetBrains IDE support (IntelliJ, PyCharm, WebStorm)
- ✅ Sublime Text plugin
- ✅ Vim/Neovim plugin
- ✅ Emacs package

---

**Last Updated**: 2025-11-15
**s2l Version**: 0.9.1.1
**Claude Code Support**: Full (v0.9.1.1)
