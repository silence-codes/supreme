# 🚀 Supreme 2 Light Quick Start Guide

Get up and running with Supreme 2 Light in 5 minutes.

---

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Internet connection (for installing security tools)

---

## Step 1: Install Supreme 2 Light (1 minute)

```bash
pip install s2l-security
```

### Verify Installation

```bash
s2l --version
```

---

## Step 2: Initialize Your Project (1 minute)

Navigate to your project directory and run the initialization wizard:

```bash
cd /path/to/your/project
s2l init
```

### Files Created:

- `.s2l.yml` - Project configuration
- `.claude/agents/s2l/agent.json` - IDE agent (if using Claude Code)
- `.claude/commands/s2l-scan.md` - Slash command docs

---

## Step 3: Install Security Tools (2 minutes)

Supreme 2 Light needs external security tools to scan different languages. Install them automatically:

```bash
s2l install --all
```

---

## Step 4: Run Your First Scan (1 minute)

```bash
s2l scan .
```

---

## Quick Reference

### Essential Commands

```bash
# Initialize
s2l init

# Install tools
s2l install --all

# Scan project
s2l scan .

# Quick scan (cache)
s2l scan . --quick

# Check installed tools
s2l install --check

# Help
s2l --help
s2l scan --help
```

### Essential Files

```
.s2l.yml                      # Project configuration
.s2l/reports/                 # Scan reports
.claude/agents/s2l/           # IDE integration
```

---

**Congratulations! You're ready to scan for security issues with Supreme 2 Light!** 🎉

**One command. Complete security.**

```bash
s2l init && s2l install --all && s2l scan .
```

---

**Questions?** Open an issue on [GitHub](https://github.com/Pantheon-Security/s2l/issues)