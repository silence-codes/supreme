# Supreme 2 Light - Multi-Language Security Scanner

[![PyPI](https://img.shields.io/pypi/v/supreme2l?label=PyPI&color=blue)](https://pypi.org/project/supreme2l/)
[![Downloads](https://img.shields.io/pypi/dm/supreme2l?label=Downloads&color=brightgreen)](https://pypi.org/project/supreme2l/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Tests](https://github.com/Zeinullahh/Supreme-2-light/actions/workflows/test.yml/badge.svg)](https://github.com/Zeinullahh/Supreme-2-light/actions/workflows/test.yml)
[![Windows](https://img.shields.io/badge/Windows-✓-brightgreen.svg)](https://github.com/Zeinullahh/Supreme-2-light)
[![macOS](https://img.shields.io/badge/macOS-✓-brightgreen.svg)](https://github.com/Zeinullahh/Supreme-2-light)
[![Linux](https://img.shields.io/badge/Linux-✓-brightgreen.svg)](https://github.com/Zeinullahh/Supreme-2-light)

**AI-first security scanner** | 74 analyzers | Intelligent FP reduction | 180+ AI agent security rules | Sandbox compatible

---

## What is Supreme 2 Light?

Supreme 2 Light is a comprehensive Static Application Security Testing (SAST) tool with **74 specialized scanners** covering all major languages and platforms. It features intelligent false positive reduction and 180+ AI agent security rules for the agentic era.

### ✨ Key Features

- 🔍 **74 Specialized Scanners** - Most comprehensive coverage available with intelligent selection
- 🎯 **Intelligent FP Filter** - Reduces false positives by 40-60% using context-aware analysis
- 🚨 **CVE Detection** - React2Shell (CVE-2025-55182), Next.js vulnerabilities, supply chain risks
- 🤖 **AI Agent Security** - 180+ rules for MCP, RAG, prompt injection, tool poisoning & more
- 🏖️ **Sandbox Compatible** - Works in Codex, restricted environments, and CI/CD pipelines
- ⚡ **Parallel Processing** - Multi-core scanning (10-40× faster than sequential)
- 🎨 **Beautiful CLI** - Rich terminal output with progress bars
- 🧠 **IDE Integration** - Claude Code, Cursor, VS Code, Gemini CLI, OpenAI Codex support
- 📦 **Auto-Installer** - One-command installation of all security tools (Windows, macOS, Linux)
- 🔄 **Smart Caching** - Skip unchanged files for lightning-fast rescans
- ⚙️ **Configurable** - `.supreme2l.yml` for project-specific settings
- 🌍 **Cross-Platform** - Native Windows, macOS, and Linux support
- 📊 **Multiple Reports** - JSON, HTML, Markdown, SARIF exports for any workflow
- 🎯 **Zero Config** - Works out of the box with sensible defaults

---

## 🚀 Quick Start

### Installation

**Windows (Recommended - Virtual Environment):**
```powershell
# Create and activate virtual environment (security best practice)
py -m venv supreme2l-env
supreme2l-env\Scripts\activate

# Install Supreme 2 Light
pip install supreme2l

# Verify installation
s2l --version
```

**Windows (System-wide - Not Recommended):**
```powershell
# Install Supreme 2 Light system-wide (not recommended)
py -m pip install supreme2l --no-warn-script-location

# Verify installation
py -m supreme2l --version
```

> **Note for Windows users**: Virtual environments provide better isolation and avoid PATH warnings. If using system-wide install, use `py -m supreme2l` for all commands.

**macOS/Linux (Recommended - Virtual Environment):**
```bash
# Create and activate virtual environment (security best practice)
python3 -m venv supreme2l-env
source supreme2l-env/bin/activate

# Install Supreme 2 Light
pip install supreme2l

# Verify installation
s2l --version
```

**macOS/Linux (System-wide - Not Recommended):**
```bash
# Only use if you understand the implications
pip install supreme2l --user

# Verify installation
s2l --version
```

**Install from source (all platforms):**
```bash
git clone https://github.com/Zeinullahh/Supreme-2-light.git
cd Supreme-2-light

# Use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -e .
```

**Platform-Specific Notes:**

- **Windows**: Use `py -m supreme2l` instead of `s2l` if the command is not found
- **macOS**: If `s2l` command is not found, run `python3 -m supreme2l setup_path` or use `python3 -m supreme2l`
- **Linux**: Should work out of the box with `s2l` command

> **✅ Windows Support**: Supreme 2 Light now has full native Windows support with automatic tool installation via winget, chocolatey, and npm!

### 5-Minute Setup

**Windows:**
```powershell
# 1. Initialize in your project
cd your-project
py -m supreme2l init

# 2. Install security tools (auto-detected for your platform)
py -m supreme2l install --all

# 3. Run your first scan
py -m supreme2l scan .
```

**macOS/Linux:**
```bash
# 1. Initialize in your project
cd your-project
s2l init

# 2. Install security tools (auto-detected for your platform)
s2l install --all

# 3. Run your first scan
s2l scan .
```

### Example Output

```
Supreme 2 Light v2025.9.0 - Security Guardian

🎯 Target: .
🔧 Mode: Full

📁 Found 145 scannable files

📊 Scanning 145 files with 6 workers...
✅ Scanned 145 files

🎯 PARALLEL SCAN COMPLETE
📂 Files scanned: 145
⚡ Files cached: 0
🔍 Issues found: 114
⏱️  Total time: 47.28s
📈 Cache hit rate: 0.0%
🔧 Scanners used: bandit, eslint, shellcheck, yamllint

📊 Reports generated:
   JSON       → .supreme2l/reports/supreme2l-scan-20250119-083045.json
   HTML       → .supreme2l/reports/supreme2l-scan-20250119-083045.html
   Markdown   → .supreme2l/reports/supreme2l-scan-20250119-083045.md

✅ Scan complete!
```

### 📊 Report Formats

Supreme 2 Light generates beautiful reports in multiple formats:

**JSON** - Machine-readable for CI/CD integration
```bash
s2l scan . --format json
```

**HTML** - Stunning glassmorphism UI with interactive charts
```bash
s2l scan . --format html
```

**Markdown** - Documentation-friendly for GitHub/wikis
```bash
s2l scan . --format markdown
```

**All Formats** - Generate everything at once
```bash
s2l scan . --format all
```

---

## 📚 Language Support

Supreme 2 Light supports **42 different scanner types** covering all major programming languages and file formats:

### Backend Languages (9)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Python | Bandit | `.py` |
| JavaScript/TypeScript | ESLint | `.js`, `.jsx`, `.ts`, `.tsx` |
| Go | golangci-lint | `.go` |
| Ruby | RuboCop | `.rb`, `.rake`, `.gemspec` |
| PHP | PHPStan | `.php` |
| Rust | Clippy | `.rs` |
| Java | Checkstyle | `.java` |
| C/C++ | cppcheck | `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp` |
| C# | Roslynator | `.cs` |

### JVM Languages (3)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Kotlin | ktlint | `.kt`, `.kts` |
| Scala | Scalastyle | `.scala` |
| Groovy | CodeNarc | `.groovy`, `.gradle` |

### Functional Languages (5)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Haskell | HLint | `.hs`, `.lhs` |
| Elixir | Credo | `.ex`, `.exs` |
| Erlang | Elvis | `.erl`, `.hrl` |
| F# | FSharpLint | `.fs`, `.fsx` |
| Clojure | clj-kondo | `.clj`, `.cljs`, `.cljc` |

### Mobile Development (2)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Swift | SwiftLint | `.swift` |
| Objective-C | OCLint | `.m`, `.mm` |

### Frontend & Styling (3)
| Language | Scanner | Extensions |
|----------|---------|------------|
| CSS/SCSS/Sass/Less | Stylelint | `.css`, `.scss`, `.sass`, `.less` |
| HTML | HTMLHint | `.html`, `.htm` |
| Vue.js | ESLint | `.vue` |

### Infrastructure as Code (4)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Terraform | tflint | `.tf`, `.tfvars` |
| Ansible | ansible-lint | `.yml` (playbooks) |
| Kubernetes | kubeval | `.yml`, `.yaml` (manifests) |
| CloudFormation | cfn-lint | `.yml`, `.yaml`, `.json` (templates) |

### Configuration Files (5)
| Language | Scanner | Extensions |
|----------|---------|------------|
| YAML | yamllint | `.yml`, `.yaml` |
| JSON | built-in | `.json` |
| TOML | taplo | `.toml` |
| XML | xmllint | `.xml` |
| Protobuf | buf lint | `.proto` |

### Shell & Scripts (4)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Bash/Shell | ShellCheck | `.sh`, `.bash` |
| PowerShell | PSScriptAnalyzer | `.ps1`, `.psm1` |
| Lua | luacheck | `.lua` |
| Perl | perlcritic | `.pl`, `.pm` |

### Documentation (2)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Markdown | markdownlint | `.md` |
| reStructuredText | rst-lint | `.rst` |

### Other Languages (5)
| Language | Scanner | Extensions |
|----------|---------|------------|
| SQL | SQLFluff | `.sql` |
| R | lintr | `.r`, `.R` |
| Dart | dart analyze | `.dart` |
| Solidity | solhint | `.sol` |
| Docker | hadolint | `Dockerfile*` |

**Total: 42 scanner types covering 100+ file extensions**

---

## 🚨 React2Shell CVE Detection (NEW in v2025.8)

Supreme 2 Light now detects **CVE-2025-55182 "React2Shell"** - a CVSS 10.0 RCE vulnerability affecting React Server Components and Next.js.

```bash
# Check if your project is vulnerable
s2l scan .

# Vulnerable versions detected:
# - React 19.0.0 - 19.2.0 (Server Components)
# - Next.js 15.0.0 - 15.0.4 (App Router)
# - Various canary/rc releases
```

**Scans**: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`

**Fix**: Upgrade to React 19.0.1+ and Next.js 15.0.5+

---

## 🤖 AI Agent Security (v2025.7+)

Supreme 2 Light provides **industry-leading AI security scanning** with **22 specialized scanners** and **180+ detection rules** for the agentic AI era. Updated for **OWASP Top 10 for LLM Applications 2025** and includes detection for **CVE-2025-6514** (mcp-remote RCE).

**[Full AI Security Documentation](docs/AI_SECURITY.md)**

### AI Security Scanners

| Scanner | Rules | Detects |
|---------|-------|---------|
| **OWASPLLMScanner** | LLM01-10 | OWASP Top 10 2025: Prompt injection, system prompt leakage, unbounded consumption |
| **MCPServerScanner** | MCP101-118 | Tool poisoning, CVE-2025-6514, confused deputy, command injection |
| **MCPConfigScanner** | MCP001-013 | Secrets, dangerous paths, HTTP without TLS, untrusted sources |
| **AIContextScanner** | AIC001-030 | Prompt injection, memory manipulation, HITL bypass |
| **RAGSecurityScanner** | RAG001-010 | Vector injection, document poisoning, tenant isolation |
| **VectorDBScanner** | VD001-010 | Unencrypted storage, PII in embeddings, exposed endpoints |
| **LLMOpsScanner** | LO001-010 | Insecure model loading, checkpoint exposure, drift detection |
| + 9 more | 60+ rules | Multi-agent, planning, reflection, A2A, model attacks |

### AI Attack Coverage

<table>
<tr><td>

**Context & Input Attacks**
- Prompt injection patterns
- Role/persona manipulation
- Hidden instructions
- Obfuscation tricks

**Memory & State Attacks**
- Memory poisoning
- Context manipulation
- Checkpoint tampering
- Cross-session exposure

**Tool & Action Attacks**
- Tool poisoning (CVE-2025-6514)
- Command injection
- Tool name spoofing
- Confused deputy patterns

</td><td>

**Workflow & Routing Attacks**
- Router manipulation
- Agent impersonation
- Workflow hijacking
- Delegation abuse

**RAG & Knowledge Attacks**
- Knowledge base poisoning
- Embedding pipeline attacks
- Source confusion
- Retrieval manipulation

**Advanced Attacks**
- HITL bypass techniques
- Semantic manipulation
- Evaluation poisoning
- Training data attacks

</td></tr>
</table>

### Supported AI Files

```
.cursorrules          # Cursor AI instructions
CLAUDE.md             # Claude Code context
.claude/              # Claude configuration directory
copilot-instructions.md  # GitHub Copilot
AGENTS.md             # Multi-agent definitions
mcp.json / mcp-config.json  # MCP server configs
*.mcp.ts / *.mcp.py   # MCP server code
rag.json / knowledge.json   # RAG configurations
memory.json           # Agent memory configs
```

### Quick AI Security Scan

```bash
# Scan AI configuration files
s2l scan . --ai-only

# Example output:
# 🔍 AI Security Scan Results
# ├── .cursorrules: 3 issues (1 CRITICAL, 2 HIGH)
# │   └── AIC001: Prompt injection - ignore previous instructions (line 15)
# │   └── AIC011: Tool shadowing - override default tools (line 23)
# ├── mcp-config.json: 2 issues (2 HIGH)
# │   └── MCP003: Dangerous path - home directory access (line 8)
# └── rag_config.json: 1 issue (1 CRITICAL)
#     └── AIR010: Knowledge base injection pattern detected (line 45)
```

---

## 🎮 Usage

### Basic Commands

```bash
# Initialize configuration
s2l init

# Scan current directory
s2l scan .

# Scan specific directory
s2l scan /path/to/project

# Quick scan (changed files only)
s2l scan . --quick

# Force full scan (ignore cache)
s2l scan . --force

# Use specific number of workers
s2l scan . --workers 4

# Fail on HIGH severity or above
s2l scan . --fail-on high

# Custom output directory
s2l scan . -o /tmp/reports
```

### Install Commands

```bash
# Check which tools are installed
s2l install --check

# Install all missing tools (interactive)
s2l install --all

# Install specific tool
s2l install bandit

# Auto-yes to all prompts (non-interactive)
s2l install --all --yes

# Auto-yes to first prompt, then auto-yes all remaining
# When prompted: type 'a' for auto-yes-all
s2l install --all
Install all 39 missing tools? [Y/n/a]: a

# Show detailed installation output
s2l install --all --debug

# Use latest versions (bypass version pinning)
s2l install --all --use-latest
```

### Init Commands

```bash
# Interactive initialization wizard
s2l init

# Initialize with specific IDE
s2l init --ide claude-code

# Initialize with multiple IDEs
s2l init --ide claude-code --ide gemini-cli --ide cursor

# Initialize with all supported IDEs
s2l init --ide all

# Force overwrite existing config
s2l init --force

# Initialize and install tools
s2l init --install
```

### Additional Commands

```bash
# Uninstall specific tool
s2l uninstall bandit

# Uninstall all Supreme 2 Light tools
s2l uninstall --all --yes

# Check for updates
s2l version --check-updates

# Show current configuration
s2l config

# Override scanner for specific file
s2l override path/to/file.yaml YAMLScanner

# List available scanners
s2l override --list

# Show current overrides
s2l override --show

# Remove override
s2l override path/to/file.yaml --remove
```

### Scan Options Reference

| Option | Description |
|--------|-------------|
| `TARGET` | Directory or file to scan (default: `.`) |
| `-w, --workers N` | Number of parallel workers (default: auto-detect) |
| `--quick` | Quick scan (changed files only, requires git) |
| `--force` | Force full scan (ignore cache) |
| `--no-cache` | Disable result caching |
| `--fail-on LEVEL` | Exit with error on severity: `critical`, `high`, `medium`, `low` |
| `-o, --output PATH` | Custom output directory for reports |
| `--format FORMAT` | Output format: `json`, `html`, `sarif`, `junit`, `text` (can specify multiple) |
| `--no-report` | Skip generating HTML report |
| `--install-mode MODE` | Tool installation: `batch`, `progressive`, `never` |
| `--auto-install` | Automatically install missing tools without prompting |
| `--no-install` | Never attempt to install missing tools |

### Install Options Reference

| Option | Description |
|--------|-------------|
| `TOOL` | Specific tool to install (e.g., `bandit`, `eslint`) |
| `--check` | Check which tools are installed |
| `--all` | Install all missing tools |
| `-y, --yes` | Skip all confirmation prompts (auto-yes) |
| `--debug` | Show detailed debug output |
| `--use-latest` | Install latest versions instead of pinned versions |

**Interactive Prompts:**
- `[Y/n/a]` - Type `Y` for yes, `n` for no, `a` for auto-yes-all remaining prompts

### Windows Auto-Installation

**✅ Fully Supported!** Supreme 2 Light automatically installs tools on Windows using winget/Chocolatey.

```powershell
# One-command installation (auto-installs everything)
s2l install --all

# When prompted, type 'a' for auto-yes-all:
Install all 39 missing tools? [Y/n/a]: a
Auto-yes enabled for all remaining prompts

# Supreme 2 Light will automatically:
# - Install Chocolatey (if needed)
# - Install Node.js (if needed)
# - Install Ruby (if needed)
# - Install PHP (if needed)
# - Install all 36+ scanner tools
# - No terminal restart required!
```

**What Gets Installed:**
- **86%** of tools install automatically (36/42 scanners)
- Winget (priority), Chocolatey, npm, pip, gem installers
- PowerShell scripts for specialized tools (phpstan, ktlint, checkstyle, taplo, clj-kondo)
- Runtime dependencies (Node.js, Ruby, PHP) auto-installed

**Manual Installation (Optional):**
Only 3 tools require manual installation:
- `swiftlint` - macOS only
- `checkmake` - Requires Go: `go install github.com/mrtazz/checkmake/cmd/checkmake@latest`
- `cppcheck` - Download from https://cppcheck.sourceforge.io/

---

## ⚙️ Configuration

### `.supreme2l.yml`

Supreme 2 Light uses a YAML configuration file for project-specific settings:

```yaml
# Supreme 2 Light Configuration File
version: 2025.9.0

# Scanner control
scanners:
  enabled: []      # Empty = all scanners enabled
  disabled: []     # List scanners to disable
  # Example: disabled: ['bandit', 'eslint']

# Build failure settings
fail_on: high      # critical | high | medium | low

# Exclusion patterns
exclude:
  paths:
    - node_modules/
    - venv/
    - .venv/
    - env/
    - .git/
    - .svn/
    - __pycache__/
    - "*.egg-info/"
    - dist/
    - build/
    - .tox/
    - .pytest_cache/
    - .mypy_cache/
  files:
    - "*.min.js"
    - "*.min.css"
    - "*.bundle.js"
    - "*.map"

# IDE integration
ide:
  claude_code:
    enabled: true
    auto_scan: true          # Scan on file save
    inline_annotations: true # Show issues inline
  cursor:
    enabled: false
  vscode:
    enabled: false
  gemini_cli:
    enabled: false

# Scan settings
workers: null        # null = auto-detect (cpu_count - 2)
cache_enabled: true  # Enable file caching for speed
```

### Generate Default Config

```bash
s2l init
```

This creates `.supreme2l.yml` with sensible defaults and auto-detects your IDE.

---

## 🤖 IDE Integration

Supreme 2 Light supports **5 major AI coding assistants** with native integrations. Initialize with `s2l init --ide all` or select specific platforms.

### Supported Platforms

| IDE | Context File | Commands | Status |
|-----|-------------|----------|--------|
| **Claude Code** | `CLAUDE.md` | `/s2l-scan`, `/s2l-install` | ✅ Full Support |
| **Gemini CLI** | `GEMINI.md` | `/scan`, `/install` | ✅ Full Support |
| **OpenAI Codex** | `AGENTS.md` | Native slash commands | ✅ Full Support |
| **GitHub Copilot** | `.github/copilot-instructions.md` | Code suggestions | ✅ Full Support |
| **Cursor** | Reuses `CLAUDE.md` | MCP + Claude commands | ✅ Full Support |

### Quick Setup

```bash
# Setup for all IDEs (recommended)
s2l init --ide all

# Or select specific platforms
s2l init --ide claude-code --ide gemini-cli
```

### Claude Code

**What it creates:**
- `CLAUDE.md` - Project context file
- `.claude/agents/supreme2l/agent.json` - Agent configuration
- `.claude/commands/s2l-scan.md` - Scan slash command
- `.claude/commands/s2l-install.md` - Install slash command

**Usage:**
```
Type: /s2l-scan
Claude: *runs security scan*
Results: Displayed in terminal + chat
```

### Gemini CLI

**What it creates:**
- `GEMINI.md` - Project context file
- `.gemini/commands/scan.toml` - Scan command config
- `.gemini/commands/install.toml` - Install command config

**Usage:**
```bash
gemini /scan              # Full scan
gemini /scan --quick      # Quick scan
gemini /install --check   # Check tools
```

### OpenAI Codex

**What it creates:**
- `AGENTS.md` - Project context (root level)

**Usage:**
```
Ask: "Run a security scan"
Codex: *executes s2l scan .*
```

### GitHub Copilot

**What it creates:**
- `.github/copilot-instructions.md` - Security standards and best practices

**How it helps:**
- Knows project security standards
- Suggests secure code patterns
- Recommends running scans after changes
- Helps fix security issues

### Cursor

**What it creates:**
- `.cursor/mcp-config.json` - MCP server configuration
- Reuses `.claude/` structure (Cursor is VS Code fork)

**Usage:**
- Works like Claude Code integration
- MCP-native for future deeper integration

---

## 🎯 False Positive Filter (NEW)

Supreme 2 Light includes an **intelligent false positive filter** that automatically reduces scan noise by identifying findings that are likely safe.

### How It Works

```bash
# Run scan - FP filter is automatic
s2l scan .

# Example output showing FP analysis:
🔍 Issues found: 34
   - Likely FPs filtered: 12 (35%)
   - Remaining issues: 22
```

### What Gets Filtered

| Pattern Type | Description | Confidence |
|--------------|-------------|------------|
| **Security Wrappers** | Credentials passed to SecureString, Fernet, AESGCM | 95% |
| **Docstrings/Comments** | Keywords in documentation, not code | 95% |
| **Test Files** | Findings in test/, spec/, mock/ directories | 70-90% |
| **Template Files** | .env.example, .env.template with placeholders | 90% |
| **Cache Key Hashes** | MD5/SHA1 used for caching, not crypto | 90% |
| **Security Modules** | Files implementing credential protection | 85% |

### FP Analysis in Reports

Each finding includes FP analysis metadata:

```json
{
  "issue": "Hardcoded credential detected",
  "severity": "HIGH",
  "fp_analysis": {
    "is_likely_fp": true,
    "confidence": 0.95,
    "reason": "security_wrapper",
    "explanation": "Credential is wrapped in security class 'SecureString' for protection"
  },
  "adjusted_severity": "LOW"
}
```

### Supported Languages

FP patterns are currently tuned for:
- **Python** - Security wrappers, docstrings, subprocess patterns
- **TypeScript/JavaScript** - JSDoc, test placeholders, secure constructors
- **Go** - Cache key hashes, mock files, checksum functions
- **Docker** - Test Dockerfiles with :latest tag
- **Java** - Test files, example configs (expanding)

---

## 🔧 Advanced Features

### System Load Monitoring

Supreme 2 Light automatically monitors system load and adjusts worker count:

```python
# Auto-detects optimal workers based on:
# - CPU usage
# - Memory usage
# - Load average
# - Available cores

# Warns when system is overloaded:
⚠️  High CPU usage: 85.3%
Using 2 workers (reduced due to system load)
```

### Sandbox/Codex Compatibility (NEW)

Supreme 2 Light now works in restricted sandbox environments like OpenAI Codex:

```bash
# In sandbox environments, Supreme 2 Light auto-detects and adjusts:
🏖️  Sandbox mode detected
    Falling back to sequential scanning...

📊 Scanning 145 files (sequential mode)...
✅ Scan complete!
```

**What gets adjusted:**
- Multiprocessing → Sequential scanning when semaphores unavailable
- Worker pool → Single-threaded execution
- No manual configuration needed - fully automatic

**Works in:**
- OpenAI Codex sandbox
- CI/CD containers with restricted permissions
- Docker containers without SHM access
- Any environment where `multiprocessing.Pool()` fails

### Smart Caching

Hash-based caching skips unchanged files:

```bash
# First scan
📂 Files scanned: 145
⏱️  Total time: 47.28s

# Second scan (no changes)
📂 Files scanned: 0
⚡ Files cached: 145
⏱️  Total time: 2.15s  # 22× faster!
```

### Parallel Processing

Multi-core scanning for massive speedups:

```
Single-threaded:  417.5 seconds
6 workers:         47.3 seconds  # 8.8× faster
24 workers:        ~18 seconds   # 23× faster
```

---

## 📊 Example Workflow

### New Project Setup

```bash
# 1. Initialize
cd my-awesome-project
s2l init

Supreme 2 Light Initialization Wizard

✅ Step 1: Project Analysis
   Found 15 language types
   Primary: PythonScanner (44 files)

✅ Step 2: Scanner Availability
   Available: 6/42 scanners
   Missing: 36 tools

✅ Step 3: Configuration
   Created .supreme2l.yml
   Auto-detected IDE: Claude Code

✅ Step 4: IDE Integration
   Created .claude/agents/supreme2l/agent.json
   Created .claude/commands/s2l-scan.md

✅ Supreme 2 Light Initialized Successfully!

# 2. Install tools
s2l install --all

📦 Installing 36 missing tools...
✅ bandit installed (pip)
✅ eslint installed (npm)
✅ shellcheck installed (apt)
...
✅ All tools installed!

# 3. First scan
s2l scan .

🔍 Issues found: 23
   CRITICAL: 0
   HIGH: 2
   MEDIUM: 18
   LOW: 3

# 4. Fix issues and rescan
s2l scan . --quick

⚡ Files cached: 142
🔍 Issues found: 12  # Progress!
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  supreme2l:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install Supreme 2 Light
        run: pip install supreme2l

      - name: Install security tools
        run: s2l install --all --yes

      - name: Run security scan
        run: s2l scan . --fail-on high
```

---

## 🏗️ Architecture

### Scanner Pattern

All scanners follow a consistent pattern:

```python
class PythonScanner(BaseScanner):
    """Scanner for Python files using Bandit"""

    def get_tool_name(self) -> str:
        return "bandit"

    def get_file_extensions(self) -> List[str]:
        return [".py"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        # Run bandit on file
        # Parse JSON output
        # Map severity levels
        # Return structured issues
        return ScannerResult(...)
```

### Auto-Registration

Scanners automatically register themselves:

```python
# supreme2l/scanners/__init__.py
registry = ScannerRegistry()
registry.register(PythonScanner())
registry.register(JavaScriptScanner())
# ... all 42 scanners
```

### Severity Mapping

Unified severity levels across all tools:

- **CRITICAL** - Security vulnerabilities, fatal errors
- **HIGH** - Errors, security warnings
- **MEDIUM** - Warnings, code quality issues
- **LOW** - Style issues, conventions
- **INFO** - Suggestions, refactoring opportunities

---

## 🧪 Testing & Quality

### Dogfooding Results

Supreme 2 Light scans itself daily:

```
✅ Files scanned: 85
✅ CRITICAL issues: 0
✅ HIGH issues: 0
✅ MEDIUM issues: 113
✅ LOW issues: 1

Status: Production Ready ✅
```

### Performance Benchmarks

| Project Size | Files | Time (6 workers) | Speed |
|--------------|-------|------------------|-------|
| Small | 50 | ~15s | 3.3 files/s |
| Medium | 145 | ~47s | 3.1 files/s |
| Large | 500+ | ~3min | 2.8 files/s |

---

## 🗺️ Roadmap

### ✅ Completed (v2025.8)

- **73 Specialized Scanners** - Comprehensive language and platform coverage
- **AI Agent Security** - 20+ scanners, 180+ rules, OWASP LLM 2025 compliant
- **CVE Detection** - React2Shell (CVE-2025-55182), Next.js vulnerabilities
- **Cross-Platform** - Native Windows, macOS, Linux with auto-installation
- **IDE Integration** - Claude Code, Cursor, Gemini CLI, GitHub Copilot
- **Multi-Format Reports** - JSON, HTML, Markdown, SARIF, JUnit
- **Parallel Processing** - 10-40× faster with smart caching

### 🚧 In Progress (v2025.9)

- **Supply Chain Protection** - `s2l protect` for install-time scanning
- **Malicious Package Database** - Known bad packages blocked before install
- **Preinstall Script Analysis** - Detect env harvesting, backdoors

### 🔮 Upcoming

- **Web Dashboard** - Cloud-hosted security insights
- **GitHub App** - Automatic PR scanning
- **VS Code Extension** - Native IDE integration
- **Enterprise Features** - SSO, audit logs, team management

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

```bash
# 1. Fork and clone
git clone https://github.com/yourusername/Supreme-2-light.git
cd Supreme-2-light

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# 3. Install in editable mode
pip install -e ".[dev]"

# 4. Run tests
pytest

# 5. Create feature branch
git checkout -b feature/my-awesome-feature

# 6. Make changes and test
s2l scan .  # Dogfood your changes!

# 7. Submit PR
git push origin feature/my-awesome-feature
```

### Adding New Scanners

See `docs/development/adding-scanners.md` for a guide on adding new language support.

---

## 📜 License

AGPL-3.0-or-later - See [LICENSE](LICENSE) file

Supreme 2 Light is free and open source software. You can use, modify, and distribute it freely, but any modifications or derivative works (including SaaS deployments) must also be released under AGPL-3.0.

For commercial licensing options, contact: support@silenceai.net

---

## 🙏 Credits

**Development:**
- Silence AI
- Claude AI (Anthropic) - AI-assisted development

**Built With:**
- Python 3.10+
- Click - CLI framework
- Rich - Terminal formatting
- Bandit, ESLint, ShellCheck, and 39+ other open-source security tools

**Inspired By:**
- Bandit (Python security)
- SonarQube (multi-language analysis)
- Semgrep (pattern-based security)
- Mega-Linter (comprehensive linting)

---

## 📖 Guides

- **[Quick Start](docs/guides/quick-start.md)** - Get running in 5 minutes
- **[AI Security Scanning](docs/AI_SECURITY.md)** - Complete guide to AI/LLM security (OWASP 2025, MCP, RAG)
- **[False Positive Filter](docs/guides/handling-false-positives.md)** - Intelligent FP detection and noise reduction
- **[IDE Integration](docs/guides/ide-integration.md)** - Setup Claude Code, Gemini, Copilot, Codex
- **[Sandbox/CI Mode](docs/guides/sandbox-mode.md)** - Using Supreme 2 Light in restricted environments

---

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/Zeinullahh/Supreme-2-light/issues)
- **Email**: support@silenceai.net
- **Documentation**: https://docs.silenceai.net
- **Discord**: https://discord.gg/supreme2l (coming soon)

---

## 🌟 Why Supreme 2 Light?

### vs. Bandit
- ✅ Supports 74 scanners (not just Python)
- ✅ Parallel processing (10-40× faster)
- ✅ **Intelligent FP filter** reduces noise
- ✅ Auto-installer for all tools
- ✅ IDE integration

### vs. SonarQube
- ✅ Simpler setup (one command)
- ✅ No server required
- ✅ **Works in sandboxed environments**
- ✅ Faster scans (local processing)
- ✅ Free and open source

### vs. Semgrep
- ✅ More language support (74 vs ~30 scanners)
- ✅ **Built-in FP analysis** per finding
- ✅ Uses established tools (Bandit, ESLint, etc.)
- ✅ Better IDE integration
- ✅ Easier configuration

### vs. Mega-Linter
- ✅ Faster (parallel + sequential fallback)
- ✅ **Context-aware FP filtering**
- ✅ Smarter caching
- ✅ Better error handling
- ✅ AI/LLM security focus

---

**Supreme 2 Light - Multi-Language Security Scanner**

**One Command. Complete Security.**

```bash
s2l init && s2l scan .
```
