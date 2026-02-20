# s2l Guides

Practical how-to guides for getting the most out of s2l.

## Available Guides

### [Quick Start](./quick-start.md)
Get up and running with s2l in under 5 minutes. Covers installation, first scan, understanding results, and basic configuration.

### [Handling False Positives](./handling-false-positives.md)
Learn how to intelligently triage scan results and reduce noise from 70+ findings to just real issues. Includes `.bandit` configuration examples and common FP patterns.

### [IDE Integration](./ide-integration.md)
Set up s2l with AI-powered IDEs (Claude Code, Gemini CLI, GitHub Copilot, Cursor). Includes context file customization and auto-scan configuration.

## Quick Links

| Task | Guide | Key Command |
|------|-------|-------------|
| Install s2l | [Quick Start](./quick-start.md) | `pip install s2l-security` |
| Run first scan | [Quick Start](./quick-start.md) | `s2l scan .` |
| Reduce false positives | [Handling FPs](./handling-false-positives.md) | Create `.bandit` file |
| Setup AI IDE | [IDE Integration](./ide-integration.md) | `s2l init` |
| Add to CI/CD | [Quick Start](./quick-start.md) | `s2l scan . --fail-on high` |

## Contributing

Found an issue or want to add a guide? [Open an issue](https://github.com/pantheon-security/s2l/issues) or submit a PR.
