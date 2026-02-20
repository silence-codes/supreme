# s2l Examples

Example configuration files to help you integrate s2l into your projects.

## Files

| File | Description |
|------|-------------|
| `s2l.example.yml` | Example s2l configuration file |
| `github-action.yml` | GitHub Actions workflow for CI/CD |
| `gitlab-ci.yml` | GitLab CI configuration |
| `pre-commit-config.yaml` | Pre-commit hooks configuration |

## Quick Start

### 1. Add s2l config to your project

```bash
cp examples/s2l.example.yml .s2l.yml
```

### 2. Set up CI/CD (choose one)

**GitHub Actions:**
```bash
mkdir -p .github/workflows
cp examples/github-action.yml .github/workflows/security.yml
```

**GitLab CI:**
```bash
cat examples/gitlab-ci.yml >> .gitlab-ci.yml
```

### 3. Set up pre-commit hooks (optional)

```bash
cp examples/pre-commit-config.yaml .pre-commit-config.yaml
pip install pre-commit
pre-commit install
```

## Learn More

- [Installation Guide](../docs/INSTALLATION.md)
- [Quick Start](../docs/QUICKSTART.md)
- [Full Documentation](https://github.com/Pantheon-Security/s2l)
