# 🐳 s2l Docker Guide

Complete guide for running s2l in Docker containers.

---

## 🚀 Quick Start

### 1. Setup Docker Access (One-Time)

```bash
# Add your user to the docker group
bash docker-setup.sh

# Then log out and log back in, or run:
newgrp docker
```

### 2. Build the Container

```bash
# Fastest: Use pre-built wheel
make docker-build-simple

# Or manually:
docker build -f Dockerfile.simple -t s2l:latest .
```

### 3. Run s2l

```bash
# Scan current directory
make docker-scan

# Or manually:
docker run --rm -v $(pwd):/workspace:ro s2l:latest scan /workspace
```

---

## 📦 Available Dockerfiles

### `Dockerfile` - Production Build (Multi-Stage)
- **Use Case**: Production deployment, minimal image size
- **Features**:
  - Multi-stage build
  - Builds s2l from source
  - Smaller final image (only runtime dependencies)
- **Build Time**: ~2-3 minutes
- **Image Size**: ~300MB

```bash
docker build -t s2l:latest .
```

### `Dockerfile.simple` - Fast Build (Pre-built Wheel)
- **Use Case**: Quick testing, development, CI/CD
- **Features**:
  - Uses pre-built wheel from `dist/`
  - Single stage build
  - Fastest build time
- **Build Time**: ~30-60 seconds
- **Image Size**: ~320MB

```bash
docker build -f Dockerfile.simple -t s2l:latest .
```

### `Dockerfile.test` - Testing Build
- **Use Case**: Running tests, development
- **Features**:
  - Includes dev dependencies (pytest, coverage, etc.)
  - Mounts source code
  - Runs test suite
- **Build Time**: ~1-2 minutes
- **Image Size**: ~400MB

```bash
docker build -f Dockerfile.test -t s2l-test:latest .
```

---

## 🎮 Usage Examples

### Basic Scanning

```bash
# Scan current directory
docker run --rm -v $(pwd):/workspace:ro s2l:latest scan /workspace

# Scan specific directory
docker run --rm -v /path/to/project:/workspace:ro s2l:latest scan /workspace

# Quick scan (changed files only)
docker run --rm -v $(pwd):/workspace:ro s2l:latest scan /workspace --quick

# Force full scan
docker run --rm -v $(pwd):/workspace:ro s2l:latest scan /workspace --force
```

### Interactive Usage

```bash
# Get help
docker run --rm s2l:latest --help

# Check version
docker run --rm s2l:latest --version

# Interactive shell
docker run --rm -it s2l:latest /bin/bash

# Inside container:
s2l scan /workspace
s2l install --check
```

### Running Tests

```bash
# Build test image
make docker-build-test

# Run tests
make docker-test

# Or manually:
docker run --rm -v $(pwd):/workspace s2l-test:latest
```

### Custom Configuration

```bash
# Mount .s2l.yml from host
docker run --rm \
  -v $(pwd):/workspace:ro \
  -v $(pwd)/.s2l.yml:/app/.s2l.yml:ro \
  s2l:latest scan /workspace
```

---

## 🐳 Docker Compose

### Available Services

```bash
# Main scanner service
docker-compose up s2l

# Development service (interactive)
docker-compose run --rm s2l-dev

# Test service
docker-compose up s2l-test
```

### Custom Scans

```yaml
# Edit docker-compose.yml to customize:
services:
  s2l:
    volumes:
      - /path/to/your/project:/workspace:ro
    command: scan /workspace --workers 4
```

---

## 🔧 Makefile Commands

All Docker operations are available via Makefile:

### Setup
```bash
make docker-setup          # Configure Docker access
```

### Build
```bash
make docker-build          # Build production image
make docker-build-simple   # Build simple image (fastest)
make docker-build-test     # Build test image
make docker-build-all      # Build all images
```

### Run
```bash
make docker-run            # Show help
make docker-scan           # Scan current directory
make docker-test           # Run tests
make docker-shell          # Interactive shell
```

### Clean
```bash
make docker-clean          # Remove s2l images
make docker-prune          # Clean Docker build cache
```

### Test
```bash
make test-install          # Run installation test script
```

---

## 🧪 Testing Across Distributions

The `test-docker-install.sh` script tests s2l installation on multiple Linux distributions:

```bash
# Test on Ubuntu 22.04, 24.04, and Debian 12
bash test-docker-install.sh

# Or using Make:
make test-install
```

**What it tests:**
- Clean installation in fresh containers
- Package manager updates
- Python environment setup
- s2l installation from wheel
- `s2l init` command
- `s2l scan` command
- Scanner availability

---

## 📋 Requirements

### Before Building

1. **Docker installed and running**
   ```bash
   docker --version
   systemctl status docker
   ```

2. **User in docker group**
   ```bash
   groups | grep docker
   ```

3. **Pre-built wheel available** (for Dockerfile.simple)
   ```bash
   ls dist/*.whl
   # Should show: supreme2l-0.9.1.1-py3-none-any.whl
   ```

### Building the Wheel

If you need to rebuild the wheel:

```bash
# Install build tools
pip install build

# Build wheel
python -m build --wheel

# Verify
ls dist/*.whl
```

---

## 🎯 CI/CD Integration

### GitHub Actions Example

```yaml
name: s2l Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build s2l Docker image
        run: docker build -f Dockerfile.simple -t s2l:latest .

      - name: Run security scan
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace:ro \
            s2l:latest scan /workspace --fail-on high
```

### GitLab CI Example

```yaml
s2l-scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -f Dockerfile.simple -t s2l:latest .
    - docker run --rm -v $(pwd):/workspace:ro s2l:latest scan /workspace
  only:
    - merge_requests
    - main
```

---

## 🐛 Troubleshooting

### Permission Denied

**Error**: `permission denied while trying to connect to the Docker daemon socket`

**Solution**:
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Apply changes
newgrp docker

# Or log out and log back in
```

### Build Fails - Wheel Not Found

**Error**: `COPY failed: file not found: dist/supreme2l-*.whl`

**Solution**:
```bash
# Build the wheel first
python -m build --wheel

# Verify it exists
ls dist/*.whl
```

### Container Can't Access Files

**Error**: Permission errors when scanning

**Solution**:
```bash
# Check file permissions
ls -la /path/to/project

# Run with user mapping
docker run --rm \
  --user $(id -u):$(id -g) \
  -v $(pwd):/workspace:ro \
  s2l:latest scan /workspace
```

### Build Cache Issues

**Error**: Old dependencies or stale builds

**Solution**:
```bash
# Clean build cache
make docker-prune

# Or manually:
docker builder prune -f

# Rebuild without cache
docker build --no-cache -f Dockerfile.simple -t s2l:latest .
```

---

## 📊 Image Comparison

| Dockerfile | Build Time | Image Size | Use Case |
|------------|------------|------------|----------|
| `Dockerfile` | ~2-3 min | ~300 MB | Production |
| `Dockerfile.simple` | ~30-60 sec | ~320 MB | Development/CI |
| `Dockerfile.test` | ~1-2 min | ~400 MB | Testing |

---

## 🔐 Security Notes

- All images run as non-root user (`s2l:1000`)
- Read-only volume mounts recommended (`:ro`)
- Minimal base images (python:3.11-slim)
- No unnecessary packages installed
- Regular security scanning with s2l itself!

```bash
# Scan the Docker images themselves
docker run --rm s2l:latest scan /app
```

---

## 📚 Additional Resources

- **Main README**: [README.md](README.md)
- **Test Script**: [test-docker-install.sh](test-docker-install.sh)
- **Docker Compose**: [docker-compose.yml](docker-compose.yml)
- **Setup Script**: [docker-setup.sh](docker-setup.sh)

---

## 🎉 Quick Reference Card

```bash
# Setup (one-time)
bash docker-setup.sh && newgrp docker

# Build
make docker-build-simple

# Scan
make docker-scan

# Test
make docker-test

# Clean
make docker-clean
```

---

**Last Updated**: 2025-11-15
**Version**: 0.9.1.1
**Status**: Ready for Testing
