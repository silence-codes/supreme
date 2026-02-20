# Supreme 2 Light Security Scanner - Docker Image
# Multi-stage build for optimal image size

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY supreme2l/ ./supreme2l/

# Build the wheel
RUN pip install --no-cache-dir build && \
    python -m build --wheel

# Stage 2: Runtime
FROM python:3.11-slim

LABEL maintainer="Silence AI <security@silenceai.net>"
LABEL description="supreme2l - The 42-Headed Security Guardian"
LABEL version="0.9.0.0"

WORKDIR /app

# Install runtime dependencies and common security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    shellcheck \
    && rm -rf /var/lib/apt/lists/*

# Copy wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/

# Install supreme2l
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Create non-root user for security
RUN useradd -m -u 1000 supreme2l && \
    chown -R supreme2l:supreme2l /app

USER supreme2l

# Verify installation
RUN s2l --version

# Set working directory for scans
WORKDIR /workspace

# Default command
ENTRYPOINT ["supreme2l"]
CMD ["--help"]
