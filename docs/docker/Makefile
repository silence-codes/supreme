# Supreme 2 Light Docker Makefile
# Convenient commands for building and testing Docker containers

.PHONY: help docker-build docker-build-simple docker-build-test docker-run docker-test docker-scan docker-clean

VERSION := 0.7.0.0

help:
	@echo "🐍 supreme2l Docker Commands"
	@echo "=========================="
	@echo ""
	@echo "Setup:"
	@echo "  make docker-setup        - Configure Docker access (adds user to docker group)"
	@echo ""
	@echo "Build:"
	@echo "  make docker-build        - Build production image (multi-stage)"
	@echo "  make docker-build-simple - Build simple image (uses pre-built wheel, fastest)"
	@echo "  make docker-build-test   - Build test image (includes dev dependencies)"
	@echo "  make docker-build-all    - Build all images"
	@echo ""
	@echo "Run:"
	@echo "  make docker-run          - Run supreme2l help"
	@echo "  make docker-scan         - Scan current directory"
	@echo "  make docker-test         - Run tests in container"
	@echo "  make docker-shell        - Interactive shell in container"
	@echo ""
	@echo "Clean:"
	@echo "  make docker-clean        - Remove all supreme2l Docker images"
	@echo "  make docker-prune        - Clean Docker build cache"
	@echo ""
	@echo "Test Script:"
	@echo "  make test-install        - Run test-docker-install.sh script"
	@echo ""

# Setup Docker access
docker-setup:
	@bash docker-setup.sh

# Build production image (multi-stage)
docker-build:
	docker build -t supreme2l:$(VERSION) -t supreme2l:latest .

# Build simple image (fastest, uses pre-built wheel)
docker-build-simple:
	docker build -f Dockerfile.simple -t supreme2l:simple -t supreme2l:latest .

# Build test image
docker-build-test:
	docker build -f Dockerfile.test -t supreme2l-test:$(VERSION) -t supreme2l-test:latest .

# Build all images
docker-build-all: docker-build docker-build-simple docker-build-test

# Run supreme2l help
docker-run:
	docker run --rm supreme2l:latest --help

# Scan current directory
docker-scan:
	docker run --rm -v $(PWD):/workspace:ro supreme2l:latest scan /workspace

# Run tests
docker-test:
	docker run --rm -v $(PWD):/workspace supreme2l-test:latest

# Interactive shell
docker-shell:
	docker run --rm -it -v $(PWD):/workspace supreme2l:latest /bin/bash

# Run the installation test script
test-install:
	@bash test-docker-install.sh

# Clean up images
docker-clean:
	docker rmi -f supreme2l:$(VERSION) supreme2l:latest supreme2l:simple || true
	docker rmi -f supreme2l-test:$(VERSION) supreme2l-test:latest || true

# Prune Docker build cache
docker-prune:
	docker builder prune -f

# Compose commands
compose-up:
	docker-compose up supreme2l

compose-dev:
	docker-compose run --rm supreme2l-dev

compose-test:
	docker-compose up supreme2l-test

compose-down:
	docker-compose down
