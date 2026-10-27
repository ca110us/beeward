.PHONY: docker-build docker-push deploy clean help

IMAGE_NAME ?= ghcr.io/ca110us/beeward
IMAGE_TAG ?= latest

help:
	@echo "Beeward Build (macOS/ARM64 compatible)"
	@echo ""
	@echo "Available targets:"
	@echo "  docker-build    Build Docker image (works on macOS)"
	@echo "  docker-push     Push image to registry"
	@echo "  deploy          Deploy DaemonSet to Kubernetes"
	@echo "  clean           Clean up Kubernetes resources"
	@echo ""
	@echo "Note: This project uses Docker multi-stage build."
	@echo "      All compilation happens inside Linux container."

# Build Docker image (works on macOS ARM64)
# Multi-stage build handles all compilation inside Linux container
docker-build:
	@echo "Building Docker image (compilation happens in container)..."
	docker build --platform linux/amd64 -t $(IMAGE_NAME):$(IMAGE_TAG) .
	@echo "✓ Build complete: $(IMAGE_NAME):$(IMAGE_TAG)"

# Push Docker image
docker-push: docker-build
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

# Deploy to Kubernetes
deploy:
	kubectl apply -f deploy/daemonset.yaml

# Clean up
clean:
	kubectl delete -f deploy/daemonset.yaml || true
	@echo "✓ Cleaned up"
