# Build stage with eBPF toolchain
FROM golang:1.24-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install only essential eBPF build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-libc-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy Go modules first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code (includes vmlinux.h)
COPY . .

# Generate eBPF scaffolding and build
RUN go generate ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o beeward .

# Runtime stage - using busybox (following Cilium pwru pattern)
FROM busybox

# Copy compiled binary
COPY --from=builder /build/beeward /usr/local/bin/beeward

# No ENTRYPOINT - let container runtime handle it
