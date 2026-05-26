# =========================
# Buil stage
# =========================
FROM golang:1.26-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    gcc \
    make \
    git \
    curl \
    pkg-config \
    libbpf-dev \
    linux-libc-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN make build

# =========================
# Runtime stage
# =========================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    libbpf1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/bin/ebpf-agent ./ebpf-agent

CMD ["./ebpf-agent"]