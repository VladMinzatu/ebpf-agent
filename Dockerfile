FROM ubuntu:24.04

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
    iproute2 \
    ca-certificates \
    build-essential \
    golang-go

WORKDIR /app

COPY . .

RUN make build

CMD ["./bin/ebpf-agent"]
