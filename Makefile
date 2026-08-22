# Variables
BINARY := ebpf-agent
CMD_DIR := ./cmd/cli
BUILD_DIR := bin
OUTPUT := $(BUILD_DIR)/$(BINARY)
IMAGE := ebpf-agent

GO := go

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build: $(OUTPUT)

$(OUTPUT):
	@echo ">> building $(BINARY)"
	@mkdir -p internal/modules/bpf
	@mkdir -p $(BUILD_DIR)
	$(GO) generate ./...
	$(GO) build -o $(OUTPUT) $(CMD_DIR)

.PHONY: clean
clean:
	@echo ">> cleaning"
	rm -rf $(BUILD_DIR)

.PHONY: rebuild
rebuild: clean build

.PHONY: fmt
fmt:
	$(GO) fmt ./...

# Build and run via Docker (recommended: no local eBPF toolchain needed).
# ARGS is "<module> [module flags]", e.g.
#   make docker-run ARGS="hello -target-pid 12345"
.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE) .

.PHONY: docker-run
docker-run:
	docker run --rm -it \
	  --privileged \
	  --pid=host \
	  --network=host \
	  -v /sys/kernel/debug:/sys/kernel/debug \
	  -v /sys/kernel/tracing:/sys/kernel/tracing \
	  -v /sys/fs/bpf:/sys/fs/bpf \
	  $(IMAGE) $(ARGS)

