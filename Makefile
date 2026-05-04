# Variables
BINARY := ebpf-agent
CMD_DIR := ./cmd/cli
BUILD_DIR := bin
OUTPUT := $(BUILD_DIR)/$(BINARY)

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

# Run
.PHONY: run
run: build
	sudo $(OUTPUT)

.PHONY: clean
clean:
	@echo ">> cleaning"
	rm -rf $(BUILD_DIR)

.PHONY: rebuild
rebuild: clean build

.PHONY: fmt
fmt:
	$(GO) fmt ./...

