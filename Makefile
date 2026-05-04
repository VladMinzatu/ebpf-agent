build:
	mkdir -p internal/modules/bpf
	go generate ./...
	go build -o ebpf-agent ./cmd/cli

