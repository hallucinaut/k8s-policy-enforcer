BINARY_NAME=k8s-policy-enforcer
CMD_PATH=./cmd/k8s-policy-enforcer
VERSION ?= 1.0.0

.PHONY: all build test clean lint help

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	go build -ldflags="-X main.Version=$(VERSION)" -o $(BINARY_NAME) $(CMD_PATH)

test:
	@echo "Running tests..."
	go test -v -race -cover ./cmd/k8s-policy-enforcer/...

lint:
	@echo "Running lint..."
	golangci-lint run ./...

clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	rm -rf dist/

help:
	@echo "Available targets:"
	@echo "  build   - Build the binary"
	@echo "  test    - Run tests with coverage"
	@echo "  lint    - Run golangci-lint"
	@echo "  clean   - Remove built artifacts"
