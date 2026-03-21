.PHONY: all format lint test install-tools help

FLAGS := GOEXPERIMENT=jsonv2
PACKAGES := ./...

all: format lint test

format:
	@echo "Formatting..."
	@gofmt -w .

lint:
	@echo "Linting..."
	@$(FLAGS) golangci-lint run $(PACKAGES)

test:
	@echo "Testing..."
	@$(FLAGS) go test -v -cover -coverprofile=coverage.out $(PACKAGES)

install-tools:
	@echo "Installing tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

help:
	@echo "Makefile for the project."
	@echo ""
	@echo "Targets:"
	@echo ""
	@echo "all: 		    Runs format, lint, and test."
	@echo "format: 	        Formats the code."
	@echo "lint: 		    Lints the code."
	@echo "test: 		    Runs the tests."
	@echo "install-tools: 	Installs the required tools."
	@echo "help: 		    Shows this help message."

.DEFAULT_GOAL := help
