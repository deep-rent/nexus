.PHONY: all format lint test help

FLAGS := GOEXPERIMENT=jsonv2
PACKAGES := ./...

all: format lint test

format:
	@echo "Formatting..."
	@$(FLAGS) golangci-lint fmt $(PACKAGES)

lint:
	@echo "Linting..."
	@$(FLAGS) golangci-lint run $(PACKAGES)

test:
	@echo "Testing..."
	@$(FLAGS) go test -v -cover -coverprofile=coverage.out $(PACKAGES)

help:
	@echo "Targets:"
	@echo ""
	@echo "  all:            Runs format, lint, and test."
	@echo "  format:         Formats the code."
	@echo "  lint:           Lints the code."
	@echo "  test:           Executes the tests."
	@echo "  help:           Shows this help message."

.DEFAULT_GOAL := help
