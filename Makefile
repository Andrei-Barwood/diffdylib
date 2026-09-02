SWIFT ?= swift
BUILD_DIR := .build
BIN := $(BUILD_DIR)/debug/diffdylib

.PHONY: build test run fixtures clean help

build:
	$(SWIFT) build

fixtures:
	bash Fixtures/build-fixtures.sh

test: fixtures
	$(SWIFT) test

run: build
	$(BIN) --help

clean:
	$(SWIFT) package clean
	rm -rf $(BUILD_DIR) Fixtures/build

help:
	@echo "DiffDylib"
	@echo "  make build     - swift build"
	@echo "  make fixtures  - compile laboratory Mach-O hosts"
	@echo "  make test      - fixtures + swift test"
	@echo "  make run       - print CLI help"
	@echo "  make clean     - remove build artifacts"
