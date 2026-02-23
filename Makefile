BINARY    := net-finder
GO        := go
GOFLAGS   :=
PREFIX    := /usr/local/bin

VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)

.PHONY: all build clean install uninstall run deps fmt vet

all: build

build:
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) .

clean:
	rm -f $(BINARY)

install: build
	sudo install -m 755 $(BINARY) $(PREFIX)/$(BINARY)

uninstall:
	sudo rm -f $(PREFIX)/$(BINARY)

run: build
	sudo ./$(BINARY)

deps:
	$(GO) mod download
	$(GO) mod tidy

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...
