BINARY    := net-finder
GO        := CGO_ENABLED=0 go
GOFLAGS   :=
PREFIX    := /usr/local/bin
IMAGE     := jollaman999/net-finder

VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)

.PHONY: all build clean install uninstall run dev deps fmt vet \
        docker-build docker-push docker-run docker-up docker-down

all: build

build:
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/net-finder

clean:
	rm -f $(BINARY)

install: build
	sudo install -m 755 $(BINARY) $(PREFIX)/$(BINARY)

uninstall:
	sudo rm -f $(PREFIX)/$(BINARY)

run: build
	sudo ./$(BINARY)

dev:
	@which air > /dev/null 2>&1 || go install github.com/air-verse/air@latest
	air

deps:
	$(GO) mod download
	$(GO) mod tidy

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

docker-push: docker-build
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

docker-run:
	docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN $(IMAGE):latest

docker-up:
	VERSION=$(VERSION) docker compose up -d --build

docker-down:
	docker compose down
