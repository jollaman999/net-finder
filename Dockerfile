FROM golang:1.21-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /net-finder .

FROM alpine:latest

COPY --from=builder /net-finder /usr/local/bin/net-finder

EXPOSE 9090

ENTRYPOINT ["net-finder"]
