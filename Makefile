BINARY := bin/sslcheck
PKG    := .

export CGO_ENABLED := 0

.PHONY: all build clean test

all: build

build:
	@mkdir -p bin
	go build -trimpath -ldflags="-s -w" -o $(BINARY) $(PKG)

clean:
	rm -rf bin

test:
	go test ./...
