VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.Version=$(VERSION)

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@latest
GOSEC       := github.com/securego/gosec/v2/cmd/gosec@latest
GOVULN      := golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: build build-linux-amd64 build-linux-arm64 test vet lint clean release

build:
	go build -ldflags "$(LDFLAGS)" -o certsync .

# 发布产物：静态交叉编译 + SHA256SUMS
build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o certsync-linux-amd64 .

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o certsync-linux-arm64 .

release: build-linux-amd64 build-linux-arm64
	cd . && sha256sum certsync-linux-amd64 certsync-linux-arm64 > SHA256SUMS

test:
	go test ./...

vet:
	go vet ./...

lint:
	go run $(STATICCHECK) ./...
	go run $(GOSEC) ./...
	go run $(GOVULN) ./...

clean:
	rm -f certsync certsync-linux-amd64 certsync-linux-arm64 SHA256SUMS
