VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS := -trimpath -buildvcs=false
LDFLAGS := -s -w -X main.version=$(VERSION)
export CGO_ENABLED := 0
export SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)

.PHONY: all build web openapi proto test cover lint vuln gosec bench size dist packages clean

all: build

openapi:
	go run ./tools/openapi-merge

web: openapi
	cd web && pnpm install --frozen-lockfile && pnpm gen:api && pnpm generate

build: web
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/serverkeeper ./cmd/serverkeeper

# go-only build using the committed UI output
build-go:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/serverkeeper ./cmd/serverkeeper

proto:
	cd proto && go run github.com/bufbuild/buf/cmd/buf@v1.74.0 generate

test:
	go test -race ./...

# fails if internal/ coverage < 80% (PRD §12)
# -coverpkg counts code exercised by other packages' tests; generated protobuf code is excluded
cover:
	go test -coverpkg=$$(go list ./internal/... | grep -v /internal/pb | paste -sd, -) -coverprofile=cover.out ./internal/...
	@go tool cover -func=cover.out | awk '/^total:/ {sub("%","",$$3); if ($$3+0 < 80) {print "coverage " $$3 "% < 80%"; exit 1} else print "coverage " $$3 "%"}'

lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@2026.2.2 ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# excluded by design for a root agent, each call site reviewed: G304 reads configured/host paths, G204 runs
# allowlisted commands only (internal/executor), G115 converts bounded timestamps and ids
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 -exclude-generated -severity medium -confidence medium \
		-exclude=G304,G204,G115 ./...

bench:
	go test -run=^$$ -bench=. -benchmem ./internal/collector/ ./internal/store/ ./internal/alert/
	./deploy/bench.sh

# binary budget < 30 MB (PRD §11.2)
size: build-go
	@s=$$(stat -c %s bin/serverkeeper); echo "binary $$((s/1024/1024)) MB"; [ $$s -lt 31457280 ]

dist:
	mkdir -p dist
	for a in amd64 arm64; do \
	  GOARCH=$$a go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/serverkeeper-linux-$$a ./cmd/serverkeeper; \
	done
	cd dist && sha256sum serverkeeper-linux-* > checksums.txt

packages: dist
	for a in amd64 arm64; do for p in deb rpm; do \
	  GOARCH=$$a VERSION=$(VERSION:v%=%) go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0 pkg \
	    --packager $$p --config deploy/nfpm.yaml --target dist/; \
	done; done

clean:
	rm -rf bin dist cover.out
