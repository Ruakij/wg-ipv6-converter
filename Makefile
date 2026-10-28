LDFLAGS = -s -w
# The architectures build/build-multiarch.sh covers.
ARCHES ?= amd64 arm64 arm

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "$(LDFLAGS)" -o bin/wg-ipv6-converter ./cmd/app

# Release binaries plus their checksums, as the release workflow publishes them.
.PHONY: dist
dist:
	rm -rf dist && mkdir dist
	for arch in $(ARCHES); do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch GOARM=7 go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/wg-ipv6-converter-linux-$$arch ./cmd/app || exit 1; \
	done
	cd dist && sha256sum wg-ipv6-converter-* > SHA256SUMS
