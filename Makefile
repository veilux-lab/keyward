.PHONY: test test-race test-integration vet fmt cover verify build app-ui app sign install clean

SWIFT_MODULE_CACHE ?= bin/.swift-module-cache

build:
	go build -o bin/keyward ./cmd/keyward

app-ui:
	@mkdir -p bin
	xcrun swiftc -module-cache-path "$(SWIFT_MODULE_CACHE)" -O -o bin/keyward-app cmd/keyward-app/main.swift

app: build app-ui
	go run ./cmd/keyward-bundle

# SIGN_IDENTITY is the exact Apple Development identity from security find-identity.
sign: build app-ui
	@test -n "$(SIGN_IDENTITY)" || { echo 'set SIGN_IDENTITY to your Apple Development certificate name'; exit 1; }
	codesign --force --sign "$(SIGN_IDENTITY)" --identifier com.nwokolo24.keyward bin/keyward
	go run ./cmd/keyward-bundle
	codesign --force --sign "$(SIGN_IDENTITY)" bin/Keyward.app

install: sign
	bin/keyward service install

test:
	go test ./...

test-race:
	go test -race ./...

# Touches the real Keychain, so it is kept out of `test` and `verify`. Items are
# written under a dedicated service name and removed afterwards, so it cannot
# affect real keyward entries.
test-integration:
	go test -tags integration -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# What CI would run. Fails on unformatted code rather than quietly reformatting.
verify: vet test-race
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	@echo "verify: ok"

clean:
	rm -rf bin coverage.out coverage.html
