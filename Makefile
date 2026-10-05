.PHONY: test test-race test-release test-integration vet fmt cover verify build sign install clean

build:
	go build -o bin/keyward ./cmd/keyward

# SIGN_IDENTITY is the exact Apple Development identity from security find-identity.
sign: build
	@test -n "$(SIGN_IDENTITY)" || { echo 'set SIGN_IDENTITY to your Apple Development certificate name'; exit 1; }
	codesign --force --sign "$(SIGN_IDENTITY)" --identifier com.nwokolo24.keyward bin/keyward

install: sign
	bin/keyward service install

test:
	go test ./...

test-race:
	go test -race ./...

test-release:
	bash -n scripts/sign-release.sh scripts/publish-release.sh scripts/update-homebrew.sh scripts/test-homebrew-release.sh
	python3 -m unittest discover -s scripts/tests -p 'test_*.py'

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
verify: vet test-race test-release
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	@echo "verify: ok"

clean:
	rm -rf bin coverage.out coverage.html
