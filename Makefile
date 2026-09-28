.PHONY: test test-race test-integration vet fmt cover verify clean

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
