.PHONY: test test-race vet fmt cover verify clean

test:
	go test ./...

test-race:
	go test -race ./...

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
