.PHONY: run build test race vet tidy clean

run:
	go run ./cmd/server

build:
	CGO_ENABLED=0 go build -trimpath -o bin/server ./cmd/server

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin
