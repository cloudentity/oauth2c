install:
	go install .

build:
	go build ./...

test:
	go test ./...

lint:
	docker run --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v1.64.5 golangci-lint run

all: build test lint
