VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/SimsekBerk/DDOS-Detection/internal/api.Version=$(VERSION)

.PHONY: all build ui test vet run-demo sim docker clean

all: ui build

## build: Go binary'lerini bin/ altına derler (UI web/dist'ten gömülür)
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ddosd ./cmd/ddosd
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ddos-sim ./cmd/ddos-sim

## ui: React arayüzünü derler (web/dist)
ui:
	cd web && npm ci && npm run build

test:
	go test ./...

vet:
	go vet ./...

## run-demo: sentetik trafikli demo (http://localhost:8090)
run-demo: build
	./bin/ddosd -config config.demo.yaml

## sim: komut satırı simülatörü örneği
sim: build
	./bin/ddos-sim -list

docker:
	docker build -t ddosd:$(VERSION) .

clean:
	rm -rf bin data data-demo
