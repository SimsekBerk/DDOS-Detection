VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/SimsekBerk/DDOS-Detection/internal/api.Version=$(VERSION)

.PHONY: all build ui test test-race fuzz bench vet run-demo run-preprod sim docker clean

all: ui build

## build: Go binary'lerini bin/ altına derler (UI web/dist'ten gömülür)
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ddosd ./cmd/ddosd
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ddos-sim ./cmd/ddos-sim
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ddos-bench ./cmd/ddos-bench
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ddos-probe ./cmd/ddos-probe

## ui: React arayüzünü derler (web/dist)
ui:
	cd web && npm ci && npm run build

test:
	go test ./...

## test-race: kısa testler, race detector ile
test-race:
	go test -race -short ./...

## fuzz: decoder'ı rastgele paketlerle 60 sn zorlar
fuzz:
	go test ./internal/decoder -run '^$$' -fuzz FuzzDecode -fuzztime 60s

## bench: algılama doğruluğu, yanlış alarm ve throughput benchmark'ı (docs/BENCHMARK.md)
bench:
	go run ./cmd/ddos-bench all -json bench-results.json

vet:
	go vet ./...

## run-demo: sentetik trafikli demo (http://localhost:8090)
run-demo: build
	./bin/ddosd -config config.demo.yaml

## run-preprod: bu makinenin gerçek trafiği (ddos-probe → ddosd, http://127.0.0.1:8092)
## önce: cp config.preprod.example.yaml config.preprod.yaml (alt ağı düzenleyin)
run-preprod: build
	./bin/ddos-probe -i $${IFACE:-en0} -collector 127.0.0.1:9995 & ./bin/ddosd -config config.preprod.yaml

## sim: komut satırı simülatörü örneği
sim: build
	./bin/ddos-sim -list

docker:
	docker build -t ddosd:$(VERSION) .

clean:
	rm -rf bin data data-demo
