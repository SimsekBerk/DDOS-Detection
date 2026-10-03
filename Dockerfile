# syntax=docker/dockerfile:1
FROM node:20-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/SimsekBerk/DDOS-Detection/internal/api.Version=${VERSION}" -o /out/ddosd ./cmd/ddosd \
 && CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/ddos-sim ./cmd/ddos-sim \
 && CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/ddos-bench ./cmd/ddos-bench

FROM alpine:3.20
RUN adduser -D -H -u 10001 ddosd && mkdir -p /data /var/run/ddosd /etc/ddosd /app && chown ddosd /data /var/run/ddosd /etc/ddosd \
 && ln -s /data /app/data && ln -s /data /app/data-demo
WORKDIR /app
COPY --from=build /out/ddosd /out/ddos-sim /out/ddos-bench /usr/local/bin/
COPY rules ./rules
COPY config.example.yaml config.demo.yaml ./
USER ddosd
EXPOSE 2055/udp 4739/udp 6343/udp 8080/tcp
ENTRYPOINT ["ddosd"]
# /etc/ddosd must be a writable volume: the settings UI saves the
# configuration and its version history there.
CMD ["-config", "/etc/ddosd/config.yaml"]
