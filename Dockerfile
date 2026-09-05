FROM golang:1.24-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/pq-shield ./cmd/proxy

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/pq-shield /usr/local/bin/pq-shield

RUN addgroup -g 10001 -S pqshield && \
    adduser  -u 10001 -S pqshield -G pqshield

WORKDIR /app

COPY configs/pq-shield.yaml /etc/pq-shield/config.yaml

RUN mkdir -p /etc/pq-shield/certs && \
    chown -R pqshield:pqshield /app /etc/pq-shield

USER pqshield

EXPOSE 8443 9090

ENTRYPOINT ["/usr/local/bin/pq-shield"]
CMD ["-config", "/etc/pq-shield/config.yaml"]
