.PHONY: all build build-upstream test certs clean run benchmark benchmark-load pprof-cpu pprof-mem integration vet docker-up docker-down

BINARY      ?= pq-shield
MOCK_BINARY ?= mock-upstream
BIN_DIR     ?= bin
PKG         := ./...
CMD         := ./cmd/proxy
MOCK_CMD    := ./cmd/mock_upstream
GO          ?= go
GOFLAGS     ?=
LDFLAGS     := -s -w

BENCH_QPS   ?= 10000
BENCH_DUR   ?= 30s
BENCH_URL   ?= https://localhost:8443/
PPROF_ADDR  ?= localhost:9090

# OS Detection for binary extensions and path separators
ifeq ($(OS),Windows_NT)
	GOEXE       := .exe
	BINARY_PATH := ./$(BIN_DIR)/$(BINARY)$(GOEXE)
	MKDIR       := powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path"
	RM          := powershell -NoProfile -Command "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"
else
	GOEXE       :=
	BINARY_PATH := ./$(BIN_DIR)/$(BINARY)
	MKDIR       := mkdir -p
	RM          := rm -rf
endif

all: build

build:
	@$(MKDIR) $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY)$(GOEXE) $(CMD)

build-upstream:
	@$(MKDIR) $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(MOCK_BINARY)$(GOEXE) $(MOCK_CMD)

vet:
	$(GO) vet $(PKG)

test:
	$(GO) test -race -count=1 -timeout 60s $(PKG)

certs:
	@$(MKDIR) certs
	$(GO) run scripts/generate_certs.go -out ./certs -hosts "localhost,127.0.0.1,pq-shield" -days 365

run: build certs
	$(BINARY_PATH) -cert ./certs/server.crt -key ./certs/server.key -listen :8443 -metrics :9090 -upstream http://127.0.0.1:8080

integration: build certs
	@echo "=== Running PQC integration tests ==="
	@echo "Ensure pq-shield is running on :8443 before invoking this target."
	$(GO) run -tags integration scripts/test_pqc_client.go -target https://localhost:8443/healthz -ca ./certs/ca.crt -server-name localhost

benchmark-load:
	$(GO) run scripts/run_benchmark.go -url $(BENCH_URL) -qps $(BENCH_QPS) -duration $(BENCH_DUR)

benchmark: build certs benchmark-load

pprof-cpu:
	@echo "Capturing 30s CPU profile from $(PPROF_ADDR)"
	$(GO) tool pprof -http=:8081 http://$(PPROF_ADDR)/debug/pprof/profile?seconds=30

pprof-mem:
	@echo "Capturing heap profile from $(PPROF_ADDR)"
	$(GO) tool pprof -http=:8081 http://$(PPROF_ADDR)/debug/pprof/heap

clean:
	@$(RM) $(BIN_DIR) .pqshield.pid cpu.pprof mem.pprof *.exe

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down