# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install Python dependencies (uses uv)
uv sync

# Run the agent (requires root or CAP_BPF + CAP_SYS_ADMIN + CAP_NET_ADMIN)
sudo python -m src.agent
sudo python -m src.agent --config config/config-dev.yaml
sudo python -m src.agent --ports 80,443,8080 --output json --show-headers

# Build BPF object from C source (requires clang + kernel headers)
make vmlinux bpf

# Prometheus metrics
sudo python -m src.agent --prometheus-port 9090
curl http://localhost:9090/metrics
```

## Architecture

The agent captures HTTP/HTTPS traffic with zero packet loss using a two-tier pipeline:

**Kernel space** (`src/bpf/http_capture.c`): eBPF program attached via kprobes (`tcp_sendmsg`, `tcp_recvmsg`, `tcp_close`) and uprobes (`SSL_write`, `SSL_read`). Performs cheap first-pass protocol heuristics on the first ~200 bytes and writes events into a **BPF ring buffer** (64–512 MB). The kernel never blocks — drops are counted and surfaced via Prometheus.

**User space** (`src/agent/`, `src/processors/`, `src/output/`): A tight `ring_buffer_poll()` loop (100ms timeout) in `EBPFAgent` reads events, casts them via ctypes structs, and fans them out to output backends. No GIL-holding I/O on the hot path.

### Key components

| Component | File | Role |
|-----------|------|------|
| `EBPFAgent` | `src/agent/ebpf_agent.py` | Main orchestrator: startup, poll loop, signal handling, shutdown |
| `BPFLoader` | `src/agent/bpf_loader.py` | Loads `.c` (JIT) or `.o` (precompiled) BPF, attaches probes, manages ring buffer |
| `SSLProbeManager` | `src/agent/ssl_probe.py` | Attaches uprobes to `libssl.so` for plaintext TLS capture before encryption |
| `ConnectionTracker` | `src/processors/conn_tracker.py` | LRU-bounded (65K max) per-connection state with TTL eviction |
| `ProtocolDetector` | `src/processors/protocol_detector.py` | Stateful refinement of kernel hints → HTTP/1.x, HTTP/2, gRPC, WebSocket, MCP, TLS |
| `HTTPParser` | `src/processors/http_parser.py` | Converts raw bytes to `ParsedEvent`; infers JSON schema shape (not values) for OpenAPI spec generation |
| `EventDispatcher` | `src/output/dispatcher.py` | Fan-out to stdout / rotating file / Kafka / webhook backends with per-output filters |
| `MetricsServer` | `src/agent/metrics.py` | Prometheus `/metrics` on configurable port |
| `AgentConfig` | `src/agent/config.py` | YAML + env var config loader; CLI flags override config file |
| ctypes structs | `src/agent/event_types.py` | Mirrors of kernel-side C structs (`EventHeaderCT`, `ConnTupleCT`), `RawEvent` / `EventMeta` dataclasses |

### Protocol detection (two-tier)

1. **Kernel-side** (`http_capture.c`): heuristics on first bytes filter irrelevant traffic before ring buffer write
2. **User-side** (`ProtocolDetector`): stateful refinement across multiple packets (HTTP/1 pipelining, HTTP/2 stream state machine)

### Output backends

All output backends run async (daemon threads) and never block the main poll loop:
- `StdoutOutput` — JSON or pretty-printed text
- `FileOutput` — rotating NDJSON with optional gzip
- `KafkaOutput` — async producer, lz4 batching, keyed by `conn_id` for per-connection ordering
- `WebhookOutput` — HTTP POST with retry

### Configuration

Three environment configs in `config/`:
- `config-dev.yaml` — 64 MB ring buffer, stdout only, DEBUG logging, Prometheus disabled
- `config-staging.yaml` — staging settings
- `config-prod.yaml` — 512 MB ring buffer, Kafka + rotating file output, WARNING logging, Prometheus on 9090

### System requirements

- Linux kernel 5.8+ (BPF ring buffer API)
- BCC / libbpf 0.24+
- Clang 12+ (for BPF compilation)
- Root or `CAP_BPF + CAP_SYS_ADMIN + CAP_NET_ADMIN`
- TLS capture requires `libssl.so` (OpenSSL); does **not** work with Go stdlib TLS or Rust `rustls`

### `http_parser.py` design note

The parser extracts field names, data types, and nesting from HTTP bodies — **not values** — to enable OpenAPI spec generation from live traffic without capturing sensitive data.