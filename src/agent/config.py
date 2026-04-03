"""
config.py — Agent Configuration (Pydantic v2)

Supports YAML config files + environment variable overrides.

Example YAML:
    bpf_object_path: src/bpf/http_capture.c
    ringbuf_size_mb: 256
    port_filter: [80, 443, 8080, 8443]
    outputs:
      - type: stdout
      - type: file
        path: /var/log/ebpf-agent/events.jsonl
      - type: kafka
        brokers: [localhost:9092]
        topic: http-events
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator


class StdoutOutputConfig(BaseModel):
    type: str = "stdout"
    pretty: bool = False


class FileOutputConfig(BaseModel):
    type: str = "file"
    path: str = "/var/log/ebpf-agent/events.jsonl"
    rotate_mb: int = 100
    max_files: int = 10
    compress: bool = True


class KafkaOutputConfig(BaseModel):
    type: str = "kafka"
    brokers: List[str] = ["localhost:9092"]
    topic: str = "http-events"
    batch_size: int = 1000
    linger_ms: int = 5


class PrometheusConfig(BaseModel):
    enabled: bool = True
    port: int = 9090
    path: str = "/metrics"


class AgentConfig(BaseModel):
    # BPF settings
    bpf_object_path: str = "src/bpf/http_capture.c"
    ringbuf_size_mb: int = Field(default=256, ge=64, le=2048)

    # Filters (empty list = capture everything)
    port_filter: List[int] = Field(default_factory=list)
    pid_filter:  List[int] = Field(default_factory=list)

    # Output configuration
    outputs: List[dict] = Field(
        default_factory=lambda: [{"type": "stdout"}]
    )

    # Prometheus metrics
    prometheus: PrometheusConfig = Field(default_factory=PrometheusConfig)

    # Processing
    max_body_capture_bytes: int = 4096
    parse_bodies: bool = True
    capture_headers: bool = True

    # Reliability
    event_queue_size: int = 100_000
    worker_threads: int = 4

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"   # "json" | "text"

    # ── Phase 0: SSL content capture ─────────────────────────────────────────
    capture_ssl_content: bool = True    # enable ssl_content.bpf.c probe
    ssl_max_capture_bytes: int = 65536  # max bytes per SSL event (64 KB)
    ssl_comm_filter: Optional[str] = None  # limit SSL capture to one comm name
    # Paths to binaries with statically-linked BoringSSL (Claude Code, Bun, NVM)
    ssl_binary_paths: List[str] = Field(default_factory=list)

    # ── Phase 0: Process/kernel monitoring ───────────────────────────────────
    capture_proc_events: bool = True    # enable process_monitor.bpf.c probe
    # Pre-seed with known agent PIDs; more can be added at runtime
    process_monitor_pids: List[int] = Field(default_factory=list)

    # ── Phase 0: Kafka envelope ───────────────────────────────────────────────
    kafka_topic: str = "api-events"
    kafka_brokers: str = "localhost:9092"
    agent_key: str = ""    # X-Agent-Key header value; loaded from env AGENT_KEY

    @classmethod
    def from_yaml(cls, path: str) -> "AgentConfig":
        config_path = Path(path)
        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        # Environment variable overrides (EBPF_AGENT_*)
        overrides = {
            k[11:].lower(): v
            for k, v in os.environ.items()
            if k.startswith("EBPF_AGENT_")
        }
        data.update(overrides)

        return cls(**data)

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Load config from environment variables only (no YAML)."""
        import os
        return cls(
            agent_key        = os.environ.get("AGENT_KEY", ""),
            kafka_topic      = os.environ.get("KAFKA_TOPIC", "api-events"),
            kafka_brokers    = os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            capture_ssl_content  = os.environ.get("CAPTURE_SSL", "true").lower() == "true",
            capture_proc_events  = os.environ.get("CAPTURE_PROC", "true").lower() == "true",
            capture_tls          = os.environ.get("CAPTURE_TLS", "true").lower() == "true",
            ssl_binary_paths = [
                p.strip() for p in
                os.environ.get("SSL_BINARY_PATHS", "").split(",")
                if p.strip()
            ],
            log_level        = os.environ.get("LOG_LEVEL", "INFO"),
        )

    def model_dump(self) -> dict:
        return {
            "bpf_object_path": self.bpf_object_path,
            "ringbuf_size_mb": self.ringbuf_size_mb,
            "port_filter":     self.port_filter,
            "pid_filter":      self.pid_filter,
            "outputs":         self.outputs,
            "prometheus":      self.prometheus.model_dump(),
        }