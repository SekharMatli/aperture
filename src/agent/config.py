"""
config.py
=========
Agent configuration via YAML file + environment variable overrides.

All settings have sensible defaults so the agent can run with no config
file at all (useful for quick local testing).

Precedence (highest → lowest):
  1. CLI argument overrides (applied by __main__.py after loading config)
  2. EBPF_AGENT_* environment variables
  3. YAML config file values
  4. Built-in defaults (defined on each field)

Example YAML
------------
    bpf_object_path: src/bpf/http_capture.c
    ringbuf_size_mb: 256
    port_filter: [80, 443, 8080, 8443]
    pid_filter: []
    capture_tls: true

    outputs:
      - type: stdout
        pretty: false
      - type: file
        path: /var/log/ebpf-agent/events.jsonl
        rotate_mb: 200
        max_files: 10
        compress: true
      - type: kafka
        brokers: [kafka1:9092, kafka2:9092]
        topic: http-events
        linger_ms: 5

    prometheus:
      enabled: true
      port: 9090

    ssl:
      enabled: true
      lib_paths: []           # empty = auto-discover

    sweep_interval_s: 30
    connection_ttl_s: 300
    max_connections: 65536
    log_level: INFO
    log_format: json          # json | text
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# ─────────────────────────────────────────────────────────────────────────────
# Sub-configs
# ─────────────────────────────────────────────────────────────────────────────

class PrometheusConfig:
    __slots__ = ("enabled", "port", "path")

    def __init__(
        self,
        enabled: bool = True,
        port:    int  = 9090,
        path:    str  = "/metrics",
    ):
        self.enabled = enabled
        self.port    = port
        self.path    = path

    @classmethod
    def from_dict(cls, d: dict) -> "PrometheusConfig":
        return cls(
            enabled = bool(d.get("enabled", True)),
            port    = int(d.get("port", 9090)),
            path    = str(d.get("path", "/metrics")),
        )

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "port": self.port, "path": self.path}


class SSLConfig:
    __slots__ = ("enabled", "lib_paths")

    def __init__(
        self,
        enabled:   bool       = True,
        lib_paths: List[str]  = None,
    ):
        self.enabled   = enabled
        self.lib_paths = lib_paths or []

    @classmethod
    def from_dict(cls, d: dict) -> "SSLConfig":
        return cls(
            enabled   = bool(d.get("enabled", True)),
            lib_paths = list(d.get("lib_paths", [])),
        )

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "lib_paths": self.lib_paths}


# ─────────────────────────────────────────────────────────────────────────────
# AgentConfig
# ─────────────────────────────────────────────────────────────────────────────

class AgentConfig:
    """
    Central configuration object for the eBPF capture agent.

    Constructed via AgentConfig.from_yaml(path) or AgentConfig.from_dict(d).
    All attributes are plain Python types — no Pydantic dependency at runtime.

    Attributes
    ----------
    bpf_object_path : str
        Path to the BPF program. Supports .c (source, compiled by BCC at
        runtime) or .o (pre-compiled ELF, faster startup).

    ringbuf_size_mb : int
        Ring buffer size in MB. Must be a power of 2. Range: 64–2048.

    port_filter : list of int
        TCP ports to capture. Empty list = capture all ports.

    pid_filter : list of int
        PIDs to capture. Empty list = capture all processes.

    capture_tls : bool
        Attach SSL uprobes to capture plaintext for HTTPS/gRPC-TLS.
        Requires libssl.so to be accessible.

    outputs : list of dict
        Output backend configuration. Each dict requires a "type" key.
        See dispatcher.py for supported types and options.

    prometheus : PrometheusConfig
        Prometheus metrics HTTP server configuration.

    ssl : SSLConfig
        SSL/TLS uprobe configuration.

    sweep_interval_s : float
        How often ConnectionTracker.sweep_expired() runs, in seconds.

    connection_ttl_s : float
        Connections not seen for this many seconds are evicted from the
        connection tracker.

    max_connections : int
        Maximum simultaneous tracked connections (matches BPF map capacity).

    stats_interval_s : float
        How often agent-level stats are logged (events/sec, drops, etc.).

    log_level : str
        Logging verbosity: DEBUG, INFO, WARNING, ERROR.

    log_format : str
        "json" for structured JSON lines, "text" for human-readable format.
    """

    # Defaults
    _DEFAULTS: Dict[str, Any] = {
        "bpf_object_path":  "src/bpf/http_capture.c",
        "ringbuf_size_mb":  256,
        "port_filter":      [],
        "pid_filter":       [],
        "capture_tls":      True,
        "outputs":          [{"type": "stdout"}],
        "prometheus":       {},
        "ssl":              {},
        "sweep_interval_s": 30.0,
        "connection_ttl_s": 300.0,
        "max_connections":  65536,
        "stats_interval_s": 10.0,
        "log_level":        "INFO",
        "log_format":       "json",
    }

    def __init__(self, **kwargs: Any):
        # Apply defaults then overrides
        merged = dict(self._DEFAULTS)
        merged.update(kwargs)

        self.bpf_object_path:  str           = str(merged["bpf_object_path"])
        self.ringbuf_size_mb:  int           = self._clamp_power2(
            int(merged["ringbuf_size_mb"]), lo=64, hi=2048)
        self.port_filter:      List[int]     = [int(p) for p in merged["port_filter"]]
        self.pid_filter:       List[int]     = [int(p) for p in merged["pid_filter"]]
        self.capture_tls:      bool          = bool(merged["capture_tls"])
        self.outputs:          List[dict]    = list(merged["outputs"])
        self.sweep_interval_s: float         = float(merged["sweep_interval_s"])
        self.connection_ttl_s: float         = float(merged["connection_ttl_s"])
        self.max_connections:  int           = int(merged["max_connections"])
        self.stats_interval_s: float         = float(merged["stats_interval_s"])
        self.log_level:        str           = str(merged["log_level"]).upper()
        self.log_format:       str           = str(merged["log_format"]).lower()

        # Sub-configs
        prom_raw = merged["prometheus"]
        self.prometheus: PrometheusConfig = (
            prom_raw if isinstance(prom_raw, PrometheusConfig)
            else PrometheusConfig.from_dict(prom_raw if prom_raw else {})
        )
        ssl_raw = merged["ssl"]
        self.ssl: SSLConfig = (
            ssl_raw if isinstance(ssl_raw, SSLConfig)
            else SSLConfig.from_dict(ssl_raw if ssl_raw else {})
        )

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str) -> "AgentConfig":
        """
        Load config from a YAML file, then apply EBPF_AGENT_* env overrides.

        If the file does not exist, returns a default config — useful for
        running without any config file during development.

        Environment variable format:
            EBPF_AGENT_RINGBUF_SIZE_MB=512
            EBPF_AGENT_LOG_LEVEL=DEBUG
            EBPF_AGENT_PORT_FILTER=80,443,8080   (comma-separated for lists)
        """
        config_path = Path(path)
        data: Dict[str, Any] = {}

        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        else:
            import sys
            print(
                f"[config] {path!r} not found — using defaults. "
                "Create a config file or set EBPF_AGENT_* env vars.",
                file=sys.stderr,
            )

        # Environment variable overrides
        for key, val in os.environ.items():
            if not key.startswith("EBPF_AGENT_"):
                continue
            field_name = key[len("EBPF_AGENT_"):].lower()
            # Convert comma-separated env vars to lists for list fields
            if field_name in ("port_filter", "pid_filter"):
                data[field_name] = [int(x) for x in val.split(",") if x.strip()]
            else:
                data[field_name] = val

        return cls(**data)

    @classmethod
    def from_dict(cls, d: dict) -> "AgentConfig":
        """Construct from a plain dict (e.g. from tests)."""
        return cls(**d)

    # ── Validation helpers ────────────────────────────────────────────────────

    @staticmethod
    def _clamp_power2(value: int, lo: int, hi: int) -> int:
        """
        Clamp value to [lo, hi] and round up to the nearest power of 2.
        Ring buffer size must be a power of 2 (kernel requirement).
        """
        value = max(lo, min(hi, value))
        # Round up to nearest power of 2
        p = 1
        while p < value:
            p <<= 1
        return p

    def validate(self) -> List[str]:
        """
        Return a list of validation error strings.
        Empty list = config is valid.
        """
        errors = []

        path = Path(self.bpf_object_path)
        if not path.exists():
            errors.append(f"bpf_object_path not found: {path}")

        if not (64 <= self.ringbuf_size_mb <= 2048):
            errors.append(
                f"ringbuf_size_mb={self.ringbuf_size_mb} out of range [64, 2048]"
            )

        for port in self.port_filter:
            if not (1 <= port <= 65535):
                errors.append(f"invalid port in port_filter: {port}")

        if self.connection_ttl_s <= 0:
            errors.append(f"connection_ttl_s must be > 0, got {self.connection_ttl_s}")

        if self.max_connections < 1024:
            errors.append(
                f"max_connections={self.max_connections} is very low (minimum 1024)"
            )

        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            errors.append(f"invalid log_level: {self.log_level!r}")

        if self.log_format not in ("json", "text"):
            errors.append(f"log_format must be 'json' or 'text', got {self.log_format!r}")

        return errors

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "bpf_object_path":  self.bpf_object_path,
            "ringbuf_size_mb":  self.ringbuf_size_mb,
            "port_filter":      self.port_filter,
            "pid_filter":       self.pid_filter,
            "capture_tls":      self.capture_tls,
            "outputs":          self.outputs,
            "prometheus":       self.prometheus.to_dict(),
            "ssl":              self.ssl.to_dict(),
            "sweep_interval_s": self.sweep_interval_s,
            "connection_ttl_s": self.connection_ttl_s,
            "max_connections":  self.max_connections,
            "stats_interval_s": self.stats_interval_s,
            "log_level":        self.log_level,
            "log_format":       self.log_format,
        }

    def __repr__(self) -> str:
        return (
            f"AgentConfig(bpf={self.bpf_object_path!r}, "
            f"ringbuf={self.ringbuf_size_mb}MB, "
            f"ports={self.port_filter or 'all'}, "
            f"tls={self.capture_tls})"
        )