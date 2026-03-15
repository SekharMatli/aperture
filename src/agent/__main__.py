#!/usr/bin/env python3
"""
eBPF HTTP capture agent — entry point
======================================
Usage:
    sudo python -m src.agent [options]
    sudo python -m src.agent --config /etc/ebpf-agent/config.yaml
    sudo python -m src.agent --ports 80,443,8080 --output-file /tmp/events.jsonl

All CLI flags override config-file values.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys


# ─────────────────────────────────────────────────────────────────────────────
# Pre-flight checks (run before any heavy imports)
# ─────────────────────────────────────────────────────────────────────────────

def _check_root() -> None:
    if os.geteuid() != 0:
        print(
            "ERROR: eBPF requires root or CAP_BPF + CAP_PERFMON.\n"
            "  Run: sudo python -m src.agent",
            file=sys.stderr,
        )
        sys.exit(1)


def _check_kernel() -> None:
    import platform
    release = platform.release()
    parts   = release.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1].split("-")[0])
    except (IndexError, ValueError):
        return  # Can't parse — proceed anyway

    if (major, minor) < (5, 8):
        print(
            f"WARNING: Kernel {release} — BPF ring buffer requires Linux 5.8+.\n"
            "  Ring buffer (BPF_MAP_TYPE_RINGBUF) is not available.\n"
            "  Upgrade your kernel or use BPF_MAP_TYPE_PERF_EVENT_ARRAY instead.",
            file=sys.stderr,
        )


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "ebpf-agent",
        description = "eBPF HTTP/gRPC/MCP capture agent — zero packet loss via ring buffer",
        formatter_class = argparse.ArgumentDefaultsHelpFormatter,
        epilog      = "Full documentation: https://github.com/your-org/ebpf-agent",
    )

    # Config
    p.add_argument("--config", "-c", metavar="FILE",
                   help="YAML config file path")

    # Capture filters
    p.add_argument("--ports", "-p", metavar="PORTS",
                   help="Comma-separated TCP ports to monitor (e.g. 80,443,8080). "
                        "Default: all ports")
    p.add_argument("--pid", "-P", type=int, metavar="PID",
                   help="Capture only traffic from this process ID")
    p.add_argument("--no-tls", action="store_true",
                   help="Disable SSL/TLS uprobes (OpenSSL plaintext capture)")

    # Ring buffer
    p.add_argument("--ringbuf-mb", type=int, metavar="MB",
                   help="Ring buffer size in MB (power of 2, 64–2048)")

    # Output
    p.add_argument("--output-file", "-f", metavar="FILE",
                   help="Write JSONL events to this file (in addition to stdout)")
    p.add_argument("--pretty", action="store_true",
                   help="Pretty-print JSON to stdout")
    p.add_argument("--no-stdout", action="store_true",
                   help="Suppress stdout output (useful when writing to file/Kafka)")

    # Kafka
    p.add_argument("--kafka-brokers", metavar="BROKERS",
                   help="Kafka broker addresses (e.g. kafka1:9092,kafka2:9092)")
    p.add_argument("--kafka-topic", metavar="TOPIC",
                   help="Kafka topic to publish events to")

    # Prometheus
    p.add_argument("--prometheus-port", type=int, metavar="PORT",
                   help="Expose Prometheus /metrics on this port (0 = disabled)")

    # Debugging
    p.add_argument("--log-level", choices=["DEBUG","INFO","WARNING","ERROR"],
                   default="INFO", help="Log verbosity")
    p.add_argument("--log-format", choices=["json","text"], default="json",
                   help="Log output format")
    p.add_argument("--stats-interval", type=float, metavar="SECONDS", default=10.0,
                   help="How often to log agent statistics")

    return p


# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging(level: str, fmt: str) -> None:
    """
    Configure structlog for the agent process.

    json format  → one JSON object per line (for log aggregators)
    text format  → human-readable with timestamps (for terminals)
    """
    import structlog

    level_int = getattr(logging, level, logging.INFO)

    # stdlib root logger (captures third-party lib logs)
    logging.basicConfig(
        stream  = sys.stderr,
        level   = level_int,
        format  = "%(asctime)s %(levelname)-7s %(name)s — %(message)s",
        datefmt = "%H:%M:%S",
    )

    if fmt == "json":
        processors = [
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        processors = [
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="%H:%M:%S"),
            structlog.dev.ConsoleRenderer(),
        ]

    structlog.configure(
        processors          = processors,
        wrapper_class       = structlog.BoundLogger,
        context_class       = dict,
        logger_factory      = structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use = True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Output config builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_outputs(args: argparse.Namespace, base_outputs: list) -> list:
    """
    Merge config-file outputs with CLI overrides.

    CLI flags add outputs; --no-stdout removes the default stdout output.
    """
    outputs = list(base_outputs)

    # Remove stdout if --no-stdout specified
    if args.no_stdout:
        outputs = [o for o in outputs if o.get("type") != "stdout"]

    # If no stdout output present and --no-stdout not given, add one
    has_stdout = any(o.get("type") == "stdout" for o in outputs)
    if not has_stdout and not args.no_stdout:
        outputs.insert(0, {"type": "stdout", "pretty": args.pretty})
    elif has_stdout and args.pretty:
        # Apply --pretty to the existing stdout config
        for o in outputs:
            if o.get("type") == "stdout":
                o["pretty"] = True

    # --output-file adds a file output
    if args.output_file:
        outputs.append({
            "type":      "file",
            "path":      args.output_file,
            "rotate_mb": 200,
            "compress":  True,
        })

    # --kafka-brokers + --kafka-topic adds a Kafka output
    if args.kafka_brokers and args.kafka_topic:
        outputs.append({
            "type":    "kafka",
            "brokers": [b.strip() for b in args.kafka_brokers.split(",")],
            "topic":   args.kafka_topic,
        })

    return outputs


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    _check_root()
    _check_kernel()

    args = build_parser().parse_args()
    _setup_logging(args.log_level, args.log_format)

    # Import heavy modules after logging is configured
    from src.agent.config     import AgentConfig
    from src.agent.ebpf_agent import EBPFAgent

    # Load config (file or defaults)
    if args.config:
        config = AgentConfig.from_yaml(args.config)
    else:
        config = AgentConfig()

    # Apply CLI overrides
    if args.ports:
        config.port_filter = [int(p.strip()) for p in args.ports.split(",")]
    if args.pid:
        config.pid_filter = [args.pid]
    if args.no_tls:
        config.capture_tls = False
    if args.ringbuf_mb:
        config.ringbuf_size_mb = args.ringbuf_mb
    if args.prometheus_port is not None:
        config.prometheus.enabled = args.prometheus_port > 0
        if args.prometheus_port > 0:
            config.prometheus.port = args.prometheus_port
    if args.stats_interval:
        config.stats_interval_s = args.stats_interval

    config.log_level  = args.log_level
    config.log_format = args.log_format

    # Merge output configs
    config.outputs = _build_outputs(args, config.outputs)

    # Validate early for clear error messages
    errors = config.validate()
    if errors:
        for err in errors:
            print(f"[config] ERROR: {err}", file=sys.stderr)
        sys.exit(1)

    import structlog
    log = structlog.get_logger("main")
    log.info("agent.config_loaded", **config.to_dict())

    # Start agent (blocks until SIGINT/SIGTERM)
    agent = EBPFAgent(config)
    try:
        agent.start()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log.error("agent.fatal_error", error=str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()