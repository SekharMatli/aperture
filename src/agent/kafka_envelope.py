"""
src/agent/kafka_envelope.py
=============================
Versioned Kafka message envelope for the eBPF agent.

Schema versioning
-----------------
Every Kafka message carries a schema_version header so the consumer can
detect and handle format changes without breaking on old messages.

    version 1 (original):
        HTTP/gRPC/MCP events from http_capture.bpf.c
        Top-level keys: timestamp_ns, conn_id, pid, comm, src_ip,
                        dst_port, protocol, direction, http1|http2|grpc|mcp

    version 2 (Phase 0):
        All v1 events PLUS two new top-level keys:
          ssl_content: {...}   — from ssl_content.bpf.c
          proc_event:  {...}   — from process_monitor.bpf.c
        Backward compatible: consumers that don't know version 2 ignore
        the new keys and process the existing keys as before.

Kafka headers on every message
-------------------------------
    X-Agent-Key:      <agent key string>        (required by consumer)
    X-Schema-Version: 1 | 2                     (new in Phase 0)
    X-Event-Kind:     http | ssl | proc | combined
    X-Root-Pid:       <int>                     (for correlation)

KafkaEnvelope wraps both the existing KafkaSink from output.py and the
two new probe classes so all three streams share a single Kafka producer.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Current schema version
SCHEMA_VERSION = "2"


def _build_headers(
    agent_key: str,
    event_kind: str,
    root_pid: int = 0,
) -> list:
    """Build Kafka message header list."""
    return [
        ("X-Agent-Key",      agent_key.encode("utf-8")),
        ("X-Schema-Version", SCHEMA_VERSION.encode("utf-8")),
        ("X-Event-Kind",     event_kind.encode("utf-8")),
        ("X-Root-Pid",       str(root_pid).encode("utf-8")),
    ]


class KafkaEnvelope:
    """
    Single Kafka producer that handles all three event streams:
      1. HTTP/gRPC/MCP events (existing, schema v1 compatible)
      2. SSL content events (new, schema v2)
      3. Process/kernel events (new, schema v2)

    All three streams go to the same Kafka topic so the consumer sees
    them in arrival order and can correlate by root_pid.

    Thread safety: write() is safe to call from multiple threads.
    The internal queue serialises Kafka produce calls.
    """

    def __init__(
        self,
        topic:       str,
        brokers:     str,
        agent_key:   str,
        queue_depth: int = 200_000,
    ) -> None:
        try:
            from confluent_kafka import Producer
        except ImportError:
            raise RuntimeError(
                "confluent-kafka not installed — run: pip install confluent-kafka"
            )

        self.topic     = topic
        self.agent_key = agent_key

        self._queue: queue.Queue[Optional[tuple]] = queue.Queue(maxsize=queue_depth)
        self._producer = Producer({
            "bootstrap.servers": brokers,
            "linger.ms":         5,
            "compression.type":  "lz4",
            "acks":              "1",
            "batch.num.messages": 10_000,
        })
        self._thread = threading.Thread(
            target=self._drain,
            name="kafka-envelope",
            daemon=True,
        )
        self._dropped    = 0
        self._produced   = 0
        self._thread.start()
        logger.info("KafkaEnvelope ready topic=%s brokers=%s", topic, brokers)

    # ── Public write methods ──────────────────────────────────────────────────

    def write_http(self, payload: dict, root_pid: int = 0) -> None:
        """Write an HTTP/gRPC/MCP event (v1 compatible)."""
        self._enqueue(payload, "http", root_pid)

    def write_ssl(self, payload: dict, root_pid: int = 0) -> None:
        """Write an SSL content event (v2)."""
        self._enqueue(payload, "ssl", root_pid)

    def write_proc(self, payload: dict, root_pid: int = 0) -> None:
        """Write a process/kernel event (v2)."""
        self._enqueue(payload, "proc", root_pid)

    def flush(self, timeout_s: float = 10.0) -> None:
        self._queue.put(None)   # sentinel
        self._thread.join(timeout=timeout_s)
        self._producer.flush(timeout=timeout_s)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _enqueue(self, payload: dict, kind: str, root_pid: int) -> None:
        item = (payload, kind, root_pid)
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            self._dropped += 1
            if self._dropped % 1000 == 1:
                logger.warning(
                    "KafkaEnvelope queue full — dropped %d events so far",
                    self._dropped,
                )

    def _drain(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                break
            payload, kind, root_pid = item
            try:
                headers = _build_headers(self.agent_key, kind, root_pid)
                value   = json.dumps(payload, default=str).encode("utf-8")
                key     = str(payload.get("conn_id", "")).encode("utf-8")

                self._producer.produce(
                    topic    = self.topic,
                    key      = key,
                    value    = value,
                    headers  = headers,
                    callback = self._on_delivery,
                )
                self._producer.poll(0)
                self._produced += 1
            except Exception as exc:
                logger.warning("KafkaEnvelope produce error: %s", exc)

    def _on_delivery(self, err, msg) -> None:
        if err:
            logger.debug("KafkaEnvelope delivery failed: %s", err)