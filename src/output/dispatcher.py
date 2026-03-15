"""
Fan-out to stdout, rotating JSONL files, Kafka (async batched), or webhooks.
"""
"""
dispatcher.py
=============
Routes ParsedEvent objects to one or more output backends.

Backends
--------
  StdoutOutput   — JSON or pretty-printed to stdout (dev / pipe)
  FileOutput     — rotating JSONL files with optional gzip compression
  KafkaOutput    — async producer with lz4 batching (confluent-kafka)
  WebhookOutput  — HTTP POST with retry and in-memory queue

Filtering
---------
Each output can specify an independent filter so different backends
receive different subsets of traffic:

  filter:
    protocols:   [HTTP1, GRPC, MCP]   # whitelist by protocol name
    ports:       [80, 443, 8080]       # dst_port match
    parse_errors: false                # drop events with parse errors
    min_body_bytes: 0                  # skip tiny bodies

Global filters (applied before routing) live on EventDispatcher itself.

Statistics
----------
EventDispatcher.stats() returns per-output and aggregate counters:
  dispatched, filtered, errors, bytes_written (where tracked)

Architecture
------------
  RawEvent
    → ProtocolDetector.detect()   [protocol_detector.py]
    → HTTPParser.parse()          [http_parser.py]
    → EventDispatcher.dispatch()  [this file]
         ├── StdoutOutput.write()
         ├── FileOutput.write()
         ├── KafkaOutput.write()
         └── WebhookOutput.write()

Thread safety
-------------
dispatch() is called from the ring buffer poll loop (single thread).
FileOutput uses a threading.Lock for rotation safety.
KafkaOutput's producer is itself thread-safe.
WebhookOutput spawns daemon threads per POST (fire-and-forget).

All output errors are logged and swallowed — one failing backend must
never block events from reaching the others.
"""

from __future__ import annotations

import gzip
import json
import os
import queue
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import structlog

from src.agent.event_types import Protocol
from src.processors.http_parser import ParsedEvent

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Output filter
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OutputFilter:
    """
    Predicate applied to a ParsedEvent before writing to one output.

    All specified conditions must pass (AND logic).
    Unset conditions are not checked (pass-through).

    Parameters
    ----------
    protocols : set of str, optional
        Whitelist of protocol display names, e.g. {"HTTP/1.x", "gRPC", "MCP"}.
        If empty or None, all protocols pass.

    ports : set of int, optional
        Whitelist of destination port numbers.
        If empty or None, all ports pass.

    directions : set of str, optional
        {"EGRESS", "INGRESS", "CLOSE"} — filter by traffic direction.

    drop_parse_errors : bool
        If True, events with parse_error set are dropped.

    drop_tls_only : bool
        If True, events whose only information is TLS record metadata
        (no application-layer visibility) are dropped.

    min_body_bytes : int
        Drop HTTP/1.x or gRPC events where the body is shorter than this.
        0 = no minimum.
    """
    protocols:        Optional[Set[str]] = None
    ports:            Optional[Set[int]] = None
    directions:       Optional[Set[str]] = None
    drop_parse_errors: bool              = False
    drop_tls_only:    bool               = False
    min_body_bytes:   int                = 0

    @classmethod
    def from_dict(cls, d: dict) -> "OutputFilter":
        """Construct from a plain dict (e.g. from YAML config)."""
        protocols = None
        if d.get("protocols"):
            # Accept both display names ("HTTP/1.x") and enum names ("HTTP1")
            protocols = set()
            for p in d["protocols"]:
                # Normalise: try looking up by enum name, fall back to raw
                try:
                    protocols.add(Protocol[p].display_name)
                except KeyError:
                    protocols.add(p)

        ports = set(d["ports"]) if d.get("ports") else None
        dirs  = set(str(x).upper() for x in d["directions"]) \
                if d.get("directions") else None

        return cls(
            protocols        = protocols,
            ports            = ports,
            directions       = dirs,
            drop_parse_errors = bool(d.get("drop_parse_errors", False)),
            drop_tls_only    = bool(d.get("drop_tls_only", False)),
            min_body_bytes   = int(d.get("min_body_bytes", 0)),
        )

    def passes(self, event: ParsedEvent) -> bool:
        """
        Return True if event passes all filter conditions.

        Called once per (event, output) pair on the hot path.
        Short-circuit order: cheapest checks first.
        """
        meta = event.meta

        # Parse error gate
        if self.drop_parse_errors and event.parse_error:
            return False

        # TLS-only gate (encrypted, no app-layer data)
        if self.drop_tls_only and event.tls and not event.http1 \
                and not event.http2 and not event.grpc \
                and not event.ws and not event.mcp:
            return False

        # Protocol filter
        if self.protocols:
            if meta.protocol.display_name not in self.protocols:
                return False

        # Port filter
        if self.ports:
            if meta.dst_port not in self.ports and meta.src_port not in self.ports:
                return False

        # Direction filter
        if self.directions:
            if meta.direction.name not in self.directions:
                return False

        # Body size filter
        # Only applied when body length is known; unknown-length events pass through.
        if self.min_body_bytes > 0:
            known_body_len: Optional[int] = None
            if event.http1:
                known_body_len = event.http1.body_len
            elif event.grpc and event.grpc.message_len is not None:
                known_body_len = event.grpc.message_len
            # If body length is unknown (e.g. gRPC HEADERS frame, WS, MCP),
            # do not filter — we cannot confidently say the body is too small.
            if known_body_len is not None and known_body_len < self.min_body_bytes:
                return False

        return True


# ─────────────────────────────────────────────────────────────────────────────
# Per-output stats
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OutputStats:
    """Counters for one output backend. All fields are monotonically increasing."""
    written:       int = 0   # events successfully written
    filtered:      int = 0   # events dropped by OutputFilter
    errors:        int = 0   # write/flush errors
    bytes_written: int = 0   # approximate serialised bytes (where tracked)

    def to_dict(self) -> dict:
        return {
            "written":       self.written,
            "filtered":      self.filtered,
            "errors":        self.errors,
            "bytes_written": self.bytes_written,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Base output interface
# ─────────────────────────────────────────────────────────────────────────────

class BaseOutput(ABC):
    """
    Abstract base for all output backends.

    Subclasses implement _write_event(event, payload) where payload is
    the pre-serialised bytes. BaseOutput handles filtering, stats, and
    error isolation so subclasses stay simple.

    Subclass contract
    -----------------
    - Implement _write_event(event, payload_bytes) → None
    - Optionally override flush() and close()
    - Do not suppress exceptions from _write_event — BaseOutput does that
    """

    def __init__(
        self,
        output_filter: Optional[OutputFilter] = None,
        include_detection: bool               = False,
        name: str                             = "",
    ):
        self._filter            = output_filter
        self._include_detection = include_detection
        self._name              = name or type(self).__name__
        self.stats              = OutputStats()

    def write(self, event: ParsedEvent) -> None:
        """
        Filter, serialise, and deliver one event.

        Called by EventDispatcher for every dispatched event.
        Never raises — errors increment stats.errors and are logged.
        """
        # Apply output-level filter
        if self._filter and not self._filter.passes(event):
            self.stats.filtered += 1
            return

        # Serialise once here so subclasses don't have to
        try:
            payload = json.dumps(
                event.to_dict(include_detection=self._include_detection),
                default=str,
            ).encode("utf-8")
        except Exception as exc:
            logger.warning("output.serialise_error",
                           output=self._name, error=str(exc))
            self.stats.errors += 1
            return

        try:
            self._write_event(event, payload)
            self.stats.written       += 1
            self.stats.bytes_written += len(payload)
        except Exception as exc:
            logger.warning("output.write_error",
                           output=self._name, error=str(exc))
            self.stats.errors += 1

    @abstractmethod
    def _write_event(self, event: ParsedEvent, payload: bytes) -> None:
        """Deliver one serialised event. May raise — caller handles."""

    def flush(self) -> None:
        """Flush any internal buffers. Default: no-op."""

    def close(self) -> None:
        """Release resources. Default: no-op."""

    def health(self) -> dict:
        """Return a health snapshot for this output."""
        return {
            "name":  self._name,
            "stats": self.stats.to_dict(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# StdoutOutput
# ─────────────────────────────────────────────────────────────────────────────

class StdoutOutput(BaseOutput):
    """
    Write events as JSON lines to stdout.

    Parameters
    ----------
    pretty : bool
        If True, emit indented JSON (2 spaces). Good for human reading;
        breaks downstream line-by-line parsers. Default: False.

    color : bool
        If True and stdout is a TTY, colorise protocol names and status
        codes using ANSI escape codes. Default: True.
    """

    # ANSI colors for protocol labels
    _COLORS = {
        "HTTP/1.x": "\033[32m",   # green
        "HTTP/2":   "\033[34m",   # blue
        "gRPC":     "\033[35m",   # magenta
        "WebSocket":"\033[33m",   # yellow
        "MCP":      "\033[36m",   # cyan
        "TLS":      "\033[90m",   # dark grey
        "UNKNOWN":  "\033[37m",   # light grey
    }
    _RESET = "\033[0m"

    def __init__(
        self,
        pretty:           bool                    = False,
        color:            bool                    = True,
        output_filter:    Optional[OutputFilter]  = None,
        include_detection: bool                   = False,
    ):
        super().__init__(output_filter, include_detection, name="stdout")
        self._pretty = pretty
        self._color  = color and sys.stdout.isatty()

    def _write_event(self, event: ParsedEvent, payload: bytes) -> None:
        if self._pretty:
            # Re-decode for indented output (small overhead, pretty-only path)
            obj  = json.loads(payload)
            line = json.dumps(obj, indent=2, default=str)
        else:
            line = payload.decode("utf-8")

        if self._color:
            proto_name = event.meta.protocol.display_name
            color      = self._COLORS.get(proto_name, "")
            line       = f"{color}{line}{self._RESET}"

        sys.stdout.write(line + "\n")
        sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────────────────
# FileOutput
# ─────────────────────────────────────────────────────────────────────────────

class FileOutput(BaseOutput):
    """
    Write events as newline-delimited JSON to rotating log files.

    Rotation triggers when the active file exceeds rotate_mb megabytes.
    When max_files is reached the oldest backup is deleted. If compress
    is True, closed backup files are gzip-compressed asynchronously.

    Thread safety: a threading.Lock protects all file operations so
    this output is safe if dispatch() is ever called from multiple threads.

    Parameters
    ----------
    path : str
        Path to the active log file (e.g. /var/log/ebpf/events.jsonl).

    rotate_mb : int
        Rotate when the active file exceeds this many megabytes. Default: 100.

    max_files : int
        Maximum number of backup files to keep (not counting the active one).
        Default: 10.

    compress : bool
        If True, compress backup files to .gz after rotation. Default: True.
    """

    def __init__(
        self,
        path:             str,
        rotate_mb:        int                    = 100,
        max_files:        int                    = 10,
        compress:         bool                   = True,
        output_filter:    Optional[OutputFilter] = None,
        include_detection: bool                  = False,
    ):
        super().__init__(output_filter, include_detection, name=f"file:{path}")
        self._path       = Path(path)
        self._rotate_bytes = rotate_mb * 1024 * 1024
        self._max_files  = max_files
        self._compress   = compress
        self._lock       = threading.Lock()
        self._fh         = None
        self._current_size = 0

        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._open_file()
        logger.info("file_output.initialized",
                    path=str(self._path),
                    rotate_mb=rotate_mb,
                    max_files=max_files,
                    compress=compress)

    def _open_file(self) -> None:
        """Open the active log file for append."""
        self._fh = open(self._path, "ab")
        self._current_size = self._path.stat().st_size if self._path.exists() else 0

    def _write_event(self, event: ParsedEvent, payload: bytes) -> None:
        line = payload + b"\n"
        with self._lock:
            self._fh.write(line)
            self._current_size += len(line)
            if self._current_size >= self._rotate_bytes:
                self._rotate()

    def _rotate(self) -> None:
        """
        Rotate the active file. Must be called with self._lock held.

        Rotation sequence:
          1. Close active file.
          2. Rename: events.jsonl → events.jsonl.1
             Rename: events.jsonl.1 → events.jsonl.2  (etc.)
          3. Delete oldest backup if > max_files.
          4. Open new active file.
          5. Optionally compress the just-rotated backup asynchronously.
        """
        self._fh.close()

        # Shift existing backups: .N → .(N+1)
        for i in range(self._max_files - 1, 0, -1):
            src = self._path.with_suffix(f"{self._path.suffix}.{i}")
            # Also handle compressed backups
            src_gz = src.with_suffix(src.suffix + ".gz")
            dst = self._path.with_suffix(f"{self._path.suffix}.{i+1}")
            dst_gz = dst.with_suffix(dst.suffix + ".gz")
            if src.exists():
                src.rename(dst)
            elif src_gz.exists():
                src_gz.rename(dst_gz)

        # Active → .1
        rotated = self._path.with_suffix(f"{self._path.suffix}.1")
        self._path.rename(rotated)

        # Delete oldest if over limit
        oldest = self._path.with_suffix(f"{self._path.suffix}.{self._max_files + 1}")
        oldest_gz = oldest.with_suffix(oldest.suffix + ".gz")
        for old in (oldest, oldest_gz):
            if old.exists():
                old.unlink()
                logger.debug("file_output.deleted_oldest", path=str(old))

        self._open_file()
        logger.info("file_output.rotated",
                    active=str(self._path),
                    backup=str(rotated))

        if self._compress:
            # Compress the rotated backup on a daemon thread
            t = threading.Thread(
                target=_gzip_file,
                args=(rotated,),
                daemon=True,
                name=f"file-compress-{rotated.name}",
            )
            t.start()

    def flush(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.flush()
                self._fh.close()
                self._fh = None
        logger.info("file_output.closed", path=str(self._path))


# ─────────────────────────────────────────────────────────────────────────────
# KafkaOutput
# ─────────────────────────────────────────────────────────────────────────────

class KafkaOutput(BaseOutput):
    """
    Async Kafka producer using confluent-kafka.

    Events are produced to `topic` with the conn_id as the partition key
    so all packets from the same connection land on the same partition,
    preserving ordering for downstream consumers.

    Parameters
    ----------
    brokers : list of str
        Bootstrap server addresses, e.g. ["kafka1:9092", "kafka2:9092"].

    topic : str
        Kafka topic name.

    batch_size : int
        Max messages to batch before forcing a send. Default: 1000.

    linger_ms : int
        Producer linger time in milliseconds. Trades latency for throughput.
        Default: 5 ms.

    compression : str
        Compression codec: "none", "lz4", "snappy", "gzip", "zstd".
        Default: "lz4" (best speed/ratio trade-off for JSON).

    If confluent-kafka is not installed, KafkaOutput degrades to a no-op
    and logs a warning — the agent continues without Kafka support.
    """

    def __init__(
        self,
        brokers:          List[str],
        topic:            str,
        batch_size:       int                    = 1000,
        linger_ms:        int                    = 5,
        compression:      str                    = "lz4",
        output_filter:    Optional[OutputFilter] = None,
        include_detection: bool                  = False,
    ):
        super().__init__(output_filter, include_detection, name=f"kafka:{topic}")
        self._topic    = topic
        self._producer = None

        try:
            from confluent_kafka import Producer  # type: ignore
            self._producer = Producer({
                "bootstrap.servers":  ",".join(brokers),
                "batch.num.messages": batch_size,
                "linger.ms":          linger_ms,
                "compression.type":   compression,
                "acks":               "1",
                # Delivery timeouts: be generous for transient broker issues
                "message.timeout.ms": 30_000,
                "retries":            3,
            })
            logger.info("kafka_output.connected",
                        brokers=brokers, topic=topic,
                        compression=compression, linger_ms=linger_ms)
        except ImportError:
            logger.warning(
                "kafka_output.unavailable",
                msg="confluent-kafka not installed. "
                    "Install with: pip install confluent-kafka",
            )

    def _write_event(self, event: ParsedEvent, payload: bytes) -> None:
        if not self._producer:
            return

        # Partition key: hex conn_id → events from same connection are ordered
        key = f"{event.meta.conn_id:016x}".encode()

        self._producer.produce(
            topic       = self._topic,
            key         = key,
            value       = payload,
            on_delivery = self._on_delivery,
        )
        # Non-blocking poll — triggers delivery callbacks without waiting
        self._producer.poll(0)

    def _on_delivery(self, err: Any, msg: Any) -> None:
        if err:
            self.stats.errors += 1
            logger.error("kafka_output.delivery_failed",
                         topic=self._topic, error=str(err))

    def flush(self) -> None:
        if self._producer:
            remaining = self._producer.flush(timeout=10.0)
            if remaining > 0:
                logger.warning("kafka_output.flush_incomplete",
                               remaining=remaining)

    def close(self) -> None:
        self.flush()
        logger.info("kafka_output.closed", topic=self._topic)


# ─────────────────────────────────────────────────────────────────────────────
# WebhookOutput
# ─────────────────────────────────────────────────────────────────────────────

class WebhookOutput(BaseOutput):
    """
    POST events as JSON to an HTTP endpoint.

    Events are placed on an in-memory queue and consumed by a background
    worker thread. This keeps dispatch() latency near zero regardless of
    webhook response time.

    On POST failure, the worker retries up to max_retries times with
    exponential back-off. Events that exhaust retries are dropped and
    counted in stats.errors.

    Parameters
    ----------
    url : str
        Full URL to POST to, e.g. "https://ingest.example.com/events".

    headers : dict, optional
        Extra HTTP headers. "Content-Type: application/json" is always set.

    timeout_s : float
        Per-request timeout in seconds. Default: 5.0.

    max_retries : int
        Retries after the first failure. 0 = no retry. Default: 2.

    queue_max : int
        Maximum in-memory queue depth. When full, new events are dropped
        (back-pressure safety). Default: 10_000.
    """

    def __init__(
        self,
        url:              str,
        headers:          Optional[Dict[str, str]] = None,
        timeout_s:        float                    = 5.0,
        max_retries:      int                      = 2,
        queue_max:        int                      = 10_000,
        output_filter:    Optional[OutputFilter]   = None,
        include_detection: bool                    = False,
    ):
        super().__init__(output_filter, include_detection, name=f"webhook:{url}")
        self._url         = url
        self._timeout     = timeout_s
        self._max_retries = max_retries
        self._headers     = {"Content-Type": "application/json"}
        if headers:
            self._headers.update(headers)

        self._queue  = queue.Queue(maxsize=queue_max)
        self._closed = threading.Event()

        # Background worker thread
        self._worker = threading.Thread(
            target=self._worker_loop,
            name=f"webhook-{url}",
            daemon=True,
        )
        self._worker.start()
        logger.info("webhook_output.started", url=url, queue_max=queue_max)

    def _write_event(self, event: ParsedEvent, payload: bytes) -> None:
        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            # Queue saturated — drop event, count as error
            self.stats.errors += 1
            logger.warning("webhook_output.queue_full",
                           url=self._url, qsize=self._queue.qsize())

    def _worker_loop(self) -> None:
        """Background thread: drain queue and POST each payload."""
        import urllib.error
        import urllib.request

        while not self._closed.is_set():
            try:
                payload = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue

            self._post_with_retry(payload, urllib.request, urllib.error)
            self._queue.task_done()

    def _post_with_retry(
        self,
        payload: bytes,
        urllib_request: Any,
        urllib_error: Any,
    ) -> None:
        """POST payload, retrying on transient errors with exponential back-off."""
        delay = 0.5  # initial retry delay in seconds
        for attempt in range(self._max_retries + 1):
            try:
                req = urllib_request.Request(
                    self._url,
                    data    = payload,
                    headers = self._headers,
                    method  = "POST",
                )
                with urllib_request.urlopen(req, timeout=self._timeout):
                    return   # success
            except Exception as exc:
                if attempt < self._max_retries:
                    logger.debug("webhook_output.retry",
                                 url=self._url, attempt=attempt + 1,
                                 delay_s=delay, error=str(exc))
                    time.sleep(delay)
                    delay = min(delay * 2, 30.0)  # cap at 30s
                else:
                    self.stats.errors += 1
                    logger.warning("webhook_output.failed",
                                   url=self._url, attempts=self._max_retries + 1,
                                   error=str(exc))

    def flush(self) -> None:
        """Block until the in-flight queue is drained."""
        self._queue.join()

    def close(self) -> None:
        self._closed.set()
        self._worker.join(timeout=10.0)
        logger.info("webhook_output.closed", url=self._url)

    def health(self) -> dict:
        d = super().health()
        d["queue_depth"] = self._queue.qsize()
        return d


# ─────────────────────────────────────────────────────────────────────────────
# CallbackOutput  (for testing and programmatic use)
# ─────────────────────────────────────────────────────────────────────────────

class CallbackOutput(BaseOutput):
    """
    Invoke a Python callable for each event. Useful for tests and
    in-process consumers (e.g. pushing to an asyncio queue).

    Parameters
    ----------
    callback : callable
        Called as callback(event: ParsedEvent). Must not raise.
    """

    def __init__(
        self,
        callback:         Callable[[ParsedEvent], None],
        output_filter:    Optional[OutputFilter] = None,
        include_detection: bool                  = False,
        name:             str                    = "callback",
    ):
        super().__init__(output_filter, include_detection, name=name)
        self._callback = callback

    def _write_event(self, event: ParsedEvent, payload: bytes) -> None:
        self._callback(event)


# ─────────────────────────────────────────────────────────────────────────────
# Output registry
# ─────────────────────────────────────────────────────────────────────────────

OUTPUT_REGISTRY: Dict[str, type] = {
    "stdout":   StdoutOutput,
    "file":     FileOutput,
    "kafka":    KafkaOutput,
    "webhook":  WebhookOutput,
    "callback": CallbackOutput,
}


def register_output(name: str, cls: type) -> None:
    """
    Register a custom output backend by name.

    Third-party or application-specific outputs can extend the dispatcher
    without modifying this file:

        class MyOutput(BaseOutput):
            def _write_event(self, event, payload): ...

        register_output("my_output", MyOutput)

        dispatcher = EventDispatcher([{"type": "my_output", "custom_arg": 1}])
    """
    if not issubclass(cls, BaseOutput):
        raise TypeError(f"{cls.__name__} must subclass BaseOutput")
    OUTPUT_REGISTRY[name] = cls
    logger.info("dispatcher.output_registered", name=name, cls=cls.__name__)


# ─────────────────────────────────────────────────────────────────────────────
# EventDispatcher
# ─────────────────────────────────────────────────────────────────────────────

class EventDispatcher:
    """
    Routes ParsedEvents to all configured output backends.

    Each event passes through:
      1. Global filter  (applied once, before routing)
      2. Per-output filter (applied independently per output)
      3. Output.write() (serialise + deliver)

    Errors in one output are logged and swallowed — never propagated.

    Parameters
    ----------
    output_configs : list of dict
        Each dict must have a "type" key matching an entry in OUTPUT_REGISTRY.
        Remaining keys are passed as keyword arguments to the output constructor.
        An optional "filter" sub-dict is extracted and converted to OutputFilter.
        An optional "include_detection" bool controls whether the detection
        block appears in serialised JSON (default: False).

    global_filter : OutputFilter, optional
        Applied before routing. Events that fail this filter are counted in
        self.global_filtered and never reach any output.

    Example config
    --------------
        dispatcher = EventDispatcher([
            {"type": "stdout", "pretty": True,
             "filter": {"protocols": ["MCP", "gRPC"]}},
            {"type": "file",
             "path": "/var/log/ebpf/events.jsonl",
             "rotate_mb": 200,
             "filter": {"drop_parse_errors": True}},
            {"type": "kafka",
             "brokers": ["kafka:9092"],
             "topic": "http-events"},
        ])
    """

    def __init__(
        self,
        output_configs: List[dict],
        global_filter:  Optional[OutputFilter] = None,
    ):
        self._outputs:          List[BaseOutput] = []
        self._global_filter:   Optional[OutputFilter] = global_filter
        self.global_filtered:  int = 0
        self.total_dispatched: int = 0

        for cfg in output_configs:
            cfg   = dict(cfg)                           # don't mutate caller's dict
            otype = cfg.pop("type", "stdout")
            klass = OUTPUT_REGISTRY.get(otype)

            if not klass:
                logger.warning("dispatcher.unknown_output_type", type=otype,
                               known=list(OUTPUT_REGISTRY.keys()))
                continue

            # Extract filter config before passing remaining kwargs
            filter_cfg = cfg.pop("filter", None)
            out_filter = OutputFilter.from_dict(filter_cfg) if filter_cfg else None

            try:
                output = klass(output_filter=out_filter, **cfg)
                self._outputs.append(output)
                logger.info("dispatcher.output_added",
                            type=otype, filter=bool(out_filter))
            except Exception as exc:
                logger.error("dispatcher.output_init_failed",
                             type=otype, error=str(exc))

        if not self._outputs:
            # Safety fallback: always emit to stdout so events are never silently lost
            logger.warning("dispatcher.no_outputs_configured",
                           msg="Falling back to stdout output")
            self._outputs.append(StdoutOutput())

    # ── Primary interface ─────────────────────────────────────────────────────

    def dispatch(self, event: ParsedEvent) -> None:
        """
        Route one ParsedEvent to all outputs.

        Called once per event from the ring buffer poll loop.
        Never raises.
        """
        self.total_dispatched += 1

        # Global filter gate
        if self._global_filter and not self._global_filter.passes(event):
            self.global_filtered += 1
            return

        for output in self._outputs:
            try:
                output.write(event)
            except Exception as exc:
                # Belt-and-suspenders: BaseOutput.write() already catches,
                # but guard here too in case of unexpected subclass errors.
                logger.warning("dispatcher.unexpected_output_error",
                               output=output._name, error=str(exc))

    def dispatch_batch(self, events: List[ParsedEvent]) -> None:
        """
        Route a list of ParsedEvents. Convenience wrapper for bulk processing.
        Same semantics as calling dispatch() in a loop.
        """
        for event in events:
            self.dispatch(event)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def flush(self) -> None:
        """Flush all outputs. Blocks until in-flight data is written."""
        for output in self._outputs:
            try:
                output.flush()
            except Exception as exc:
                logger.warning("dispatcher.flush_error",
                               output=output._name, error=str(exc))

    def close(self) -> None:
        """
        Flush and close all outputs. Call once on agent shutdown.
        Safe to call multiple times (subsequent calls are no-ops per output).
        """
        self.flush()
        for output in self._outputs:
            try:
                output.close()
            except Exception as exc:
                logger.warning("dispatcher.close_error",
                               output=output._name, error=str(exc))
        logger.info("dispatcher.closed",
                    total_dispatched=self.total_dispatched,
                    global_filtered=self.global_filtered)

    # ── Observability ─────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """
        Return aggregate and per-output statistics.

        Example return value::

            {
                "total_dispatched": 150000,
                "global_filtered":  5000,
                "total_written":    140000,
                "total_errors":     12,
                "outputs": [
                    {"name": "stdout",  "stats": {"written": 140000, ...}},
                    {"name": "kafka:..", "stats": {"written": 140000, ...}},
                ]
            }
        """
        output_stats = [o.health() for o in self._outputs]
        total_written = sum(
            o.stats.written for o in self._outputs
        )
        total_errors  = sum(
            o.stats.errors  for o in self._outputs
        )
        return {
            "total_dispatched": self.total_dispatched,
            "global_filtered":  self.global_filtered,
            "total_written":    total_written,
            "total_errors":     total_errors,
            "outputs":          output_stats,
        }

    def add_output(self, output: BaseOutput) -> None:
        """
        Dynamically add an output at runtime.

        Useful for attaching a short-lived debug output during a live
        capture session without restarting the agent.
        """
        if not isinstance(output, BaseOutput):
            raise TypeError(f"Expected BaseOutput subclass, got {type(output)}")
        self._outputs.append(output)
        logger.info("dispatcher.output_added_dynamic", name=output._name)

    def remove_output(self, name: str) -> bool:
        """
        Remove and close the first output whose _name matches.

        Returns True if an output was removed, False if not found.
        """
        for i, output in enumerate(self._outputs):
            if output._name == name:
                try:
                    output.close()
                except Exception:
                    pass
                self._outputs.pop(i)
                logger.info("dispatcher.output_removed", name=name)
                return True
        return False

    def __len__(self) -> int:
        return len(self._outputs)

    def __repr__(self) -> str:
        names = [o._name for o in self._outputs]
        return (f"EventDispatcher(outputs={names}, "
                f"dispatched={self.total_dispatched})")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _gzip_file(path: Path) -> None:
    """
    Compress path to path.gz in-place, then delete the original.
    Runs on a daemon thread after file rotation.
    """
    gz_path = path.with_suffix(path.suffix + ".gz")
    try:
        with open(path, "rb") as src, gzip.open(gz_path, "wb") as dst:
            dst.write(src.read())
        path.unlink()
        logger.debug("file_output.compressed", path=str(gz_path))
    except Exception as exc:
        logger.warning("file_output.compress_error",
                       path=str(path), error=str(exc))
