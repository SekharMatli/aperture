"""
metrics.py
==========
Agent telemetry: in-process counters + optional Prometheus HTTP endpoint.

Two layers
----------
AgentCounters   — raw integer counters, incremented on the hot path.
                  Lock-free reads via atomic-ish Python integers (GIL
                  makes single-integer ops effectively atomic on CPython).
                  Updated from the single-threaded poll loop.

MetricsServer   — wraps prometheus_client, starts an HTTP server on the
                  configured port, and mirrors AgentCounters into gauges
                  and counters that Prometheus can scrape.

Prometheus degrades gracefully: if prometheus_client is not installed,
MetricsServer.start() is a no-op and everything else works normally.

Exposed metrics
---------------
  ebpf_agent_events_total{protocol}    Counter  — events processed
  ebpf_agent_drops_total               Counter  — kernel ring-buffer drops
  ebpf_agent_parse_errors_total        Counter  — parse failures
  ebpf_agent_active_connections        Gauge    — live connections
  ebpf_agent_evicted_connections_total Counter  — LRU + TTL evictions
  ebpf_agent_bytes_captured_total      Counter  — bytes seen at capture point
  ebpf_agent_events_per_second         Gauge    — rolling 10-s rate
  ebpf_agent_uptime_seconds            Gauge    — agent uptime
  ebpf_agent_output_written_total      Counter  — events written to outputs
  ebpf_agent_output_errors_total       Counter  — output write errors
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Prometheus import (optional)
# ─────────────────────────────────────────────────────────────────────────────

try:
    import prometheus_client as prom
    from prometheus_client import Counter, Gauge, CollectorRegistry, start_http_server
    _PROM_AVAILABLE = True
except ImportError:
    _PROM_AVAILABLE = False
    prom = None  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# AgentCounters — raw counters, no Prometheus dependency
# ─────────────────────────────────────────────────────────────────────────────

class AgentCounters:
    """
    Integer counters for all agent telemetry.

    Updated exclusively from the single-threaded ring-buffer poll loop.
    The GIL makes individual integer increments atomic on CPython, so no
    locking is needed for the hot path. The MetricsServer reads these
    values from a background thread — occasional torn reads are acceptable
    for telemetry.

    All counters are monotonically increasing. Compute rates by diffing
    successive snapshots.
    """

    __slots__ = (
        # Event pipeline
        "events_total",          # all ring-buffer events received
        "events_by_protocol",    # {protocol_name: count}
        "parse_errors",          # events where http_parser set parse_error
        "malformed_events",      # events too small to contain a valid header
        "close_events",          # CLOSE direction events (tcp_close probe)

        # Drops (kernel-side ring buffer overflow)
        "kernel_drops",          # cumulative since agent start
        "_last_drop_baseline",   # last value read from drop_counter map

        # Connections
        "connections_created",   # new ConnectionRecord creations
        "connections_closed",    # CLOSE events processed
        "connections_evicted",   # LRU + TTL evictions

        # Throughput
        "bytes_captured",        # sum of payload_len across all events

        # Output
        "output_written",        # events successfully written to any output
        "output_errors",         # output write failures

        # Timing
        "_start_time",           # time.monotonic() at construction
        "_window_events",        # events in current 10-s rate window
        "_window_start",         # monotonic timestamp of window start
        "events_per_second",     # rolling 10-s rate (updated each window)
    )

    def __init__(self) -> None:
        self.events_total          = 0
        self.events_by_protocol:   Dict[str, int] = {}
        self.parse_errors          = 0
        self.malformed_events      = 0
        self.close_events          = 0
        self.kernel_drops          = 0
        self._last_drop_baseline   = 0
        self.connections_created   = 0
        self.connections_closed    = 0
        self.connections_evicted   = 0
        self.bytes_captured        = 0
        self.output_written        = 0
        self.output_errors         = 0
        self._start_time           = time.monotonic()
        self._window_events        = 0
        self._window_start         = time.monotonic()
        self.events_per_second     = 0.0

    # ── Hot-path update methods ───────────────────────────────────────────────

    def record_event(self, protocol_name: str, payload_len: int) -> None:
        """Call once per ring-buffer event on the poll-loop thread."""
        self.events_total    += 1
        self.bytes_captured  += payload_len
        self._window_events  += 1
        self.events_by_protocol[protocol_name] = (
            self.events_by_protocol.get(protocol_name, 0) + 1
        )
        self._maybe_roll_window()

    def record_parse_error(self) -> None:
        self.parse_errors += 1

    def record_malformed(self) -> None:
        self.malformed_events += 1

    def record_close(self) -> None:
        self.close_events       += 1
        self.connections_closed += 1

    def record_connection_created(self) -> None:
        self.connections_created += 1

    def record_eviction(self) -> None:
        self.connections_evicted += 1

    def record_output_written(self, count: int = 1) -> None:
        self.output_written += count

    def record_output_error(self, count: int = 1) -> None:
        self.output_errors += count

    def add_kernel_drops(self, delta: int) -> None:
        """Add newly observed kernel drops (delta since last read)."""
        self.kernel_drops += delta

    # ── Derived metrics ───────────────────────────────────────────────────────

    @property
    def uptime_s(self) -> float:
        return time.monotonic() - self._start_time

    @property
    def drop_rate_pct(self) -> float:
        total = self.events_total + self.kernel_drops
        return (self.kernel_drops / total * 100) if total > 0 else 0.0

    # ── Rate window ───────────────────────────────────────────────────────────

    _WINDOW_S = 10.0  # rolling window size in seconds

    def _maybe_roll_window(self) -> None:
        now    = time.monotonic()
        elapsed = now - self._window_start
        if elapsed >= self._WINDOW_S:
            self.events_per_second = self._window_events / elapsed
            self._window_events    = 0
            self._window_start     = now

    # ── Snapshot ──────────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        """
        Return a JSON-serialisable snapshot of all counters.
        Safe to call from any thread (may have minor torn reads).
        """
        return {
            "uptime_s":             round(self.uptime_s, 1),
            "events_total":         self.events_total,
            "events_per_second":    round(self.events_per_second, 1),
            "events_by_protocol":   dict(self.events_by_protocol),
            "parse_errors":         self.parse_errors,
            "malformed_events":     self.malformed_events,
            "close_events":         self.close_events,
            "kernel_drops":         self.kernel_drops,
            "drop_rate_pct":        round(self.drop_rate_pct, 3),
            "connections_created":  self.connections_created,
            "connections_closed":   self.connections_closed,
            "connections_evicted":  self.connections_evicted,
            "bytes_captured":       self.bytes_captured,
            "output_written":       self.output_written,
            "output_errors":        self.output_errors,
        }


# ─────────────────────────────────────────────────────────────────────────────
# MetricsServer — Prometheus HTTP endpoint
# ─────────────────────────────────────────────────────────────────────────────

class MetricsServer:
    """
    Starts a Prometheus-compatible HTTP server and periodically syncs
    AgentCounters into Prometheus metrics.

    If prometheus_client is not installed, start() is a no-op and the
    agent continues without metrics export.

    Parameters
    ----------
    counters : AgentCounters
        The shared counter object updated by the poll loop.

    port : int
        TCP port for the metrics HTTP server. Default: 9090.

    scrape_interval_s : float
        How often counters are synced into Prometheus metrics.
        Should be lower than the Prometheus scrape interval (default 15s).
        Default: 5.0.
    """

    def __init__(
        self,
        counters:           AgentCounters,
        port:               int   = 9090,
        scrape_interval_s:  float = 5.0,
    ):
        self._counters         = counters
        self._port             = port
        self._scrape_interval  = scrape_interval_s
        self._running          = False
        self._thread:          Optional[threading.Thread] = None
        self._available        = _PROM_AVAILABLE

        # Prometheus metric objects (initialised in start())
        self._c_events:       Optional[object] = None
        self._c_drops:        Optional[object] = None
        self._c_parse_errors: Optional[object] = None
        self._c_output_written: Optional[object] = None
        self._c_output_errors:  Optional[object] = None
        self._g_active_conns: Optional[object] = None
        self._g_evicted:      Optional[object] = None
        self._g_eps:          Optional[object] = None
        self._g_uptime:       Optional[object] = None
        self._g_drop_rate:    Optional[object] = None
        self._c_bytes:        Optional[object] = None

        # Shadow values for computing Counter deltas
        # (prometheus_client Counters only go up — we compute deltas)
        self._shadow: Dict[str, int] = {}

    def start(self) -> bool:
        """
        Start the Prometheus HTTP server and background sync thread.

        Returns True if started successfully, False if prometheus_client
        is not installed or the server fails to bind.
        """
        if not self._available:
            import sys
            print(
                f"[metrics] prometheus_client not installed — "
                f"metrics endpoint on :{self._port} disabled. "
                "Install with: pip install prometheus-client",
                file=sys.stderr,
            )
            return False

        try:
            self._init_metrics()
            start_http_server(self._port)
            self._running = True
            self._thread  = threading.Thread(
                target=self._sync_loop,
                name="metrics-sync",
                daemon=True,
            )
            self._thread.start()
            return True
        except Exception as exc:
            import sys
            print(f"[metrics] Failed to start Prometheus server: {exc}", file=sys.stderr)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)

    # ── Prometheus metric initialisation ──────────────────────────────────────

    def _init_metrics(self) -> None:
        """Create all Prometheus metric objects."""
        ns = "ebpf_agent"  # namespace prefix for all metrics

        self._c_events = Counter(
            f"{ns}_events_total",
            "Total ring-buffer events processed",
            ["protocol"],
        )
        self._c_drops = Counter(
            f"{ns}_drops_total",
            "Total events dropped due to ring-buffer overflow",
        )
        self._c_parse_errors = Counter(
            f"{ns}_parse_errors_total",
            "Total events where payload parsing failed",
        )
        self._c_output_written = Counter(
            f"{ns}_output_written_total",
            "Total events successfully written to output backends",
        )
        self._c_output_errors = Counter(
            f"{ns}_output_errors_total",
            "Total output backend write failures",
        )
        self._c_bytes = Counter(
            f"{ns}_bytes_captured_total",
            "Total payload bytes seen at the capture point",
        )
        self._g_active_conns = Gauge(
            f"{ns}_active_connections",
            "Current number of tracked active connections",
        )
        self._g_evicted = Gauge(
            f"{ns}_evicted_connections_total",
            "Total connections evicted from the tracker (LRU + TTL)",
        )
        self._g_eps = Gauge(
            f"{ns}_events_per_second",
            "Rolling 10-second event rate",
        )
        self._g_uptime = Gauge(
            f"{ns}_uptime_seconds",
            "Agent uptime in seconds",
        )
        self._g_drop_rate = Gauge(
            f"{ns}_drop_rate_percent",
            "Kernel drop rate as a percentage of total events",
        )

    # ── Sync loop ─────────────────────────────────────────────────────────────

    def _sync_loop(self) -> None:
        """Background thread: periodically push counter values to Prometheus."""
        while self._running:
            try:
                self._sync()
            except Exception:
                pass
            time.sleep(self._scrape_interval)

    def _sync(self) -> None:
        """
        Push current AgentCounters values into Prometheus metric objects.

        Prometheus Counters are monotonically increasing — we track shadow
        values and only call .inc() with the positive delta.
        """
        c = self._counters

        # Per-protocol event counter
        for proto, total in c.events_by_protocol.items():
            key  = f"events_{proto}"
            prev = self._shadow.get(key, 0)
            delta = total - prev
            if delta > 0:
                self._c_events.labels(protocol=proto).inc(delta)
                self._shadow[key] = total

        # Scalar counters (delta-based)
        for attr, prom_counter, key in [
            ("kernel_drops",    self._c_drops,          "drops"),
            ("parse_errors",    self._c_parse_errors,   "parse_errors"),
            ("output_written",  self._c_output_written, "output_written"),
            ("output_errors",   self._c_output_errors,  "output_errors"),
            ("bytes_captured",  self._c_bytes,          "bytes"),
        ]:
            total = getattr(c, attr)
            prev  = self._shadow.get(key, 0)
            delta = total - prev
            if delta > 0:
                prom_counter.inc(delta)
                self._shadow[key] = total

        # Gauges (set to current value directly)
        self._g_eps.set(c.events_per_second)
        self._g_uptime.set(c.uptime_s)
        self._g_drop_rate.set(c.drop_rate_pct)
        self._g_evicted.set(c.connections_evicted)
        # active_connections is set by the agent's sweep callback

    def set_active_connections(self, count: int) -> None:
        """Called by EBPFAgent after each sweep to update the live gauge."""
        if self._g_active_conns:
            self._g_active_conns.set(count)