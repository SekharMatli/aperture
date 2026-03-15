"""
ebpf_agent.py
=============
Production eBPF HTTP capture agent.

Wires together all components into a single runnable
process. Owns the main poll loop, lifecycle management, and the sweep
timer that expires idle connections.

Component wiring
----------------
  BPFLoader           — loads the kernel program, manages ring buffer
  SSLProbeManager     — attaches uprobes to libssl for TLS plaintext
  ConnectionTracker   — per-connection state, LRU eviction, protocol promotion
  ProtocolDetector    — refines kernel's coarse protocol guess
  HTTPParser          — converts raw bytes to ParsedEvent
  EventDispatcher     — fans out ParsedEvent to configured output backends
  AgentCounters       — telemetry for the above
  MetricsServer       — exposes counters as Prometheus /metrics

Main loop
---------
  while running:
      loader.poll(timeout_ms=100)          ← epoll, blocks up to 100ms
      if sweep_due:
          tracker.sweep_expired(now_ns)    ← evict stale connections
          metrics_server.set_active()      ← update Prometheus gauge
      if stats_due:
          log counters snapshot

Signal handling
---------------
  SIGINT / SIGTERM → set _shutdown flag → poll loop exits → graceful drain

Thread model
------------
  Main thread:     poll loop (single-threaded, no locking needed on hot path)
  Daemon threads:  MetricsServer sync, FileOutput rotation, WebhookOutput POST

Zero-loss strategy
------------------
  • Ring buffer sized at ringbuf_size_mb (default 256 MB)
  • epoll-based wakeup — no busy-wait, sub-millisecond wake latency
  • Kernel drop counter read every stats_interval_s; logged + metriced
  • dispatcher.flush() called on shutdown to drain in-flight Kafka/webhook
"""

from __future__ import annotations

import ctypes
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import structlog

from src.agent.bpf_loader import BPFLoader, BPFLoaderError
from src.agent.config import AgentConfig
from src.agent.event_types import Direction, EventMeta, Protocol, RawEvent
from src.agent.metrics import AgentCounters, MetricsServer
from src.agent.ssl_probe import SSLProbeManager
from src.output.dispatcher import EventDispatcher
from src.processors.conn_tracker import ConnectionTracker
from src.processors.http_parser import HTTPParser
from src.processors.protocol_detector import ProtocolDetector

logger = structlog.get_logger(__name__)


class EBPFAgent:
    """
    Production eBPF HTTP capture agent.

    Lifecycle
    ---------
        agent = EBPFAgent(config)
        agent.start()        # blocks until SIGINT/SIGTERM
        # or:
        agent.start_async()  # non-blocking; call agent.stop() to halt

    Parameters
    ----------
    config : AgentConfig
        Fully populated configuration object. See config.py.
    """

    VERSION = "2.0.0"

    def __init__(self, config: AgentConfig) -> None:
        self.config = config

        # ── Core pipeline components ──────────────────────────────────────────
        self._detector   = ProtocolDetector()
        self._tracker    = ConnectionTracker(
            detector        = self._detector,
            max_connections = config.max_connections,
            ttl_seconds     = config.connection_ttl_s,
            on_evict        = self._on_connection_evict,
        )
        self._parser     = HTTPParser()
        self._dispatcher = EventDispatcher(config.outputs)

        # ── Telemetry ─────────────────────────────────────────────────────────
        self._counters        = AgentCounters()
        self._metrics_server  = MetricsServer(
            counters          = self._counters,
            port              = config.prometheus.port,
            scrape_interval_s = 5.0,
        )

        # ── BPF / SSL (initialised in start()) ───────────────────────────────
        self._loader:     Optional[BPFLoader]       = None
        self._ssl_mgr:    Optional[SSLProbeManager] = None

        # ── Control ───────────────────────────────────────────────────────────
        self._shutdown        = False
        self._started         = False
        self._last_sweep_ts   = 0.0   # monotonic
        self._last_stats_ts   = 0.0   # monotonic

        # Install signal handlers now so they work even before start()
        signal.signal(signal.SIGINT,  self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Load BPF program, attach probes, start Prometheus, run poll loop.

        Blocks until SIGINT / SIGTERM is received or stop() is called.
        Call this from __main__; it handles its own finally/cleanup.
        """
        try:
            self._startup()
            self._poll_loop()
        finally:
            self._shutdown_cleanup()

    def stop(self) -> None:
        """Signal the poll loop to exit. Safe to call from any thread."""
        self._shutdown = True

    # ─────────────────────────────────────────────────────────────────────────
    # Startup sequence
    # ─────────────────────────────────────────────────────────────────────────

    def _startup(self) -> None:
        """
        Full startup sequence. Raises on unrecoverable errors.

        Order matters:
          1. Validate config
          2. Load BPF program (verifier runs here)
          3. Configure BPF map filters
          4. Attach kprobes
          5. Attach SSL uprobes  (optional, non-fatal if no libssl found)
          6. Start Prometheus server (optional, non-fatal)
          7. Open ring buffer
        """
        logger.info("agent.starting",
                    version=self.VERSION,
                    pid=os.getpid(),
                    bpf_path=self.config.bpf_object_path,
                    ringbuf_mb=self.config.ringbuf_size_mb)

        # 1. Validate config
        errors = self.config.validate()
        if errors:
            for err in errors:
                logger.error("agent.config_error", error=err)
            raise ValueError(f"Invalid config: {errors[0]}")

        # 2. Load BPF
        self._loader = BPFLoader(
            bpf_path        = self.config.bpf_object_path,
            ringbuf_size_mb = self.config.ringbuf_size_mb,
        )
        try:
            self._loader.load()
        except BPFLoaderError as exc:
            logger.error("agent.bpf_load_failed", error=str(exc))
            raise

        # 3. Configure filters
        self._loader.configure_filters(
            port_filter = self.config.port_filter,
            pid_filter  = self.config.pid_filter,
        )

        # 4. Attach kprobes
        try:
            self._loader.attach_probes()
        except BPFLoaderError as exc:
            logger.error("agent.probe_attach_failed", error=str(exc))
            raise

        # 5. SSL uprobes (non-fatal)
        if self.config.capture_tls:
            self._ssl_mgr = SSLProbeManager(self._loader, self.config.ssl)
            n = self._ssl_mgr.attach()
            if n == 0:
                logger.warning("agent.ssl_probes_none_attached",
                               msg="TLS capture will show encrypted bytes only")
        else:
            logger.info("agent.ssl_disabled")

        # 6. Prometheus (non-fatal)
        if self.config.prometheus.enabled:
            ok = self._metrics_server.start()
            if ok:
                logger.info("agent.prometheus_started",
                            port=self.config.prometheus.port)

        # 7. Open ring buffer
        self._loader.open_ring_buffer(self._on_ring_buffer_event)

        self._started      = True
        self._last_sweep_ts = time.monotonic()
        self._last_stats_ts = time.monotonic()

        logger.info("agent.started",
                    probes=self._loader.probes_attached,
                    ssl_probes=self._ssl_mgr.probe_count if self._ssl_mgr else 0,
                    outputs=len(self._dispatcher))

    # ─────────────────────────────────────────────────────────────────────────
    # Main poll loop
    # ─────────────────────────────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        """
        Main event loop. Blocks on epoll up to 100ms, then does housekeeping.

        100ms timeout gives:
          - Sub-100ms responsiveness to SIGINT
          - ~10 sweep/stats checks per second (cheap)
          - No busy-wait when traffic is idle
        """
        logger.info("agent.capture_active")

        while not self._shutdown:
            # Poll ring buffer — callback fires synchronously for each event
            self._loader.poll(timeout_ms=100)

            now = time.monotonic()

            # Periodic sweep: evict stale connections
            if now - self._last_sweep_ts >= self.config.sweep_interval_s:
                self._sweep(now)
                self._last_sweep_ts = now

            # Periodic stats logging
            if now - self._last_stats_ts >= self.config.stats_interval_s:
                self._emit_stats()
                self._last_stats_ts = now

        logger.info("agent.poll_loop_exited")

    # ─────────────────────────────────────────────────────────────────────────
    # Ring buffer callback — HOT PATH
    # ─────────────────────────────────────────────────────────────────────────

    def _on_ring_buffer_event(
        self,
        cpu:      int,
        data_ptr: ctypes.c_void_p,
        size:     int,
    ) -> None:
        """
        Called by BCC for every ring buffer event. Runs on the poll thread.

        This is the hottest code path in the agent. Keep allocations minimal.
        All heavy work (JSON serialisation, file I/O) happens in dispatcher
        backends which are designed to be fast on the write side.
        """
        from src.agent.event_types import EventHeaderCT

        min_size = ctypes.sizeof(EventHeaderCT)
        if size < min_size:
            self._counters.record_malformed()
            return

        # Parse raw event (zero-copy header read, one bytes() copy for payload)
        try:
            raw_event = RawEvent.from_ring_buffer(data_ptr, size)
        except Exception as exc:
            logger.debug("agent.raw_parse_error", error=str(exc))
            self._counters.record_malformed()
            return

        self._counters.record_event(
            raw_event.meta.protocol.display_name,
            raw_event.meta.payload_len,
        )

        # CLOSE events: flush connection state, no payload to parse
        if raw_event.meta.direction == Direction.CLOSE:
            self._tracker.update(raw_event)   # records close timestamp
            self._counters.record_close()
            return

        # Update connection tracker + run protocol detection
        try:
            conn_record = self._tracker.update(raw_event)
        except Exception as exc:
            logger.debug("agent.tracker_error", error=str(exc))
            return

        # Check if this is the first packet for this connection
        if conn_record.total_packets == 1:
            self._counters.record_connection_created()

        # Skip parsing if no payload (e.g. ACK-only segments)
        if not raw_event.payload:
            return

        # Parse payload into structured event
        detection = conn_record.last_result
        if detection is None:
            return

        try:
            parsed = self._parser.parse(raw_event, detection)
        except Exception as exc:
            logger.debug("agent.parse_error", error=str(exc),
                         conn_id=f"0x{raw_event.meta.conn_id:016x}")
            self._counters.record_parse_error()
            return

        if parsed.parse_error:
            self._counters.record_parse_error()

        # Dispatch to output backends
        try:
            self._dispatcher.dispatch(parsed)
        except Exception as exc:
            logger.debug("agent.dispatch_error", error=str(exc))
            return

        # Update output counters from dispatcher stats
        # (done periodically, not per-event, to avoid per-event dict lookups)

    # ─────────────────────────────────────────────────────────────────────────
    # Housekeeping
    # ─────────────────────────────────────────────────────────────────────────

    def _sweep(self, now_mono: float) -> None:
        """
        Evict connections idle for longer than connection_ttl_s.
        Updates Prometheus active_connections gauge.
        """
        now_ns   = time.time_ns()
        evicted  = self._tracker.sweep_expired(now_ns)
        active   = len(self._tracker)

        if evicted > 0:
            logger.debug("agent.sweep",
                         evicted=evicted, active=active)

        self._metrics_server.set_active_connections(active)

        # Also check kernel drop counter
        drops = self._loader.read_drop_counter()
        if drops > 0:
            self._counters.add_kernel_drops(drops)
            logger.warning("agent.kernel_drops",
                           new_drops=drops,
                           total=self._counters.kernel_drops,
                           drop_rate_pct=round(self._counters.drop_rate_pct, 2),
                           recommendation="Increase ringbuf_size_mb if drops persist")

    def _emit_stats(self) -> None:
        """Log a structured snapshot of agent counters."""
        snap = self._counters.snapshot()
        # Also pull latest output stats from dispatcher
        disp_stats = self._dispatcher.stats()
        snap["output_written"] = disp_stats["total_written"]
        snap["output_errors"]  = disp_stats["total_errors"]
        snap["active_connections"] = len(self._tracker)

        logger.info("agent.stats", **snap)

    # ─────────────────────────────────────────────────────────────────────────
    # Eviction callback (called from ConnectionTracker)
    # ─────────────────────────────────────────────────────────────────────────

    def _on_connection_evict(self, record) -> None:
        """
        Called by ConnectionTracker when a connection is evicted (LRU, TTL, or CLOSE).
        Updates the eviction counter. Does not raise.
        """
        self._counters.record_eviction()
        logger.debug("agent.connection_evicted",
                     conn_id=record.conn_id_hex,
                     protocol=record.protocol.display_name,
                     duration_ms=round(record.duration_ms, 1),
                     total_bytes=record.total_bytes)

    # ─────────────────────────────────────────────────────────────────────────
    # Signal handling
    # ─────────────────────────────────────────────────────────────────────────

    def _handle_signal(self, signum: int, frame) -> None:
        sig_name = {signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(
            signum, str(signum))
        logger.info("agent.signal_received", signal=sig_name)
        self._shutdown = True

    # ─────────────────────────────────────────────────────────────────────────
    # Shutdown cleanup
    # ─────────────────────────────────────────────────────────────────────────

    def _shutdown_cleanup(self) -> None:
        """
        Graceful shutdown: detach probes, drain outputs, log final stats.
        Always runs, even on exception from _poll_loop.
        """
        logger.info("agent.shutting_down")

        # 1. Detach probes so no new events arrive
        if self._loader:
            self._loader.detach_probes()

        # 2. SSL cleanup
        if self._ssl_mgr:
            try:
                self._ssl_mgr.detach()
            except Exception:
                pass

        # 3. Drain dispatcher (flush Kafka, wait for webhook queue)
        try:
            self._dispatcher.flush()
            self._dispatcher.close()
        except Exception as exc:
            logger.warning("agent.dispatcher_close_error", error=str(exc))

        # 4. Stop Prometheus server
        try:
            self._metrics_server.stop()
        except Exception:
            pass

        # 5. Close BPF object (frees kernel memory)
        if self._loader:
            try:
                self._loader.close()
            except Exception:
                pass

        # 6. Final stats
        snap = self._counters.snapshot()
        logger.info("agent.stopped",
                    **snap,
                    active_connections=len(self._tracker))

    # ─────────────────────────────────────────────────────────────────────────
    # Diagnostics
    # ─────────────────────────────────────────────────────────────────────────

    def health(self) -> dict:
        """
        Return a complete health snapshot. Safe to call at any time.
        Useful for implementing a /healthz HTTP endpoint or admin tool.
        """
        return {
            "version":    self.VERSION,
            "started":    self._started,
            "shutdown":   self._shutdown,
            "bpf":        self._loader.health().to_dict() if self._loader else None,
            "ssl":        self._ssl_mgr.health() if self._ssl_mgr else None,
            "tracker":    self._tracker.stats(),
            "dispatcher": self._dispatcher.stats(),
            "counters":   self._counters.snapshot(),
        }

    def __repr__(self) -> str:
        state = "running" if self._started and not self._shutdown else \
                "stopped" if self._shutdown else "initialised"
        return (f"EBPFAgent(state={state}, "
                f"events={self._counters.events_total}, "
                f"connections={len(self._tracker)})")