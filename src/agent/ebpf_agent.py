"""
ebpf_agent.py
=============
Production eBPF HTTP capture agent.

Component wiring
----------------
  BPFLoader           — loads http_capture.bpf.c (BCC JIT) or .o (pre-compiled)
                        selects mode from config.bpf_object_path file extension
  SSLProbeManager     — attaches uprobes to libssl for TLS plaintext capture
  ConnectionTracker   — per-connection state, LRU eviction, protocol promotion
  ProtocolDetector    — refines kernel's coarse protocol guess
  HTTPParser          — converts raw bytes to ParsedEvent
  EventDispatcher     — fans out ParsedEvent to configured output backends
  AgentCounters       — telemetry counters for all the above
  MetricsServer       — exposes counters as Prometheus /metrics

BPF loading modes (controlled by config.bpf_object_path)
---------------------------------------------------------
  .c  — BCC JIT-compiles http_capture.bpf.c against the host kernel at startup.
        Requires clang + linux-headers-$(uname -r) on the host.
        Startup overhead: ~2-3 seconds for compile.
        Use this mode for customer distribution (single image, any kernel).

  .o  — BPFLoader calls bcc.BPF(obj=...) to load a pre-compiled ELF.
        Requires /sys/kernel/btf/vmlinux for CO-RE type resolution.
        Startup overhead: <100ms.
        Use this mode in CI/CD when targeting a known kernel fleet.

  The BPFLoader class in bpf_loader.py makes this decision transparently
  based on the file extension. EBPFAgent does not need to know which mode
  is active; it simply calls loader.load() and proceeds identically.

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
  Daemon threads:  MetricsServer sync, FileOutput rotation, KafkaOutput drain

Zero-loss strategy
------------------
  • Ring buffer sized at ringbuf_size_mb (default 256 MB, up to 2048)
  • epoll-based wakeup — no busy-wait, sub-millisecond wake latency
  • Kernel drop counter read every sweep_interval_s; logged + metriced
  • dispatcher.flush() called on shutdown to drain in-flight Kafka/webhook
"""

from __future__ import annotations

import ctypes
import os
import signal
import time
from pathlib import Path
from typing import Optional

import structlog

from src.agent.bpf_loader import BPFLoader, BPFLoaderError, assert_kernel_supported
from src.agent.config import AgentConfig
from src.agent.event_types import Direction, RawEvent
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

    BPF loading
    -----------
    EBPFAgent delegates all BPF loading to BPFLoader. The choice between
    JIT-compile-from-source (.c) and load-pre-compiled-ELF (.o) is made
    entirely inside BPFLoader.load() based on config.bpf_object_path's
    file extension. EBPFAgent does not branch on this choice anywhere.

    Customer distribution
    ---------------------
    Ship the Docker image with http_capture.bpf.c included and
    bpf_object_path defaulting to the .c path. On first startup on the
    customer host, BCC compiles the .c against the bind-mounted host kernel
    headers. This produces a correct .o for that exact kernel version,
    avoiding the cross-kernel compatibility problem of pre-compiling.

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
        self._counters       = AgentCounters()
        self._metrics_server = MetricsServer(
            counters          = self._counters,
            port              = config.prometheus.port,
            scrape_interval_s = 5.0,
        )

        # ── BPF / SSL (initialised in _startup()) ─────────────────────────────
        #
        # _loader is a BPFLoader instance. It owns the BCC BPF object, the ring
        # buffer fd, and all kprobe/kretprobe attachment state. Everything
        # kernel-side goes through this object; EBPFAgent never touches the BCC
        # API directly.
        #
        # _ssl_mgr attaches uprobes to libssl.so after _loader.load() so that
        # SSL_read / SSL_write events are also captured into the ring buffer.
        self._loader:  Optional[BPFLoader]       = None
        self._ssl_mgr: Optional[SSLProbeManager] = None

        # ── Control ───────────────────────────────────────────────────────────
        self._shutdown      = False
        self._started       = False
        self._last_sweep_ts = 0.0   # monotonic
        self._last_stats_ts = 0.0   # monotonic

        # Install signal handlers immediately so they work before start()
        signal.signal(signal.SIGINT,  self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    # ─────────────────────────────────────────────────────────────────────────
    # Public lifecycle
    # ─────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Full startup: load BPF, attach probes, start Prometheus, run poll loop.

        Blocks until SIGINT / SIGTERM is received or stop() is called.
        Calls _shutdown_cleanup() in a finally block — always runs on exit.
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
        Full startup sequence. Raises on any unrecoverable error.

        Steps:
          1. Validate config (field ranges, file existence)
          2. Assert kernel version supports ring buffer (≥ 5.8)
          3. Instantiate BPFLoader and call load()
               BPFLoader.load() selects the loading mode:
                 bpf_object_path ends in .c → BCC JIT compile from source
                 bpf_object_path ends in .o → load pre-compiled ELF via bcc.BPF(obj=)
               Both modes produce an identical BCC BPF object internally.
               All subsequent BPFLoader calls (configure_filters, attach_probes,
               open_ring_buffer, poll) are the same regardless of which mode ran.
          4. Configure BPF map filters (port_filter, pid_filter)
          5. Attach kprobes / kretprobes
          6. Attach SSL uprobes  (optional — skipped if libssl not found)
          7. Start Prometheus metrics server  (optional — non-fatal)
          8. Open ring buffer and register event callback
        """
        logger.info(
            "agent.starting",
            version        = self.VERSION,
            pid            = os.getpid(),
            bpf_path       = self.config.bpf_object_path,
            bpf_mode       = "jit" if self.config.bpf_object_path.endswith(".c") else "precompiled",
            ringbuf_mb     = self.config.ringbuf_size_mb,
        )

        # 1. Validate config
        errors = self.config.validate()
        if errors:
            for err in errors:
                logger.error("agent.config_error", error=err)
            raise ValueError(f"Invalid config: {errors[0]}")

        # 2. Kernel version gate
        try:
            assert_kernel_supported()
        except BPFLoaderError as exc:
            logger.error("agent.kernel_unsupported", error=str(exc))
            raise

        # 3. Load BPF program
        #
        # BPFLoader.load() inspects the .c / .o extension and calls either
        # _load_from_source() (BCC JIT) or _load_from_object() (pre-compiled).
        # After load() returns, self._loader.bpf is a fully initialised BCC
        # BPF object regardless of which path was taken.
        #
        # If loading from .c fails with a BCC compile error (missing headers,
        # wrong kernel version), BPFLoaderError is raised with the verifier log
        # attached — surfaced directly to the operator in the error message.
        self._loader = BPFLoader(
            bpf_path        = self.config.bpf_object_path,
            ringbuf_size_mb = self.config.ringbuf_size_mb,
        )
        try:
            self._loader.load()
        except BPFLoaderError as exc:
            logger.error(
                "agent.bpf_load_failed",
                error    = str(exc),
                bpf_path = self.config.bpf_object_path,
                hint     = (
                    "For .c mode: ensure clang and linux-headers-$(uname -r) are "
                    "installed and the host kernel headers are bind-mounted to /usr/src. "
                    "For .o mode: ensure /sys/kernel/btf/vmlinux is present."
                ),
            )
            raise

        logger.info(
            "agent.bpf_loaded",
            mode    = "jit"          if self.config.bpf_object_path.endswith(".c") else "precompiled",
            path    = self.config.bpf_object_path,
        )

        # 4. Configure BPF map filters
        #    Must happen before attach_probes() so the first captured packet
        #    already goes through the configured port/pid allowlists.
        self._loader.configure_filters(
            port_filter = self.config.port_filter,
            pid_filter  = self.config.pid_filter,
        )

        # 5. Attach kprobes and kretprobes
        #    After this call, the kernel delivers events to the ring buffer.
        #    The ring buffer is not yet polled — events accumulate until step 8.
        try:
            self._loader.attach_probes()
        except BPFLoaderError as exc:
            logger.error("agent.probe_attach_failed", error=str(exc))
            raise

        # 6. SSL uprobes (non-fatal — agent works without TLS capture)
        if self.config.capture_tls:
            self._ssl_mgr = SSLProbeManager(self._loader, self.config.ssl)
            n = self._ssl_mgr.attach()
            if n == 0:
                logger.warning(
                    "agent.ssl_probes_none_attached",
                    msg = "TLS capture disabled — HTTPS traffic will be encrypted blobs. "
                          "Ensure libssl.so is accessible on the host.",
                )
            else:
                logger.info("agent.ssl_probes_attached", count=n)
        else:
            logger.info("agent.ssl_disabled")

        # 7. Prometheus metrics server (non-fatal)
        if self.config.prometheus.enabled:
            ok = self._metrics_server.start()
            if ok:
                logger.info(
                    "agent.prometheus_started",
                    port = self.config.prometheus.port,
                    path = self.config.prometheus.path,
                )
            else:
                logger.warning("agent.prometheus_start_failed")

        # 8. Open ring buffer and register callback
        #    From this point on, poll() will invoke _on_ring_buffer_event
        #    for every event the kernel writes to the ring buffer.
        self._loader.open_ring_buffer(self._on_ring_buffer_event)

        self._started       = True
        self._last_sweep_ts = time.monotonic()
        self._last_stats_ts = time.monotonic()

        logger.info(
            "agent.started",
            probes     = self._loader.probes_attached,
            ssl_probes = self._ssl_mgr.probe_count if self._ssl_mgr else 0,
            outputs    = len(self._dispatcher),
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Main poll loop
    # ─────────────────────────────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        """
        Main event loop. Blocks on epoll up to 100ms, then does housekeeping.

        100ms timeout balances:
          - Sub-100ms responsiveness to SIGINT
          - ~10 sweep/stats checks per second (cheap)
          - No busy-wait when traffic is idle
        """
        logger.info("agent.capture_active")

        while not self._shutdown:
            # Poll ring buffer — _on_ring_buffer_event fires synchronously
            # for each queued event before poll() returns.
            self._loader.poll(timeout_ms=100)

            now = time.monotonic()

            # Periodic sweep: evict stale connections, read kernel drop counter
            if now - self._last_sweep_ts >= self.config.sweep_interval_s:
                self._sweep(now)
                self._last_sweep_ts = now

            # Periodic stats log
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

        Hot path: keep allocations minimal. All heavy I/O (JSON serialisation,
        file writes, Kafka produce) happens inside EventDispatcher backends
        which are designed to be non-blocking on the write side.

        Flow per event:
          data_ptr → RawEvent.from_ring_buffer()   parse fixed header + payload
              → ConnectionTracker.update()          resolve/update conn state
              → HTTPParser.parse()                  parse HTTP/gRPC/MCP payload
              → EventDispatcher.dispatch()          fan out to output backends
        """
        from src.agent.event_types import EventHeaderCT

        min_size = ctypes.sizeof(EventHeaderCT)
        if size < min_size:
            self._counters.record_malformed()
            return

        # Parse raw event — zero-copy header read, one bytes() copy for payload
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

        # CLOSE events: update conn state, no payload to parse
        if raw_event.meta.direction == Direction.CLOSE:
            self._tracker.update(raw_event)
            self._counters.record_close()
            return

        # Update connection tracker + run protocol detection
        try:
            conn_record = self._tracker.update(raw_event)
        except Exception as exc:
            logger.debug("agent.tracker_error", error=str(exc))
            return

        if conn_record.total_packets == 1:
            self._counters.record_connection_created()

        # Skip if no payload (ACK-only TCP segments carry no application data)
        if not raw_event.payload:
            return

        # Parse payload into structured event
        detection = conn_record.last_result
        if detection is None:
            return

        try:
            parsed = self._parser.parse(raw_event, detection)
        except Exception as exc:
            logger.debug(
                "agent.parse_error",
                error   = str(exc),
                conn_id = f"0x{raw_event.meta.conn_id:016x}",
            )
            self._counters.record_parse_error()
            return

        if parsed.parse_error:
            self._counters.record_parse_error()

        # Fan out to configured output backends (stdout, file, Kafka, etc.)
        try:
            self._dispatcher.dispatch(parsed)
        except Exception as exc:
            logger.debug("agent.dispatch_error", error=str(exc))

    # ─────────────────────────────────────────────────────────────────────────
    # Housekeeping
    # ─────────────────────────────────────────────────────────────────────────

    def _sweep(self, now_mono: float) -> None:
        """
        Evict connections idle for longer than connection_ttl_s.
        Read kernel drop counter and warn if non-zero.
        Update Prometheus active_connections gauge.
        """
        evicted = self._tracker.sweep_expired(time.time_ns())
        active  = len(self._tracker)

        if evicted > 0:
            logger.debug("agent.sweep", evicted=evicted, active=active)

        self._metrics_server.set_active_connections(active)

        # Kernel drops = ring buffer was full; events were silently discarded
        # by the BPF program. Non-zero means ringbuf_size_mb needs increasing.
        drops = self._loader.read_drop_counter()
        if drops > 0:
            self._counters.add_kernel_drops(drops)
            logger.warning(
                "agent.kernel_drops",
                new_drops        = drops,
                total            = self._counters.kernel_drops,
                drop_rate_pct    = round(self._counters.drop_rate_pct, 2),
                recommendation   = (
                    f"Increase ringbuf_size_mb (currently "
                    f"{self.config.ringbuf_size_mb} MB). "
                    "Next power-of-2 value: "
                    f"{self.config.ringbuf_size_mb * 2} MB."
                ),
            )

    def _emit_stats(self) -> None:
        """Log a structured snapshot of all agent counters."""
        snap = self._counters.snapshot()
        disp = self._dispatcher.stats()
        snap.update({
            "output_written":    disp["total_written"],
            "output_errors":     disp["total_errors"],
            "active_connections": len(self._tracker),
            "bpf_mode": "jit" if self.config.bpf_object_path.endswith(".c") else "precompiled",
        })
        logger.info("agent.stats", **snap)

    # ─────────────────────────────────────────────────────────────────────────
    # Eviction callback (called by ConnectionTracker)
    # ─────────────────────────────────────────────────────────────────────────

    def _on_connection_evict(self, record) -> None:
        """
        Called by ConnectionTracker when a connection is evicted
        (LRU overflow, TTL expiry, or explicit CLOSE event).
        Updates the eviction counter; does not raise.
        """
        self._counters.record_eviction()
        logger.debug(
            "agent.connection_evicted",
            conn_id    = record.conn_id_hex,
            protocol   = record.protocol.display_name,
            duration_ms = round(record.duration_ms, 1),
            total_bytes = record.total_bytes,
        )

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
        Graceful shutdown sequence. Always runs via finally in start().

        Order:
          1. Detach all kprobes/kretprobes  — stops new events entering ring buffer
          2. Detach SSL uprobes             — stops new TLS events
          3. Flush + close dispatcher       — drains Kafka producer, webhook queue
          4. Stop Prometheus server
          5. Close BPFLoader                — frees kernel BPF memory + maps
          6. Log final stats
        """
        logger.info("agent.shutting_down")

        # 1. Detach probes — no new events after this
        if self._loader:
            self._loader.detach_probes()

        # 2. SSL cleanup
        if self._ssl_mgr:
            try:
                self._ssl_mgr.detach()
            except Exception:
                pass

        # 3. Drain dispatcher (Kafka flush, webhook queue drain)
        try:
            self._dispatcher.flush()
            self._dispatcher.close()
        except Exception as exc:
            logger.warning("agent.dispatcher_close_error", error=str(exc))

        # 4. Stop Prometheus
        try:
            self._metrics_server.stop()
        except Exception:
            pass

        # 5. Close BPFLoader — releases ring buffer fd, BPF maps, kernel memory
        if self._loader:
            try:
                self._loader.close()
            except Exception:
                pass

        # 6. Final stats
        snap = self._counters.snapshot()
        logger.info(
            "agent.stopped",
            **snap,
            active_connections = len(self._tracker),
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Diagnostics
    # ─────────────────────────────────────────────────────────────────────────

    def health(self) -> dict:
        """
        Return a complete health snapshot. Safe to call at any time.
        Useful for a /healthz HTTP endpoint or admin tooling.
        """
        return {
            "version":    self.VERSION,
            "started":    self._started,
            "shutdown":   self._shutdown,
            "bpf_mode":   "jit" if self.config.bpf_object_path.endswith(".c") else "precompiled",
            "bpf":        self._loader.health().to_dict() if self._loader else None,
            "ssl":        self._ssl_mgr.health() if self._ssl_mgr else None,
            "tracker":    self._tracker.stats(),
            "dispatcher": self._dispatcher.stats(),
            "counters":   self._counters.snapshot(),
        }

    def __repr__(self) -> str:
        state = (
            "running"     if self._started and not self._shutdown else
            "stopped"     if self._shutdown else
            "initialised"
        )
        return (
            f"EBPFAgent(state={state}, "
            f"mode={'jit' if self.config.bpf_object_path.endswith('.c') else 'precompiled'}, "
            f"events={self._counters.events_total}, "
            f"connections={len(self._tracker)})"
        )