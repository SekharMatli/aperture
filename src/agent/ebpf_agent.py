"""
ebpf_agent/agent.py
─────────────────────────────────────────────────────────────────────────────
Core eBPF agent: loads the BPF program, attaches probes, consumes the ring
buffer and dispatches structured events to pluggable output sinks.

Zero-packet-loss strategy
  • Ring buffer sized at 64 MB (configurable) — BPF side never blocks
  • Python consumer runs in a tight loop with no GIL-holding I/O on the
    critical path (perf_buffer_poll replacement with ring_buffer callback)
  • If the ring buffer fills the kernel drops the event and increments a
    counter we surface in metrics; user-space is never the bottleneck
"""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import signal
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, List, Optional

from bcc import BPF, USDT
from bcc.libbcc import lib as bcc_lib

from .config import AgentConfig
from .event import HttpEvent, EventType, Direction
from .kafka_envelope import KafkaEnvelope
from .metrics import MetricsCollector
from .output import OutputSink
from .process_monitor_probe import ProcessMonitorProbe, ProcessEvent
from .ssl_content_probe import SSLContentProbe, SslContentEvent
from .ssl_probe import SSLProbeManager
from .utils.logger import get_logger

logger = get_logger(__name__)

# ─── BPF map / struct layout (must mirror http_capture.bpf.c) ────────────────

MAX_MSG_SIZE = 16384
COMM_LEN = 16


class _HttpEventRaw(ctypes.Structure):
    """ctypes mirror of struct http_event_t in the BPF program."""
    _pack_ = 1
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("conn_id",      ctypes.c_uint64),
        ("pid",          ctypes.c_uint32),
        ("tid",          ctypes.c_uint32),
        ("uid",          ctypes.c_uint32),
        ("gid",          ctypes.c_uint32),
        ("src_addr",     ctypes.c_uint32),
        ("dst_addr",     ctypes.c_uint32),
        ("src_port",     ctypes.c_uint16),
        ("dst_port",     ctypes.c_uint16),
        ("family",       ctypes.c_uint16),
        ("direction",    ctypes.c_uint8),
        ("event_type",   ctypes.c_uint8),
        ("data_len",     ctypes.c_uint32),
        ("seq",          ctypes.c_uint32),
        ("latency_ns",   ctypes.c_uint64),
        ("comm",         ctypes.c_char * COMM_LEN),
        ("data",         ctypes.c_char * MAX_MSG_SIZE),
    ]


class _ConfigMap(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("capture_all_ports",  ctypes.c_uint8),
        ("capture_responses",  ctypes.c_uint8),
        ("filter_by_pid",      ctypes.c_uint8),
        ("target_pid",         ctypes.c_uint32),
        ("max_payload_bytes",  ctypes.c_uint32),
    ]


# ─── Agent ────────────────────────────────────────────────────────────────────

class EBPFAgent:
    """
    Loads the compiled eBPF object, attaches all kprobes/uprobes and pumps
    the ring buffer.  Outputs are delivered to registered OutputSink objects.
    """

    BPF_SRC = Path(__file__).parent.parent / "bpf" / "http_capture.bpf.c"

    def __init__(self, config: AgentConfig) -> None:
        self.config  = config
        self.metrics = MetricsCollector()
        self.sinks:  List[OutputSink] = []
        self._bpf:   Optional[BPF]    = None
        self._stop   = threading.Event()
        self._ssl_mgr: Optional[SSLProbeManager] = None

        # Phase 0 probes
        self._ssl_content_probe: Optional[SSLContentProbe]     = None
        self._proc_monitor_probe: Optional[ProcessMonitorProbe] = None
        self._kafka_envelope: Optional[KafkaEnvelope]           = None

        # Stats
        self._events_received  = 0
        self._events_dropped   = 0
        self._last_stats_ts    = time.monotonic()

    # ── Public API ────────────────────────────────────────────────────────────

    def add_sink(self, sink: OutputSink) -> "EBPFAgent":
        self.sinks.append(sink)
        return self

    def start(self) -> None:
        logger.info("Starting eBPF HTTP agent (pid=%d)", os.getpid())
        self._load_bpf()
        self._configure_maps()
        self._attach_kprobes()
        if self.config.capture_tls:
            self._attach_ssl_uprobes()

        # Phase 0: start SSL content and process monitor probes
        self._start_phase0_probes()

        logger.info("All probes attached — consuming ring buffer")
        self._run_event_loop()

    def stop(self) -> None:
        logger.info("Stopping agent")
        self._stop.set()

    # ── Phase 0: SSL content + process monitor ───────────────────────────────

    def _start_phase0_probes(self) -> None:
        """Start Phase 0 eBPF probes: SSL content capture and process monitor."""

        # Set up Kafka envelope if configured
        agent_key    = self.config.agent_key
        kafka_brokers = self.config.kafka_brokers
        kafka_topic   = self.config.kafka_topic

        if agent_key and kafka_brokers:
            try:
                self._kafka_envelope = KafkaEnvelope(
                    topic     = kafka_topic,
                    brokers   = kafka_brokers,
                    agent_key = agent_key,
                )
                logger.info("KafkaEnvelope initialised topic=%s", kafka_topic)
            except Exception as exc:
                logger.warning("KafkaEnvelope init failed: %s", exc)

        # Start SSL content probe
        if getattr(self.config, "capture_ssl_content", True):
            try:
                self._ssl_content_probe = SSLContentProbe(self.config)
                self._ssl_content_probe.on_event = self._on_ssl_event
                self._ssl_content_probe.start()
                logger.info("SSLContentProbe started")
            except Exception as exc:
                logger.warning("SSLContentProbe failed to start: %s", exc)

        # Start process monitor probe
        if getattr(self.config, "capture_proc_events", True):
            try:
                self._proc_monitor_probe = ProcessMonitorProbe(self.config)
                self._proc_monitor_probe.on_event = self._on_proc_event
                self._proc_monitor_probe.start()
                logger.info("ProcessMonitorProbe started")
            except Exception as exc:
                logger.warning("ProcessMonitorProbe failed to start: %s", exc)

    def _on_ssl_event(self, ev: SslContentEvent) -> None:
        """Callback from SSLContentProbe — route to Kafka and registered sinks."""
        self.metrics.record_ssl(ev)
        payload = ev.to_kafka_dict()

        if self._kafka_envelope:
            self._kafka_envelope.write_ssl(payload, root_pid=ev.root_pid)

        # Notify registered sinks that support SSL events
        for sink in self.sinks:
            if hasattr(sink, "write_ssl"):
                try:
                    sink.write_ssl(ev)
                except Exception as exc:
                    logger.debug("Sink %s ssl error: %s", sink, exc)

        # Also register this pid as an agent with the process monitor
        if self._proc_monitor_probe and ev.pid:
            self._proc_monitor_probe.register_agent_pid(ev.pid, ev.comm)

    def _on_proc_event(self, ev: ProcessEvent) -> None:
        """Callback from ProcessMonitorProbe — route to Kafka and sinks."""
        payload = ev.to_kafka_dict()

        if self._kafka_envelope:
            self._kafka_envelope.write_proc(payload, root_pid=ev.root_pid)

        for sink in self.sinks:
            if hasattr(sink, "write_proc"):
                try:
                    sink.write_proc(ev)
                except Exception as exc:
                    logger.debug("Sink %s proc error: %s", sink, exc)

    # ── BPF loading ───────────────────────────────────────────────────────────

    def _load_bpf(self) -> None:
        cflags = [
            "-O2",
            "-g",
            f"-DMAX_MSG_SIZE={MAX_MSG_SIZE}",
        ]
        if self.config.debug_bpf:
            cflags.append("-DDEBUG")

        logger.debug("Loading BPF from %s", self.BPF_SRC)
        try:
            self._bpf = BPF(src_file=str(self.BPF_SRC), cflags=cflags)
        except Exception as exc:
            logger.error("Failed to load BPF program: %s", exc)
            raise

    def _configure_maps(self) -> None:
        assert self._bpf is not None

        # Write config map
        cfg_map = self._bpf["config_map"]
        key     = ctypes.c_uint32(0)
        cfg     = _ConfigMap()
        cfg.capture_all_ports = int(self.config.capture_all_ports)
        cfg.capture_responses = int(self.config.capture_responses)
        cfg.filter_by_pid     = int(self.config.pid_filter is not None)
        cfg.target_pid        = self.config.pid_filter or 0
        cfg.max_payload_bytes = self.config.max_payload_bytes
        cfg_map[key]          = cfg

        # Write port filter map
        port_map = self._bpf["port_filter"]
        for port in self.config.http_ports:
            k = ctypes.c_uint16(port)
            v = ctypes.c_uint8(1)
            port_map[k] = v
            logger.debug("Watching port %d", port)

    def _attach_kprobes(self) -> None:
        b = self._bpf
        probes = [
            ("tcp_sendmsg",  "kprobe_tcp_sendmsg",    False),
            ("tcp_sendmsg",  "kretprobe_tcp_sendmsg",  True),
            ("tcp_recvmsg",  "kprobe_tcp_recvmsg",    False),
            ("tcp_recvmsg",  "kretprobe_tcp_recvmsg",  True),
            ("tcp_connect",  "kprobe_tcp_connect",    False),
            ("tcp_close",    "kprobe_tcp_close",      False),
        ]
        for fn_name, prog_name, is_ret in probes:
            try:
                if is_ret:
                    b.attach_kretprobe(event=fn_name, fn_name=prog_name)
                else:
                    b.attach_kprobe(event=fn_name, fn_name=prog_name)
                logger.debug("Attached %s → %s", "kretprobe" if is_ret else "kprobe", fn_name)
            except Exception as exc:
                logger.warning("Could not attach %s: %s", fn_name, exc)

    def _attach_ssl_uprobes(self) -> None:
        self._ssl_mgr = SSLProbeManager(self._bpf, self.config)
        self._ssl_mgr.attach()

    # ── Ring buffer event loop ────────────────────────────────────────────────

    def _run_event_loop(self) -> None:
        b = self._bpf

        # Register ring buffer callback
        def _handle_event(ctx, data, size):
            try:
                self._process_raw_event(data, size)
            except Exception as exc:
                logger.debug("Event parse error: %s", exc)
                self._events_dropped += 1

        b["events"].open_ring_buffer(_handle_event)

        # Handle signals gracefully
        signal.signal(signal.SIGINT,  lambda *_: self.stop())
        signal.signal(signal.SIGTERM, lambda *_: self.stop())

        logger.info("Ring buffer open — press Ctrl-C to stop")
        try:
            while not self._stop.is_set():
                # Non-blocking poll; timeout keeps the stop-check responsive
                b.ring_buffer_poll(timeout=100)
                self._maybe_emit_stats()
        finally:
            self._flush_sinks()
            logger.info(
                "Shutdown complete. received=%d dropped=%d",
                self._events_received,
                self._events_dropped,
            )

    # ── Event processing ──────────────────────────────────────────────────────

    def _process_raw_event(self, data, size: int) -> None:
        if size < ctypes.sizeof(_HttpEventRaw):
            return

        raw: _HttpEventRaw = ctypes.cast(data, ctypes.POINTER(_HttpEventRaw)).contents
        self._events_received += 1

        event = self._raw_to_event(raw)
        if event is None:
            return

        self.metrics.record(event)

        # Route through KafkaEnvelope for versioned headers
        if self._kafka_envelope:
            try:
                self._kafka_envelope.write_http(event.to_dict())
            except Exception as exc:
                logger.debug("KafkaEnvelope http error: %s", exc)

        for sink in self.sinks:
            try:
                sink.write(event)
            except Exception as exc:
                logger.debug("Sink %s error: %s", sink, exc)

    def _raw_to_event(self, raw: _HttpEventRaw) -> Optional[HttpEvent]:
        data_len = min(raw.data_len, MAX_MSG_SIZE)
        payload  = bytes(raw.data[:data_len])

        try:
            src_ip = str(ipaddress.IPv4Address(socket.ntohl(raw.src_addr)))
            dst_ip = str(ipaddress.IPv4Address(socket.ntohl(raw.dst_addr)))
        except Exception:
            src_ip = dst_ip = "0.0.0.0"

        return HttpEvent(
            timestamp_ns  = raw.timestamp_ns,
            conn_id       = raw.conn_id,
            pid           = raw.pid,
            tid           = raw.tid,
            uid           = raw.uid,
            comm          = raw.comm.decode("utf-8", errors="replace").rstrip("\x00"),
            src_ip        = src_ip,
            dst_ip        = dst_ip,
            src_port      = raw.src_port,
            dst_port      = raw.dst_port,
            direction     = Direction(raw.direction),
            event_type    = EventType(raw.event_type),
            latency_ns    = raw.latency_ns,
            payload       = payload,
        )

    # ── Housekeeping ──────────────────────────────────────────────────────────

    def _maybe_emit_stats(self) -> None:
        now = time.monotonic()
        if now - self._last_stats_ts < self.config.stats_interval_sec:
            return
        self._last_stats_ts = now
        logger.info(
            "[stats] events_rx=%d events_dropped=%d",
            self._events_received,
            self._events_dropped,
        )
        self.metrics.snapshot()

    def _flush_sinks(self) -> None:
        # Stop Phase 0 probes
        if self._ssl_content_probe:
            try:
                self._ssl_content_probe.stop()
            except Exception:
                pass
        if self._proc_monitor_probe:
            try:
                self._proc_monitor_probe.stop()
            except Exception:
                pass
        if self._kafka_envelope:
            try:
                self._kafka_envelope.flush()
            except Exception:
                pass

        for sink in self.sinks:
            try:
                sink.flush()
            except Exception:
                pass