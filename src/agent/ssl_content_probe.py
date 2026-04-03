"""
src/agent/ssl_content_probe.py
================================
Loads ssl_content.bpf.c, attaches uprobes to SSL_read/SSL_write, and
converts raw ring-buffer events into SslContentEvent dataclass objects.

BoringSSL / statically-linked libraries
-----------------------------------------
Claude Code (Bun), some Node.js builds, and Chromium embed BoringSSL with
symbols stripped.  We locate SSL_read/SSL_write by scanning the binary for
known byte patterns (the function prologue, which is stable within a minor
version).  When --binary-path is provided we use this mechanism; otherwise
we fall back to system libssl.so with nm-based symbol lookup.

SSE (Server-Sent Events) chunk reassembly
------------------------------------------
LLM APIs stream responses as SSE: many small chunks each prefixed with
"data: {...}".  A single SSL_read call may return one chunk or a partial
chunk.  The SSEReassembler buffers chunks per-pid and emits complete JSON
objects when it sees "data: [DONE]" or a configurable flush timeout.

Event envelope compatibility
------------------------------
SslContentEvent.to_kafka_dict() produces a dict with the same top-level
envelope as the existing HTTP event format expected by event_parser.py:
    {
        "timestamp_ns": int,
        "conn_id":       int,   # pid-based synthetic id
        "comm":          str,
        "src_ip":        str,
        "pid":           int,
        "protocol":      "HTTPS",
        "direction":     "EGRESS"|"INGRESS",
        "ssl_content": {        # NEW in schema v2
            "direction":    "write"|"read",
            "data":         str,   # decoded UTF-8
            "data_len":     int,
            "truncated":    bool,
            "seq":          int,
            "is_reassembled": bool,
        }
    }

The consumer's event_parser.py reads the "ssl_content" key when present
and routes to the LLM/SSL processing path.
"""
from __future__ import annotations

import ctypes
import json
import logging
import mmap
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Constants matching ssl_content.bpf.c ─────────────────────────────────────

SSL_CONTENT_MAX = 65536
COMM_LEN        = 16
SSL_DIR_WRITE   = 1
SSL_DIR_READ    = 2

# SSE reassembly constants
_SSE_IDLE_TIMEOUT_S  = 2.0    # flush incomplete SSE buffer after this many seconds
_SSE_MAX_BUFFER_BYTES = 256 * 1024  # 256 KB max buffer per pid before force flush


# ─── ctypes mirror of struct ssl_event_t ──────────────────────────────────────

class _SslEventRaw(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("root_pid",     ctypes.c_uint64),
        ("pid",          ctypes.c_uint32),
        ("tid",          ctypes.c_uint32),
        ("uid",          ctypes.c_uint32),
        ("direction",    ctypes.c_uint8),
        ("is_tls",       ctypes.c_uint8),
        ("truncated",    ctypes.c_uint8),
        ("pad",          ctypes.c_uint8),
        ("data_len",     ctypes.c_uint32),
        ("seq",          ctypes.c_uint32),
        ("comm",         ctypes.c_char * COMM_LEN),
        ("data",         ctypes.c_char * SSL_CONTENT_MAX),
    ]


# ─── ctypes mirror of struct ssl_config_t ─────────────────────────────────────

class _SslConfigMap(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("max_capture_bytes", ctypes.c_uint32),
        ("filter_by_comm",    ctypes.c_uint8),
        ("pad",               ctypes.c_uint8 * 3),
        ("target_comm",       ctypes.c_char * COMM_LEN),
    ]


# ─── SslContentEvent dataclass ────────────────────────────────────────────────

@dataclass
class SslContentEvent:
    """Decoded SSL plaintext event ready for downstream processing."""
    timestamp_ns:   int
    pid:            int
    tid:            int
    uid:            int
    root_pid:       int
    comm:           str
    direction:      str          # "write" | "read"
    data:           bytes        # raw decoded bytes
    data_len:       int
    truncated:      bool
    seq:            int
    is_reassembled: bool = False  # True if SSE chunks were merged

    @property
    def timestamp_ms(self) -> float:
        return self.timestamp_ns / 1_000_000

    def to_kafka_dict(self) -> dict:
        """
        Produces a Kafka message payload compatible with event_parser.py.
        The 'ssl_content' sub-object is parsed by a new branch in _parse_event.
        """
        try:
            decoded = self.data.decode("utf-8", errors="replace")
        except Exception:
            decoded = ""

        return {
            "timestamp_ns":  self.timestamp_ns,
            "conn_id":       (self.pid << 16) | (self.seq & 0xFFFF),
            "pid":           self.pid,
            "comm":          self.comm,
            "src_ip":        "127.0.0.1",    # SSL events have no network addr
            "dst_port":      443,
            "protocol":      "HTTPS",
            "direction":     "EGRESS" if self.direction == "write" else "INGRESS",
            "ssl_content": {
                "direction":      self.direction,
                "data":           decoded,
                "data_len":       self.data_len,
                "truncated":      self.truncated,
                "seq":            self.seq,
                "is_reassembled": self.is_reassembled,
                "root_pid":       self.root_pid,
            },
        }


# ─── SSE Reassembler ──────────────────────────────────────────────────────────

@dataclass
class _SseBuffer:
    pid:      int
    chunks:   List[bytes] = field(default_factory=list)
    last_ts:  float       = field(default_factory=time.monotonic)
    total:    int         = 0   # accumulated byte count

    def append(self, chunk: bytes) -> None:
        self.chunks.append(chunk)
        self.total   += len(chunk)
        self.last_ts  = time.monotonic()

    def flush(self) -> bytes:
        data = b"".join(self.chunks)
        self.chunks.clear()
        self.total = 0
        return data

    def is_complete(self) -> bool:
        """True when we have seen a final SSE marker."""
        combined = b"".join(self.chunks)
        return b"data: [DONE]" in combined or b'"finish_reason"' in combined

    def is_timed_out(self) -> bool:
        return (time.monotonic() - self.last_ts) > _SSE_IDLE_TIMEOUT_S

    def is_oversized(self) -> bool:
        return self.total >= _SSE_MAX_BUFFER_BYTES


class SSEReassembler:
    """
    Buffers SSE chunks per-pid and emits complete payloads.

    Call feed(event) → returns either None (still buffering) or a merged
    SslContentEvent with is_reassembled=True when the stream is complete.
    """

    def __init__(self) -> None:
        self._buffers: Dict[int, _SseBuffer] = {}
        self._lock    = threading.Lock()

    def feed(self, ev: SslContentEvent) -> Optional[SslContentEvent]:
        """
        Feed one raw SSL read event.  Returns a merged event if complete,
        None if still accumulating.
        """
        if ev.direction != "read":
            return ev   # writes are not SSE; pass through immediately

        data = ev.data

        # Detect non-SSE responses immediately (not text/event-stream)
        # If it looks like a normal HTTP response, pass through
        if data.startswith(b"HTTP/") or data.startswith(b"{"):
            return ev

        # Is it SSE data?
        is_sse = b"data: " in data or b"event: " in data

        if not is_sse:
            return ev   # not SSE, pass through

        pid = ev.pid
        with self._lock:
            if pid not in self._buffers:
                self._buffers[pid] = _SseBuffer(pid=pid)
            buf = self._buffers[pid]
            buf.append(data)

            emit = buf.is_complete() or buf.is_oversized()

            if emit:
                merged_data = buf.flush()
                del self._buffers[pid]

                return SslContentEvent(
                    timestamp_ns   = ev.timestamp_ns,
                    pid            = ev.pid,
                    tid            = ev.tid,
                    uid            = ev.uid,
                    root_pid       = ev.root_pid,
                    comm           = ev.comm,
                    direction      = "read",
                    data           = merged_data,
                    data_len       = len(merged_data),
                    truncated      = ev.truncated,
                    seq            = ev.seq,
                    is_reassembled = True,
                )
            return None   # still accumulating

    def flush_stale(self) -> List[SslContentEvent]:
        """
        Called periodically to flush timed-out SSE buffers.
        Returns list of events to emit.
        """
        results: List[SslContentEvent] = []
        with self._lock:
            stale_pids = [
                pid for pid, buf in self._buffers.items()
                if buf.is_timed_out()
            ]
            for pid in stale_pids:
                buf = self._buffers.pop(pid)
                if not buf.chunks:
                    continue
                merged = buf.flush()
                results.append(SslContentEvent(
                    timestamp_ns   = int(time.monotonic() * 1e9),
                    pid            = pid,
                    tid            = 0,
                    uid            = 0,
                    root_pid       = pid,
                    comm           = "unknown",
                    direction      = "read",
                    data           = merged,
                    data_len       = len(merged),
                    truncated      = False,
                    seq            = 0,
                    is_reassembled = True,
                ))
        return results


# ─── BoringSSL pattern scanner ────────────────────────────────────────────────

# Known BoringSSL SSL_write prologue patterns (x86_64).
# These are stable within minor versions and survive symbol stripping.
# Add new patterns as new Claude / Bun versions are released.
_BORING_SSL_WRITE_PATTERNS: List[bytes] = [
    # Bun 1.x BoringSSL SSL_write: push rbp; mov rbp, rsp; push r15; push r14
    bytes([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56]),
    # Alternative: push rbx; sub rsp, N
    bytes([0x53, 0x48, 0x83, 0xEC]),
]

_BORING_SSL_READ_PATTERNS: List[bytes] = [
    bytes([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55]),
    bytes([0x55, 0x48, 0x89, 0xE5, 0x41, 0x56]),
]


def _scan_binary_for_pattern(binary_path: str, pattern: bytes,
                               limit: int = 5) -> List[int]:
    """
    Memory-map `binary_path` and scan for `pattern`.
    Returns up to `limit` file offsets where the pattern was found.
    """
    offsets: List[int] = []
    try:
        with open(binary_path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            pos = 0
            while len(offsets) < limit:
                idx = mm.find(pattern, pos)
                if idx == -1:
                    break
                offsets.append(idx)
                pos = idx + 1
            mm.close()
    except Exception as exc:
        logger.debug("pattern scan failed on %s: %s", binary_path, exc)
    return offsets


def find_boringssl_offsets(binary_path: str) -> Optional[Tuple[int, int]]:
    """
    Attempt to find SSL_write and SSL_read offsets in a BoringSSL binary.
    Returns (write_offset, read_offset) or None if not found.
    """
    write_off: Optional[int] = None
    read_off:  Optional[int] = None

    for pat in _BORING_SSL_WRITE_PATTERNS:
        offsets = _scan_binary_for_pattern(binary_path, pat)
        if offsets:
            write_off = offsets[0]
            logger.info("BoringSSL SSL_write found at offset 0x%x in %s",
                        write_off, binary_path)
            break

    for pat in _BORING_SSL_READ_PATTERNS:
        offsets = _scan_binary_for_pattern(binary_path, pat)
        if offsets:
            read_off = offsets[0]
            logger.info("BoringSSL SSL_read found at offset 0x%x in %s",
                        read_off, binary_path)
            break

    if write_off is not None and read_off is not None:
        return (write_off, read_off)

    logger.warning("BoringSSL pattern scan found write=%s read=%s for %s",
                   write_off, read_off, binary_path)
    return None


# ─── SSLContentProbe — the main loader / probe manager ───────────────────────

class SSLContentProbe:
    """
    Loads ssl_content.bpf.c, attaches uprobes to all SSL libraries found,
    polls the ring buffer, and dispatches SslContentEvent objects to a
    registered callback.

    Designed to run alongside the existing EBPFAgent — they share the same
    process but use separate BPF objects and ring buffers.

    Usage
    -----
        def on_ssl_event(ev: SslContentEvent):
            ...

        probe = SSLContentProbe(config)
        probe.on_event = on_ssl_event
        probe.start()       # non-blocking; starts background thread
        ...
        probe.stop()
    """

    BPF_SRC = Path(__file__).parent.parent / "bpf" / "ssl_content.bpf.c"

    def __init__(self, config) -> None:
        self.config    = config
        self._bpf      = None
        self._stop     = threading.Event()
        self._thread:  Optional[threading.Thread] = None
        self._reassembler = SSEReassembler()
        self.on_event: Optional[Callable[[SslContentEvent], None]] = None

        self._events_rx      = 0
        self._events_dropped = 0

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Load BPF, attach probes, start background poller thread."""
        self._load_bpf()
        self._configure_maps()
        self._attach_all_probes()
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="ssl-content-probe",
            daemon=True,
        )
        self._thread.start()
        logger.info("SSLContentProbe started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(
            "SSLContentProbe stopped rx=%d dropped=%d",
            self._events_rx, self._events_dropped,
        )

    # ── BPF loading ────────────────────────────────────────────────────────────

    def _load_bpf(self) -> None:
        from bcc import BPF
        cflags = [
            "-O2",
            f"-DSSL_CONTENT_MAX={SSL_CONTENT_MAX}",
        ]
        if getattr(self.config, "debug_bpf", False):
            cflags.append("-DDEBUG")

        logger.debug("Loading BPF from %s", self.BPF_SRC)
        try:
            self._bpf = BPF(src_file=str(self.BPF_SRC), cflags=cflags)
        except Exception as exc:
            logger.error("Failed to load ssl_content BPF: %s", exc)
            raise

    def _configure_maps(self) -> None:
        b = self._bpf
        key = ctypes.c_uint32(0)
        cfg = _SslConfigMap()
        cfg.max_capture_bytes = getattr(self.config, "ssl_max_capture_bytes", SSL_CONTENT_MAX)
        cfg.filter_by_comm    = 0   # capture all comms; Python filters

        comm_filter = getattr(self.config, "ssl_comm_filter", None)
        if comm_filter:
            cfg.filter_by_comm = 1
            comm_bytes = comm_filter.encode("utf-8")[:COMM_LEN - 1]
            ctypes.memmove(cfg.target_comm, comm_bytes, len(comm_bytes))

        b["ssl_config_map"][key] = cfg
        logger.debug("SSL config: max_capture=%d filter_comm=%s",
                     cfg.max_capture_bytes,
                     comm_filter or "none")

    # ── Probe attachment ───────────────────────────────────────────────────────

    def _attach_all_probes(self) -> None:
        attached = 0

        # 1. Binary path with BoringSSL pattern matching (Claude Code, Bun, NVM Node)
        binary_paths = getattr(self.config, "ssl_binary_paths", [])
        for bp in binary_paths:
            if os.path.exists(bp):
                attached += self._attach_boringssl(bp)

        # 2. System libssl.so (OpenSSL / system packages)
        ssl_libs = self._find_system_ssl_libs()
        for lib in ssl_libs:
            attached += self._attach_openssl(lib)

        if attached == 0:
            logger.warning(
                "SSLContentProbe: no probes attached. "
                "Set ssl_lib_paths or ssl_binary_paths in config."
            )
        else:
            logger.info("SSLContentProbe: %d probe(s) attached", attached)

    def _find_system_ssl_libs(self) -> List[str]:
        import glob
        patterns = getattr(self.config, "ssl_lib_paths", [
            "/usr/lib/x86_64-linux-gnu/libssl.so*",
            "/usr/lib/aarch64-linux-gnu/libssl.so*",
            "/usr/lib/libssl.so*",
            "/usr/local/lib/libssl.so*",
        ])
        found = []
        for pat in patterns:
            found.extend(glob.glob(pat))
        return list(set(found))

    def _attach_openssl(self, lib_path: str) -> int:
        """Attach by symbol name (OpenSSL with symbols)."""
        b = self._bpf
        count = 0
        for sym, fn, is_ret in [
            ("SSL_write",    "uprobe_ssl_write",       False),
            ("SSL_write_ex", "uprobe_ssl_write_ex",    False),
            ("SSL_read",     "uprobe_ssl_read_entry",  False),
            ("SSL_read",     "uretprobe_ssl_read",     True),
            ("SSL_read_ex",  "uprobe_ssl_read_ex_entry", False),
            ("SSL_read_ex",  "uretprobe_ssl_read_ex",  True),
        ]:
            try:
                if is_ret:
                    b.attach_uretprobe(name=lib_path, sym=sym, fn_name=fn)
                else:
                    b.attach_uprobe(name=lib_path, sym=sym, fn_name=fn)
                count += 1
                logger.debug("Attached %s/%s @ %s", fn, sym, lib_path)
            except Exception as exc:
                logger.debug("Could not attach %s@%s: %s", sym, lib_path, exc)

        if count:
            logger.info("OpenSSL probes (%d) attached on %s", count, lib_path)
        return count

    def _attach_boringssl(self, binary_path: str) -> int:
        """
        Attach by file offset to stripped BoringSSL (Claude Code, Bun).
        Uses pattern matching to find SSL_write / SSL_read offsets.
        """
        result = find_boringssl_offsets(binary_path)
        if result is None:
            logger.warning("BoringSSL: could not find offsets in %s", binary_path)
            return 0

        write_off, read_off = result
        b = self._bpf
        count = 0

        for offset, fn, is_ret in [
            (write_off, "uprobe_ssl_write",       False),
            (read_off,  "uprobe_ssl_read_entry",  False),
            (read_off,  "uretprobe_ssl_read",     True),
        ]:
            try:
                if is_ret:
                    b.attach_uretprobe(name=binary_path, addr=offset, fn_name=fn)
                else:
                    b.attach_uprobe(name=binary_path, addr=offset, fn_name=fn)
                count += 1
                logger.debug("BoringSSL attached %s @ 0x%x in %s", fn, offset, binary_path)
            except Exception as exc:
                logger.warning("BoringSSL attach %s@0x%x failed: %s", fn, offset, exc)

        if count:
            logger.info("BoringSSL probes (%d) attached on %s", count, binary_path)
        return count

    # ── Ring buffer poll loop ─────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        b = self._bpf

        def _handle(ctx, data, size):
            try:
                self._process_raw(data, size)
            except Exception as exc:
                logger.debug("ssl event parse error: %s", exc)
                self._events_dropped += 1

        b["ssl_events"].open_ring_buffer(_handle)

        # Periodic SSE flush timer
        _last_sse_flush = time.monotonic()

        while not self._stop.is_set():
            b.ring_buffer_poll(timeout=100)

            now = time.monotonic()
            if now - _last_sse_flush > 0.5:
                stale = self._reassembler.flush_stale()
                for ev in stale:
                    self._dispatch(ev)
                _last_sse_flush = now

    def _process_raw(self, data, size: int) -> None:
        if size < ctypes.sizeof(_SslEventRaw):
            return

        raw: _SslEventRaw = ctypes.cast(data, ctypes.POINTER(_SslEventRaw)).contents
        self._events_rx += 1

        data_len = min(raw.data_len, SSL_CONTENT_MAX)
        payload  = bytes(raw.data[:data_len])

        ev = SslContentEvent(
            timestamp_ns = raw.timestamp_ns,
            pid          = raw.pid,
            tid          = raw.tid,
            uid          = raw.uid,
            root_pid     = raw.root_pid,
            comm         = raw.comm.decode("utf-8", errors="replace").rstrip("\x00"),
            direction    = "write" if raw.direction == SSL_DIR_WRITE else "read",
            data         = payload,
            data_len     = data_len,
            truncated    = bool(raw.truncated),
            seq          = raw.seq,
        )

        # Pass through SSE reassembler for inbound data
        merged = self._reassembler.feed(ev)
        if merged is not None:
            self._dispatch(merged)

    def _dispatch(self, ev: SslContentEvent) -> None:
        if self.on_event:
            try:
                self.on_event(ev)
            except Exception as exc:
                logger.debug("ssl on_event callback error: %s", exc)