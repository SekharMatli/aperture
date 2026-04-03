"""
src/agent/process_monitor_probe.py
====================================
Loads process_monitor.bpf.c, manages the root_pid_set filter map, polls
the ring buffer, and emits ProcessEvent dataclass objects.

Process tree tracking
---------------------
Every PROC_EXEC event updates our in-memory pid→ppid tree.  This tree is
used to resolve the "root agent pid" for any kernel event — it walks the
parent chain until it finds a pid registered as a root agent.

When the agent discovers a new process_name in the SSL/HTTP stream it calls
register_agent_pid(pid) to add that pid to the BPF root_pid_set so the
kernel filter activates.

fd → path resolution
--------------------
FILE_WRITE events don't carry a path (resolving fd→path in BPF is too
expensive — it requires walking the task file table).  The Python side
resolves /proc/{pid}/fd/{fd} when it receives a FILE_WRITE event.  This
works as long as the process hasn't exited by the time the event reaches
userspace, which is true for >99% of write events.

Kafka envelope
--------------
ProcessEvent.to_kafka_dict() produces:
    {
        "timestamp_ns": int,
        "conn_id":      int,
        "pid":          int,
        "comm":         str,
        "src_ip":       str,
        "protocol":     "KERNEL",
        "direction":    "EGRESS",
        "proc_event": {         # NEW in schema v2
            "event_type":  "exec"|"exit"|"file_open"|"file_write"|"net_connect",
            "root_pid":    int,
            "ppid":        int,
            "retval":      int,
            "path":        str,   # file path or exec filename
            "flags":       int,   # open flags
            "dst_addr":    str,   # dotted-decimal for NET_CONNECT
            "dst_port":    int,
            "bytes_count": int,   # for FILE_WRITE
        }
    }
"""
from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ─── Constants matching process_monitor.bpf.c ─────────────────────────────────

PATH_MAX_CAP = 256
COMM_LEN     = 16

class ProcEventType(IntEnum):
    EXEC        = 1
    EXIT        = 2
    FILE_OPEN   = 3
    FILE_WRITE  = 4
    NET_CONNECT = 5
    NET_BIND    = 6


# ─── ctypes mirror of struct proc_event_t ─────────────────────────────────────

class _ProcEventRaw(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("root_pid",     ctypes.c_uint64),
        ("pid",          ctypes.c_uint32),
        ("ppid",         ctypes.c_uint32),
        ("tid",          ctypes.c_uint32),
        ("uid",          ctypes.c_uint32),
        ("event_type",   ctypes.c_uint8),
        ("pad",          ctypes.c_uint8 * 3),
        ("retval",       ctypes.c_int32),
        ("flags",        ctypes.c_uint32),
        ("dst_addr",     ctypes.c_uint32),
        ("src_addr",     ctypes.c_uint32),
        ("dst_port",     ctypes.c_uint16),
        ("src_port",     ctypes.c_uint16),
        ("bytes_count",  ctypes.c_uint64),
        ("comm",         ctypes.c_char * COMM_LEN),
        ("path",         ctypes.c_char * PATH_MAX_CAP),
    ]


# ─── ProcessEvent dataclass ───────────────────────────────────────────────────

@dataclass
class ProcessEvent:
    timestamp_ns: int
    pid:          int
    ppid:         int
    tid:          int
    uid:          int
    root_pid:     int
    comm:         str
    event_type:   ProcEventType
    retval:       int
    flags:        int
    path:         str
    dst_addr:     str         # dotted-decimal IP
    dst_port:     int
    bytes_count:  int

    # Resolved after the fact
    resolved_path: Optional[str] = None   # fd→path for FILE_WRITE

    @property
    def timestamp_ms(self) -> float:
        return self.timestamp_ns / 1_000_000

    @property
    def event_type_name(self) -> str:
        return self.event_type.name.lower()

    def to_kafka_dict(self) -> dict:
        path = self.resolved_path or self.path
        return {
            "timestamp_ns":  self.timestamp_ns,
            "conn_id":       (self.pid << 16) | (int(self.timestamp_ns) & 0xFFFF),
            "pid":           self.pid,
            "comm":          self.comm,
            "src_ip":        "0.0.0.0",
            "dst_port":      self.dst_port,
            "protocol":      "KERNEL",
            "direction":     "EGRESS",
            "proc_event": {
                "event_type":  self.event_type_name,
                "root_pid":    self.root_pid,
                "ppid":        self.ppid,
                "retval":      self.retval,
                "path":        path,
                "flags":       self.flags,
                "dst_addr":    self.dst_addr,
                "dst_port":    self.dst_port,
                "bytes_count": self.bytes_count,
            },
        }


# ─── In-memory process tree ───────────────────────────────────────────────────

@dataclass
class ProcessNode:
    pid:        int
    ppid:       int
    comm:       str
    started_at: float = field(default_factory=time.monotonic)
    exited_at:  Optional[float] = None
    exit_code:  Optional[int]   = None
    children:   Set[int]        = field(default_factory=set)


class ProcessTree:
    """
    Thread-safe in-memory pid→ProcessNode tree.

    Used to resolve root_pid from a leaf pid, and to answer
    "is this pid a child of a monitored agent?" questions.
    """

    # Max nodes before we GC dead processes
    _MAX_NODES    = 65536
    _GC_TTL_S     = 300.0

    def __init__(self) -> None:
        self._nodes:    Dict[int, ProcessNode] = {}
        self._roots:    Set[int]               = set()   # registered agent root PIDs
        self._lock      = threading.Lock()
        self._last_gc   = time.monotonic()

    def register_root(self, pid: int, comm: str) -> None:
        """Mark a pid as a top-level agent root."""
        with self._lock:
            self._roots.add(pid)
            if pid not in self._nodes:
                self._nodes[pid] = ProcessNode(pid=pid, ppid=0, comm=comm)

    def on_exec(self, pid: int, ppid: int, comm: str) -> None:
        with self._lock:
            node = ProcessNode(pid=pid, ppid=ppid, comm=comm)
            self._nodes[pid] = node
            parent = self._nodes.get(ppid)
            if parent:
                parent.children.add(pid)
            self._maybe_gc()

    def on_exit(self, pid: int, exit_code: int) -> None:
        with self._lock:
            node = self._nodes.get(pid)
            if node:
                node.exited_at = time.monotonic()
                node.exit_code = exit_code
            self._roots.discard(pid)

    def resolve_root_pid(self, pid: int) -> int:
        """Walk ppid chain to find the nearest registered root."""
        with self._lock:
            cur = pid
            seen: Set[int] = set()
            for _ in range(16):
                if cur in seen:
                    break
                seen.add(cur)
                if cur in self._roots:
                    return cur
                node = self._nodes.get(cur)
                if not node or node.ppid == 0 or node.ppid == cur:
                    break
                cur = node.ppid
            return pid   # no root found, use self

    def is_monitored(self, pid: int) -> bool:
        """True if pid is, or is a child of, a registered root."""
        if not self._roots:
            return True   # discovery mode: monitor everything
        root = self.resolve_root_pid(pid)
        return root in self._roots

    def snapshot(self) -> dict:
        """Return a JSON-serialisable process tree snapshot."""
        with self._lock:
            return {
                pid: {
                    "comm":      node.comm,
                    "ppid":      node.ppid,
                    "children":  list(node.children),
                    "exit_code": node.exit_code,
                    "age_s":     round(time.monotonic() - node.started_at, 1),
                }
                for pid, node in self._nodes.items()
            }

    def _maybe_gc(self) -> None:
        """Remove exited nodes older than _GC_TTL_S. Must be called with lock."""
        now = time.monotonic()
        if now - self._last_gc < 60 or len(self._nodes) < self._MAX_NODES:
            return
        cutoff = now - self._GC_TTL_S
        dead = [
            pid for pid, n in self._nodes.items()
            if n.exited_at and n.exited_at < cutoff
        ]
        for pid in dead:
            del self._nodes[pid]
        self._last_gc = now


# ─── fd → path resolver ──────────────────────────────────────────────────────

def resolve_fd_path(pid: int, fd: int) -> Optional[str]:
    """
    Resolve /proc/{pid}/fd/{fd} → real path.
    Returns None if the fd no longer exists (process exited or fd closed).
    """
    link = Path(f"/proc/{pid}/fd/{fd}")
    try:
        return str(link.resolve())
    except (OSError, FileNotFoundError):
        return None


# ─── ProcessMonitorProbe ─────────────────────────────────────────────────────

class ProcessMonitorProbe:
    """
    Loads process_monitor.bpf.c, manages the root_pid_set filter map,
    polls the ring buffer, and emits ProcessEvent objects.

    Usage
    -----
        def on_proc_event(ev: ProcessEvent):
            ...

        probe = ProcessMonitorProbe(config)
        probe.on_event = on_proc_event
        probe.start()

    To add a new agent pid to the kernel filter at runtime:
        probe.register_agent_pid(pid, comm)
    """

    BPF_SRC = Path(__file__).parent.parent / "bpf" / "process_monitor.bpf.c"

    # Sentinel key used to differentiate "empty set = discovery mode"
    # from "filter mode active". When we switch to filter mode we insert
    # this sentinel so should_capture() in BPF knows filters are active.
    _SENTINEL_KEY = 0xFFFFFFFF

    def __init__(self, config) -> None:
        self.config    = config
        self._bpf      = None
        self._stop     = threading.Event()
        self._thread:  Optional[threading.Thread] = None
        self.tree      = ProcessTree()
        self.on_event: Optional[Callable[[ProcessEvent], None]] = None

        self._events_rx      = 0
        self._events_dropped = 0
        self._filter_active  = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._load_bpf()
        # Pre-populate with any PIDs configured at startup
        initial_pids = getattr(self.config, "process_monitor_pids", [])
        for pid in initial_pids:
            comm = self._get_comm(pid)
            self.register_agent_pid(pid, comm)

        self._thread = threading.Thread(
            target=self._poll_loop,
            name="process-monitor-probe",
            daemon=True,
        )
        self._thread.start()
        logger.info("ProcessMonitorProbe started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(
            "ProcessMonitorProbe stopped rx=%d dropped=%d",
            self._events_rx, self._events_dropped,
        )

    def register_agent_pid(self, pid: int, comm: str = "") -> None:
        """
        Add pid to the BPF root_pid_set so the kernel filter captures it
        and all its children.  Safe to call after start().
        """
        if not self._bpf:
            logger.warning("register_agent_pid called before start()")
            return

        self.tree.register_root(pid, comm)

        try:
            pid_key = ctypes.c_uint32(pid)
            val     = ctypes.c_uint8(1)
            self._bpf["root_pid_set"][pid_key] = val

            # Insert sentinel to activate filter mode
            if not self._filter_active:
                sentinel_key = ctypes.c_uint32(self._SENTINEL_KEY)
                sentinel_val = ctypes.c_uint8(1)
                self._bpf["root_pid_set"][sentinel_key] = sentinel_val
                self._filter_active = True

            logger.debug("Registered agent pid=%d comm=%s", pid, comm)
        except Exception as exc:
            logger.warning("Failed to register pid=%d in BPF map: %s", pid, exc)

    def deregister_agent_pid(self, pid: int) -> None:
        """Remove a pid from the BPF filter (e.g. agent exited)."""
        if not self._bpf:
            return
        try:
            pid_key = ctypes.c_uint32(pid)
            del self._bpf["root_pid_set"][pid_key]
        except Exception:
            pass
        self.tree.on_exit(pid, 0)

    def get_process_tree_snapshot(self) -> dict:
        return self.tree.snapshot()

    # ── BPF loading ────────────────────────────────────────────────────────────

    def _load_bpf(self) -> None:
        from bcc import BPF
        cflags = ["-O2"]
        if getattr(self.config, "debug_bpf", False):
            cflags.append("-DDEBUG")
        try:
            self._bpf = BPF(src_file=str(self.BPF_SRC), cflags=cflags)
        except Exception as exc:
            logger.error("Failed to load process_monitor BPF: %s", exc)
            raise

    # ── Ring buffer poll loop ─────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        b = self._bpf

        def _handle(ctx, data, size):
            try:
                self._process_raw(data, size)
            except Exception as exc:
                logger.debug("proc event parse error: %s", exc)
                self._events_dropped += 1

        b["proc_events"].open_ring_buffer(_handle)

        while not self._stop.is_set():
            b.ring_buffer_poll(timeout=100)

    def _process_raw(self, data, size: int) -> None:
        if size < ctypes.sizeof(_ProcEventRaw):
            return

        raw: _ProcEventRaw = ctypes.cast(data, ctypes.POINTER(_ProcEventRaw)).contents
        self._events_rx += 1

        try:
            dst_addr = str(ipaddress.IPv4Address(
                int.from_bytes(raw.dst_addr.to_bytes(4, "little"), "big")
            ))
        except Exception:
            dst_addr = "0.0.0.0"

        ev = ProcessEvent(
            timestamp_ns = raw.timestamp_ns,
            pid          = raw.pid,
            ppid         = raw.ppid,
            tid          = raw.tid,
            uid          = raw.uid,
            root_pid     = int(raw.root_pid),
            comm         = raw.comm.decode("utf-8", errors="replace").rstrip("\x00"),
            event_type   = ProcEventType(raw.event_type),
            retval       = raw.retval,
            flags        = raw.flags,
            path         = raw.path.decode("utf-8", errors="replace").rstrip("\x00"),
            dst_addr     = dst_addr,
            dst_port     = raw.dst_port,
            bytes_count  = raw.bytes_count,
        )

        # Update in-memory tree
        if ev.event_type == ProcEventType.EXEC:
            self.tree.on_exec(ev.pid, ev.ppid, ev.comm)
        elif ev.event_type == ProcEventType.EXIT:
            self.tree.on_exit(ev.pid, ev.retval)

        # Resolve fd→path for write events
        if ev.event_type == ProcEventType.FILE_WRITE and ev.retval > 0:
            resolved = resolve_fd_path(ev.pid, ev.retval)
            if resolved:
                ev.resolved_path = resolved

        # Re-resolve root_pid using our Python tree (more complete than BPF map)
        ev.root_pid = self.tree.resolve_root_pid(ev.pid)

        if self.on_event:
            try:
                self.on_event(ev)
            except Exception as exc:
                logger.debug("proc on_event callback error: %s", exc)

    @staticmethod
    def _get_comm(pid: int) -> str:
        try:
            return Path(f"/proc/{pid}/comm").read_text().strip()
        except Exception:
            return "unknown"