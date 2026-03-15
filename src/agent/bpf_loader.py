"""
Handles both pre-compiled .o files and JIT compilation from .c source via BCC.
Clean attach/detach lifecycle.
"""

"""
bpf_loader.py
=============
Loads the compiled eBPF object, attaches probes, manages the ring buffer,
and provides the poll interface to the agent's main event loop.

Responsibilities
----------------
1. Load the BPF program from either:
     a) A pre-compiled ELF .o file   (production — built with clang/llvm)
     b) A C source .c file           (development — JIT-compiled by BCC)

2. Attach / detach all kprobes and kretprobes cleanly:
     kprobe/tcp_sendmsg       → probe_tcp_sendmsg
     kprobe/tcp_recvmsg       → probe_tcp_recvmsg_entry
     kretprobe/tcp_recvmsg    → probe_tcp_recvmsg_exit
     kprobe/tcp_close         → probe_tcp_close

3. Configure BPF maps before the first probe fires:
     port_filter   — allowlist of TCP ports to capture (empty = all)
     pid_filter    — allowlist of PIDs to capture      (empty = all)

4. Expose the ring buffer via open_ring_buffer() and poll(), using BCC's
   epoll-based wakeup — no busy-waiting, sub-millisecond latency.

5. Read the kernel-side drop counter (drop_counter percpu array) so the
   agent can emit drop-rate metrics and alerts.

6. Provide a HealthSnapshot at any time: probe attach state, ring buffer
   size, kernel drops, and the BPF verifier log if load failed.

Design constraints
------------------
- Exactly one BPFLoader instance per agent process.
- load() must be called before any other method.
- detach_probes() is idempotent — safe to call multiple times.
- close() releases all BPF resources; BPFLoader must not be used after.
- All errors are raised as BPFLoaderError with a descriptive message and
  the raw BCC/OS error attached as __cause__.

Kernel requirements
-------------------
- Linux 5.8+  for BPF_MAP_TYPE_RINGBUF
- CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN  (or run as root)
- debugfs mounted at /sys/kernel/debug    (for kprobe attachment)
- kernel headers installed                (for BCC source compilation)

BCC compatibility
-----------------
BCC Python bindings ship under two package names depending on distro:
  - python3-bpfcc   (Debian/Ubuntu — imports as `bcc`)
  - bcc             (pip — imports as `bcc`)
Both are tried; a clear error is raised if neither is available.
"""

from __future__ import annotations

import ctypes
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import structlog

from src.agent.event_types import EventHeaderCT, RawEvent

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# BCC import with clear error message
# ─────────────────────────────────────────────────────────────────────────────

_bcc_module: Any = None
_bcc_error:  Optional[str] = None

def _import_bcc() -> Any:
    """
    Import the BCC Python module, trying both known package locations.

    Returns the BCC module on success.
    Raises BPFLoaderError with install instructions on failure.
    """
    global _bcc_module, _bcc_error

    if _bcc_module is not None:
        return _bcc_module

    try:
        import bcc as _bcc                           # pip / upstream
        _bcc_module = _bcc
        return _bcc_module
    except ImportError:
        pass

    try:
        import bpfcc as _bcc                         # some Debian builds
        _bcc_module = _bcc
        return _bcc_module
    except ImportError:
        pass

    _bcc_error = (
        "BCC Python bindings not found.\n"
        "Install on Ubuntu/Debian:\n"
        "  sudo apt-get install python3-bpfcc bpfcc-tools libbpfcc-dev\n"
        "Install via pip (requires kernel headers):\n"
        "  pip install bcc\n"
        "See: https://github.com/iovisor/bcc/blob/master/INSTALL.md"
    )
    raise BPFLoaderError(_bcc_error)


# ─────────────────────────────────────────────────────────────────────────────
# Probe definitions
#
# Each entry: (kernel_function, bpf_handler_name, is_kretprobe)
# Must exactly match the SEC() annotations and handler names in http_capture.c
# ─────────────────────────────────────────────────────────────────────────────

_PROBES: List[Tuple[str, str, bool]] = [
    ("tcp_sendmsg",   "probe_tcp_sendmsg",        False),  # kprobe
    ("tcp_recvmsg",   "probe_tcp_recvmsg_entry",  False),  # kprobe
    ("tcp_recvmsg",   "probe_tcp_recvmsg_exit",   True),   # kretprobe
    ("tcp_close",     "probe_tcp_close",           False),  # kprobe
]

# Map names as declared in http_capture.c (used as keys into bpf["<name>"])
_MAP_EVENTS        = "events"
_MAP_DROP_COUNTER  = "drop_counter"
_MAP_PORT_FILTER   = "port_filter"
_MAP_PID_FILTER    = "pid_filter"

# BPF compile flags for source-mode compilation
_BPF_CFLAGS = [
    "-O2",
    "-g",
    "-D__TARGET_ARCH_x86",
    # Include paths for kernel headers
    f"-I/usr/include/{os.uname().machine}-linux-gnu",
    "-I/usr/include",
    "-Wall",
    "-Wno-unused-value",
    "-Wno-pointer-sign",
    "-Wno-compare-distinct-pointer-types",
]


# ─────────────────────────────────────────────────────────────────────────────
# Error types
# ─────────────────────────────────────────────────────────────────────────────

class BPFLoaderError(Exception):
    """
    Raised for all BPFLoader failures.

    Attributes
    ----------
    message : str
        Human-readable description of what went wrong.
    verifier_log : str, optional
        Raw BPF verifier output, if available. Present when a BPF program
        fails to load due to a verifier rejection.
    """
    def __init__(self, message: str, verifier_log: str = ""):
        super().__init__(message)
        self.verifier_log = verifier_log

    def __str__(self) -> str:
        s = super().__str__()
        if self.verifier_log:
            s += f"\n\nBPF Verifier log:\n{self.verifier_log}"
        return s


# ─────────────────────────────────────────────────────────────────────────────
# Health snapshot
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class HealthSnapshot:
    """
    Point-in-time health view of the BPF loader.
    Returned by BPFLoader.health(); safe to log as a dict.
    """
    loaded:            bool             # BPF program successfully loaded
    probes_attached:   bool             # all kprobes/kretprobes attached
    bpf_path:          str              # path to the .c or .o file loaded
    ringbuf_size_mb:   int              # ring buffer size in MB
    kernel_drops:      int              # cumulative drops from drop_counter
    port_filter_count: int              # number of ports in filter (0 = all)
    pid_filter_count:  int              # number of PIDs in filter  (0 = all)
    attached_probes:   List[str]        = field(default_factory=list)
    load_error:        Optional[str]    = None

    def to_dict(self) -> dict:
        return {
            "loaded":            self.loaded,
            "probes_attached":   self.probes_attached,
            "bpf_path":          self.bpf_path,
            "ringbuf_size_mb":   self.ringbuf_size_mb,
            "kernel_drops":      self.kernel_drops,
            "port_filter_count": self.port_filter_count,
            "pid_filter_count":  self.pid_filter_count,
            "attached_probes":   self.attached_probes,
            "load_error":        self.load_error,
        }


# ─────────────────────────────────────────────────────────────────────────────
# BPFLoader
# ─────────────────────────────────────────────────────────────────────────────

class BPFLoader:
    """
    Manages the full lifecycle of the eBPF capture program.

    Usage pattern (mirrors EBPFAgent.start())
    -----------------------------------------
        loader = BPFLoader(
            bpf_path       = "src/bpf/http_capture.c",
            ringbuf_size_mb = 256,
        )
        loader.load()
        loader.configure_filters(port_filter=[80, 443, 8080],
                                  pid_filter=[])
        loader.attach_probes()

        # Main event loop
        loader.open_ring_buffer(callback)
        while running:
            loader.poll(timeout_ms=100)
            if time.monotonic() - last_check > 5:
                drops = loader.read_drop_counter()
                if drops: logger.warning("kernel drops", count=drops)
                last_check = time.monotonic()

        loader.detach_probes()
        loader.close()

    Parameters
    ----------
    bpf_path : str
        Path to the BPF program. Two modes:
          *.c  — compiled at runtime by BCC (requires kernel headers + clang)
          *.o  — pre-compiled ELF, loaded directly (faster, no clang needed)

    ringbuf_size_mb : int
        Ring buffer size in MB. Must be a power of 2. Default: 256.
        Increase if drop_counter grows under sustained high-traffic load.
        The ring buffer is allocated in kernel memory at load time.

    cflags : list of str, optional
        Additional -D or -I flags passed to BCC when compiling .c source.
        The default _BPF_CFLAGS are always included; these are appended.
    """

    def __init__(
        self,
        bpf_path:        str,
        ringbuf_size_mb: int        = 256,
        cflags:          List[str]  = None,
    ):
        self._path           = Path(bpf_path)
        self._ringbuf_size   = ringbuf_size_mb * 1024 * 1024
        self._extra_cflags   = cflags or []

        # State
        self._bpf:               Any      = None   # BCC BPF object
        self._ring_buf_mgr:      Any      = None   # BCC RingBuf manager
        self._loaded:            bool     = False
        self._probes_attached:   bool     = False
        self._attached_list:     List[str] = []

        # Cumulative drop counter baseline (we report deltas, not totals)
        self._drop_baseline:     int      = 0

        # Filter counts for health reporting
        self._port_filter_count: int      = 0
        self._pid_filter_count:  int      = 0

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def load(self) -> None:
        """
        Load the BPF program into the kernel.

        Selects source vs object mode based on file extension.
        Validates the path exists and the ring buffer size is a power of 2.

        Raises
        ------
        BPFLoaderError
            If the file is not found, the size is invalid, BCC is not
            installed, or the BPF verifier rejects the program.
        """
        self._validate_preconditions()
        bcc = _import_bcc()

        logger.info("bpf_loader.loading",
                    path=str(self._path),
                    mode="source" if self._path.suffix == ".c" else "object",
                    ringbuf_mb=self._ringbuf_size // (1024 * 1024))

        try:
            if self._path.suffix == ".c":
                self._load_from_source(bcc)
            elif self._path.suffix == ".o":
                self._load_from_object(bcc)
            else:
                raise BPFLoaderError(
                    f"Unsupported BPF file extension: {self._path.suffix!r}. "
                    "Expected .c (source) or .o (compiled object)."
                )
        except BPFLoaderError:
            raise
        except Exception as exc:
            # Wrap BCC exceptions with a clear message
            verifier = getattr(exc, "verifier_log", "") or ""
            raise BPFLoaderError(
                f"Failed to load BPF program from {self._path}: {exc}"
            ) from exc

        self._loaded = True
        logger.info("bpf_loader.loaded",
                    path=str(self._path),
                    ringbuf_mb=self._ringbuf_size // (1024 * 1024))

    def configure_filters(
        self,
        port_filter: List[int],
        pid_filter:  List[int],
    ) -> None:
        """
        Write port and PID allowlists into the BPF filter maps.

        Must be called after load() and before attach_probes() so that
        no packets are captured before the filters are in place.

        Filter activation convention (mirrors http_capture.c):
          - An empty list means "capture everything" — the sentinel key 0
            is NOT written, so the kernel helper returns "filter inactive".
          - A non-empty list writes sentinel key 0 first (activates filter
            mode), then writes each allowed port/PID.

        Parameters
        ----------
        port_filter : list of int
            TCP port numbers to capture (src or dst).
            Empty list → capture all ports.

        pid_filter : list of int
            Process IDs to capture.
            Empty list → capture all PIDs.
        """
        self._assert_loaded()

        if port_filter:
            port_map = self._bpf[_MAP_PORT_FILTER]
            # Sentinel key 0 activates filter mode in the BPF program
            port_map[ctypes.c_uint16(0)] = ctypes.c_uint8(1)
            for port in port_filter:
                if not (1 <= port <= 65535):
                    logger.warning("bpf_loader.invalid_port", port=port)
                    continue
                port_map[ctypes.c_uint16(port)] = ctypes.c_uint8(1)
            self._port_filter_count = len(port_filter)
            logger.info("bpf_loader.port_filter_set",
                        ports=port_filter, count=len(port_filter))
        else:
            self._port_filter_count = 0
            logger.info("bpf_loader.port_filter_disabled")

        if pid_filter:
            pid_map = self._bpf[_MAP_PID_FILTER]
            pid_map[ctypes.c_uint32(0)] = ctypes.c_uint8(1)
            for pid in pid_filter:
                if pid <= 0:
                    logger.warning("bpf_loader.invalid_pid", pid=pid)
                    continue
                pid_map[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
            self._pid_filter_count = len(pid_filter)
            logger.info("bpf_loader.pid_filter_set",
                        pids=pid_filter, count=len(pid_filter))
        else:
            self._pid_filter_count = 0
            logger.info("bpf_loader.pid_filter_disabled")

    def attach_probes(self) -> None:
        """
        Attach all kprobes and kretprobes defined in _PROBES.

        Probes are attached in definition order. If any attachment fails,
        already-attached probes are detached before raising, leaving the
        system in a clean state.

        After this call returns, the kernel will begin delivering events
        to the ring buffer on every tcp_sendmsg, tcp_recvmsg, tcp_close.

        Raises
        ------
        BPFLoaderError
            If any probe cannot be attached (kernel function not found,
            missing capabilities, debugfs not mounted, etc.).
        """
        self._assert_loaded()

        if self._probes_attached:
            logger.warning("bpf_loader.probes_already_attached")
            return

        for kernel_fn, handler_fn, is_ret in _PROBES:
            try:
                if is_ret:
                    self._bpf.attach_kretprobe(
                        event   = kernel_fn,
                        fn_name = handler_fn,
                    )
                else:
                    self._bpf.attach_kprobe(
                        event   = kernel_fn,
                        fn_name = handler_fn,
                    )
                probe_label = f"{'kretprobe' if is_ret else 'kprobe'}/{kernel_fn}"
                self._attached_list.append(probe_label)
                logger.info("bpf_loader.probe_attached",
                            kernel_fn=kernel_fn,
                            handler=handler_fn,
                            kret=is_ret)

            except Exception as exc:
                # Roll back everything attached so far
                logger.error("bpf_loader.probe_attach_failed",
                             kernel_fn=kernel_fn, handler=handler_fn,
                             error=str(exc))
                self.detach_probes()
                raise BPFLoaderError(
                    f"Failed to attach {'kretprobe' if is_ret else 'kprobe'} "
                    f"on {kernel_fn!r} → {handler_fn!r}: {exc}"
                ) from exc

        self._probes_attached = True
        logger.info("bpf_loader.all_probes_attached",
                    count=len(self._attached_list),
                    probes=self._attached_list)

    def detach_probes(self) -> None:
        """
        Detach all probes. Idempotent — safe to call multiple times.

        After this returns, no new events will be delivered to the ring
        buffer. Events already in the ring buffer can still be drained
        by continuing to call poll().

        Errors during detach are logged but not raised — a cleanup path
        must not itself raise.
        """
        if not self._bpf:
            return

        for kernel_fn, handler_fn, is_ret in _PROBES:
            try:
                if is_ret:
                    self._bpf.detach_kretprobe(event=kernel_fn)
                else:
                    self._bpf.detach_kprobe(event=kernel_fn)
                logger.info("bpf_loader.probe_detached",
                            kernel_fn=kernel_fn, kret=is_ret)
            except Exception as exc:
                # Non-fatal: probe may already have been detached
                logger.warning("bpf_loader.probe_detach_error",
                               kernel_fn=kernel_fn, error=str(exc))

        self._probes_attached = False
        self._attached_list.clear()
        logger.info("bpf_loader.probes_detached")

    def close(self) -> None:
        """
        Release all BPF resources and free kernel memory.

        Calls detach_probes() first, then BCC cleanup(). After this
        call, BPFLoader must not be used.

        Safe to call even if load() was never called (no-op).
        """
        if self._bpf is None:
            return

        self.detach_probes()

        try:
            self._bpf.cleanup()
        except Exception as exc:
            logger.warning("bpf_loader.cleanup_error", error=str(exc))

        self._bpf        = None
        self._ring_buf_mgr = None
        self._loaded     = False
        logger.info("bpf_loader.closed")

    # ── Ring buffer interface ──────────────────────────────────────────────────

    def open_ring_buffer(
        self,
        callback: Callable[[int, ctypes.c_void_p, int], None],
    ) -> None:
        """
        Register an event callback with the ring buffer and open the
        epoll file descriptor.

        The callback is called once per event with:
            callback(cpu, data_ptr, size)

        Where:
            cpu      : int            — CPU that produced the event (informational)
            data_ptr : ctypes.c_void_p — pointer to ring buffer memory
                                         Layout: [EventHeaderCT][payload bytes]
            size     : int            — total bytes reserved (header + payload)

        The caller is responsible for parsing data_ptr using
        RawEvent.from_ring_buffer(data_ptr, size). See event_types.py.

        This must be called after attach_probes() and before poll().

        Parameters
        ----------
        callback
            Function to call for each ring buffer event.
            Must not raise — exceptions are caught and logged.
        """
        self._assert_loaded()

        events_map  = self._bpf[_MAP_EVENTS]
        events_fd   = events_map.get_fd()
        ring_buf_mgr = self._bpf.get_table("events")

        # Wrap the user callback to guard against exceptions
        def _safe_callback(cpu: int, data: ctypes.c_void_p, size: int) -> None:
            try:
                callback(cpu, data, size)
            except Exception as exc:
                logger.warning("bpf_loader.callback_exception",
                               cpu=cpu, size=size, error=str(exc))

        ring_buf_mgr.open_ring_buffer(events_fd, _safe_callback)
        self._ring_buf_mgr = ring_buf_mgr

        logger.info("bpf_loader.ring_buffer_opened",
                    ringbuf_mb=self._ringbuf_size // (1024 * 1024))

    def poll(self, timeout_ms: int = 100) -> int:
        """
        Block for up to timeout_ms milliseconds waiting for ring buffer events.

        Uses epoll internally (via BCC's ring buffer manager). When events
        are available, the registered callback is invoked synchronously for
        each one before poll() returns.

        Parameters
        ----------
        timeout_ms : int
            Maximum time to block. 0 = non-blocking drain. Default: 100.

        Returns
        -------
        int
            0 on timeout (no events), positive if events were processed.

        Raises
        ------
        BPFLoaderError
            If open_ring_buffer() has not been called.
        """
        if self._ring_buf_mgr is None:
            raise BPFLoaderError(
                "poll() called before open_ring_buffer(). "
                "Call open_ring_buffer(callback) first."
            )
        return self._ring_buf_mgr.poll(timeout_ms)

    # ── Drop counter ──────────────────────────────────────────────────────────

    def read_drop_counter(self) -> int:
        """
        Read the cumulative per-CPU drop counter from the kernel.

        The drop counter increments each time bpf_ringbuf_reserve() fails
        because the ring buffer is full. This is the definitive zero-loss
        indicator: if this value grows, increase ringbuf_size_mb or reduce
        traffic volume.

        Returns the count of drops since the previous call to this method
        (delta, not total). This lets the caller emit a rate metric without
        needing to track state.

        Returns 0 if the map is not accessible (e.g. during shutdown).
        """
        if not self._loaded or self._bpf is None:
            return 0

        try:
            # drop_counter is BPF_MAP_TYPE_PERCPU_ARRAY
            # Summing all CPUs gives the total across the system
            total = sum(self._bpf[_MAP_DROP_COUNTER].values())
            delta = total - self._drop_baseline
            if delta > 0:
                self._drop_baseline = total
            return max(0, delta)
        except Exception as exc:
            logger.debug("bpf_loader.drop_counter_read_error", error=str(exc))
            return 0

    def total_kernel_drops(self) -> int:
        """
        Return the cumulative total drops since load() was called.
        Unlike read_drop_counter(), this does NOT advance the baseline.
        """
        if not self._loaded or self._bpf is None:
            return 0
        try:
            return sum(self._bpf[_MAP_DROP_COUNTER].values())
        except Exception:
            return 0

    # ── Map access ────────────────────────────────────────────────────────────

    def get_map(self, name: str) -> Any:
        """
        Return a BCC map object by name (as defined in http_capture.c).

        Use for diagnostic inspection, not for hot-path access.

        Parameters
        ----------
        name : str
            BPF map name, e.g. "connections", "port_filter", "events".

        Raises
        ------
        BPFLoaderError  if not loaded.
        KeyError        if the map name does not exist.
        """
        self._assert_loaded()
        return self._bpf[name]

    # ── Health ────────────────────────────────────────────────────────────────

    def health(self) -> HealthSnapshot:
        """
        Return a point-in-time health snapshot.

        Safe to call at any time, even before load().
        """
        return HealthSnapshot(
            loaded            = self._loaded,
            probes_attached   = self._probes_attached,
            bpf_path          = str(self._path),
            ringbuf_size_mb   = self._ringbuf_size // (1024 * 1024),
            kernel_drops      = self.total_kernel_drops(),
            port_filter_count = self._port_filter_count,
            pid_filter_count  = self._pid_filter_count,
            attached_probes   = list(self._attached_list),
            load_error        = None,
        )

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def probes_attached(self) -> bool:
        return self._probes_attached

    @property
    def bpf(self) -> Any:
        """
        Direct access to the underlying BCC BPF object.

        Intended for advanced use (e.g. reading the connections map for
        diagnostic tooling). Prefer the typed methods above for all normal
        agent operations.

        Raises BPFLoaderError if not loaded.
        """
        self._assert_loaded()
        return self._bpf

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _validate_preconditions(self) -> None:
        """
        Check preconditions before attempting to load.

        Validates:
          - File exists
          - Extension is .c or .o
          - ringbuf_size is a power of 2
          - Running as root (or has CAP_BPF) — checked via euid
        """
        if not self._path.exists():
            raise BPFLoaderError(
                f"BPF program not found: {self._path}\n"
                "For source mode, run: make -C src/bpf\n"
                "For compiled mode, build the .o first."
            )

        if self._path.suffix not in (".c", ".o"):
            raise BPFLoaderError(
                f"Unsupported extension {self._path.suffix!r}. "
                "Expected .c (source) or .o (compiled ELF)."
            )

        # Ring buffer must be power-of-2 bytes (kernel enforces this)
        size = self._ringbuf_size
        if size <= 0 or (size & (size - 1)) != 0:
            raise BPFLoaderError(
                f"ringbuf_size must be a power of 2, got {size} bytes "
                f"({size // (1024*1024)} MB). "
                "Valid values: 64, 128, 256, 512, 1024, 2048 MB."
            )

        if os.geteuid() != 0:
            logger.warning(
                "bpf_loader.not_root",
                msg="Loading BPF typically requires root or CAP_BPF. "
                    "Proceeding — may fail with EPERM.",
            )

    def _load_from_source(self, bcc: Any) -> None:
        """
        Compile and load the BPF C source file via BCC.

        This path requires:
          - clang / llvm installed
          - Kernel headers for the running kernel
          - The BCC library itself

        The RINGBUF_SIZE macro is injected as a -D flag so the C source
        uses the size configured in Python rather than its own default.
        """
        source_text = self._path.read_text(encoding="utf-8")

        cflags = list(_BPF_CFLAGS)
        cflags.append(f"-DRINGBUF_SIZE={self._ringbuf_size}")
        cflags.extend(self._extra_cflags)

        logger.debug("bpf_loader.compiling",
                     path=str(self._path), cflags=cflags)

        try:
            self._bpf = bcc.BPF(text=source_text, cflags=cflags)
        except Exception as exc:
            # BCC surfaces compile/verifier errors as generic exceptions.
            # Try to extract the verifier log from the exception message.
            verifier_log = _extract_verifier_log(str(exc))
            raise BPFLoaderError(
                f"BCC failed to compile {self._path}: {exc}",
                verifier_log=verifier_log,
            ) from exc

    def _load_from_object(self, bcc: Any) -> None:
        """
        Load a pre-compiled BPF ELF object file.

        The .o file must have been compiled with:
          clang -O2 -g -target bpf -D__TARGET_ARCH_x86 ...
              -DRINGBUF_SIZE=<size>
              -c http_capture.c -o http_capture.o

        Note: BCC's obj= parameter loads the ELF and runs the BPF verifier
        but does NOT recompile; the RINGBUF_SIZE embedded at compile time
        is used, not the Python-side ringbuf_size_mb setting.
        """
        try:
            self._bpf = bcc.BPF(obj=str(self._path))
        except Exception as exc:
            verifier_log = _extract_verifier_log(str(exc))
            raise BPFLoaderError(
                f"Failed to load BPF object {self._path}: {exc}",
                verifier_log=verifier_log,
            ) from exc

    def _assert_loaded(self) -> None:
        """Raise BPFLoaderError if load() has not been called successfully."""
        if not self._loaded or self._bpf is None:
            raise BPFLoaderError(
                "BPFLoader.load() must be called before using this method."
            )


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _extract_verifier_log(exc_text: str) -> str:
    """
    Try to extract the BPF verifier log from a BCC exception message.

    BCC surfaces verifier output inline in the exception string.
    This function isolates the verifier section to make error messages
    more actionable.
    """
    marker = "BPF program load failed:"
    idx = exc_text.find(marker)
    if idx != -1:
        return exc_text[idx + len(marker):].strip()
    # Fallback: return the full exception text
    return exc_text[:2000]   # cap at 2KB to avoid log flooding


def check_bcc_available() -> bool:
    """
    Return True if BCC Python bindings are importable, False otherwise.
    Does not raise. Use for pre-flight checks and feature gates.
    """
    try:
        _import_bcc()
        return True
    except BPFLoaderError:
        return False


def check_kernel_version() -> Tuple[int, int, int]:
    """
    Return the running kernel version as (major, minor, patch).

    Raises BPFLoaderError if the version cannot be determined.
    The minimum required version for ring buffer support is 5.8.0.
    """
    try:
        ver_str = os.uname().release          # e.g. "6.1.0-27-amd64"
        parts   = ver_str.split("-")[0].split(".")
        major   = int(parts[0])
        minor   = int(parts[1]) if len(parts) > 1 else 0
        patch   = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except Exception as exc:
        raise BPFLoaderError(
            f"Cannot determine kernel version from uname: {exc}"
        ) from exc


def assert_kernel_supported() -> None:
    """
    Raise BPFLoaderError if the kernel does not support BPF ring buffers.
    Minimum required: Linux 5.8.0.
    """
    major, minor, patch = check_kernel_version()
    if (major, minor) < (5, 8):
        raise BPFLoaderError(
            f"Kernel {major}.{minor}.{patch} does not support "
            "BPF_MAP_TYPE_RINGBUF (requires Linux 5.8+). "
            "Upgrade your kernel or use BPF_MAP_TYPE_PERF_EVENT_ARRAY instead."
        )