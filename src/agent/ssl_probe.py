"""
ssl_probe.py
============
Attaches uprobes to OpenSSL / BoringSSL shared libraries to capture
plaintext before encryption (SSL_write) and after decryption (SSL_read).

Why uprobes instead of TLS-layer kprobes?
-----------------------------------------
The kernel only sees encrypted bytes after SSL_write completes and before
SSL_read returns. By hooking *inside* the library at userspace level, we
capture plaintext that is structurally identical to what the application
code sees — HTTP headers, gRPC frames, MCP JSON — before the TLS record
layer wraps it.

Probe placement
---------------
  SSL_write  entry   buf pointer is plaintext BEING SENT   (EGRESS)
  SSL_read   return  buf contains plaintext JUST RECEIVED  (INGRESS)
             ↑ return probe (uretprobe) is required for SSL_read
             because the buffer is filled by the kernel during the call

The BPF program at the uprobe sites reads the buf argument, stamps the
event with conn metadata (looked up from the SSL* pointer via the
connections map), and submits it to the same ring buffer as the kprobes.
This means the rest of the pipeline (protocol detector, parser, dispatcher)
sees SSL events exactly like any other TCP event.

Library discovery
-----------------
  1. Config ssl.lib_paths (explicit overrides)
  2. ld.so.cache  via ldconfig -p  (standard system libraries)
  3. Hardcoded fallback glob patterns (covers most distros)

Process-level SSL probing
--------------------------
For processes that statically link OpenSSL (Node.js, Python, Go), the
library is part of the executable rather than a shared object. Discovery
for these cases uses /proc/<pid>/maps to find loaded memory regions.
SSLProbeManager.attach_to_pid() handles this path.
"""

from __future__ import annotations

import glob
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Library discovery
# ─────────────────────────────────────────────────────────────────────────────

# Fallback glob patterns when ldconfig is unavailable
_OPENSSL_GLOBS = [
    "/usr/lib/x86_64-linux-gnu/libssl.so*",
    "/usr/lib/aarch64-linux-gnu/libssl.so*",
    "/usr/lib/arm-linux-gnueabihf/libssl.so*",
    "/usr/lib64/libssl.so*",
    "/usr/lib/libssl.so*",
    "/lib/x86_64-linux-gnu/libssl.so*",
    "/lib/libssl.so*",
    "/usr/local/lib/libssl.so*",
    "/usr/local/ssl/lib/libssl.so*",
]

# BoringSSL embedded in Chrome/Chromium
_BORING_GLOBS = [
    "/opt/google/chrome/libssl.so",
    "/opt/google/chrome-beta/libssl.so",
    "/usr/lib/chromium/libssl.so",
    "/usr/lib/chromium-browser/libssl.so",
    "/snap/chromium/*/usr/lib/chromium-browser/libssl.so*",
]

# Symbols to probe (try in order, stop at first success per library)
_WRITE_SYMBOLS  = ["SSL_write", "SSL_write_ex"]
_READ_SYMBOLS   = ["SSL_read",  "SSL_read_ex"]


def discover_ssl_libs(extra_paths: Optional[List[str]] = None) -> List[str]:
    """
    Return a deduplicated list of libssl.so paths present on this system.

    Discovery order:
      1. extra_paths from config (explicit overrides — highest priority)
      2. ldconfig -p output (covers standard system installs)
      3. Fallback glob patterns (when ldconfig not available)
      4. BoringSSL embedded libs (Chrome etc.)
    """
    found: List[str] = []

    # 1. Explicit overrides
    if extra_paths:
        for p in extra_paths:
            if Path(p).exists():
                found.append(p)

    # 2. ldconfig -p
    try:
        out = subprocess.check_output(
            ["ldconfig", "-p"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        for line in out.splitlines():
            # Lines look like: "	libssl.so.3 (libc6,x86-64) => /lib/x86_64-linux-gnu/libssl.so.3"
            if "libssl.so" in line and "=>" in line:
                lib_path = line.split("=>")[-1].strip()
                if Path(lib_path).exists():
                    found.append(lib_path)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass

    # 3. Glob fallback
    if not found:
        for pattern in _OPENSSL_GLOBS:
            found.extend(glob.glob(pattern))

    # 4. BoringSSL
    for pattern in _BORING_GLOBS:
        found.extend(glob.glob(pattern))

    # Deduplicate preserving order, resolve symlinks so we don't attach twice
    seen:   set  = set()
    result: List[str] = []
    for p in found:
        try:
            real = str(Path(p).resolve())
        except OSError:
            real = p
        if real not in seen:
            seen.add(real)
            result.append(p)  # keep original path for BCC (resolves internally)

    return result


def symbol_exists_in_lib(lib_path: str, symbol: str) -> bool:
    """
    Return True if `symbol` is exported from `lib_path`.
    Uses `nm -D` (dynamic symbol table) — fast and reliable.
    """
    try:
        out = subprocess.check_output(
            ["nm", "-D", "--defined-only", lib_path],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        return f" {symbol}\n" in out or out.endswith(f" {symbol}")
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return True  # Optimistically try to attach if nm not available


# ─────────────────────────────────────────────────────────────────────────────
# Per-process SSL discovery (statically linked binaries)
# ─────────────────────────────────────────────────────────────────────────────

def get_ssl_regions_for_pid(pid: int) -> List[Tuple[str, int]]:
    """
    Parse /proc/<pid>/maps to find loaded regions containing SSL symbols.

    Returns a list of (path, base_addr) tuples for regions that look like
    SSL libraries (either shared objects or the main executable for
    statically linked builds).

    This is used for per-process SSL probing when the library is
    embedded in the binary rather than loaded as a shared object.
    """
    maps_path = Path(f"/proc/{pid}/maps")
    if not maps_path.exists():
        return []

    regions: List[Tuple[str, int]] = []
    seen_paths: set = set()

    try:
        for line in maps_path.read_text().splitlines():
            # Format: addr-addr perms offset dev inode pathname
            parts = line.split()
            if len(parts) < 6:
                continue
            path = parts[5]
            if path in seen_paths or path.startswith("["):
                continue
            if "libssl" in path or "openssl" in path or "boringssl" in path:
                addr_range = parts[0]
                base_hex   = addr_range.split("-")[0]
                try:
                    base_addr = int(base_hex, 16)
                    seen_paths.add(path)
                    regions.append((path, base_addr))
                except ValueError:
                    pass
    except (OSError, PermissionError):
        pass

    return regions


# ─────────────────────────────────────────────────────────────────────────────
# SSLProbeManager
# ─────────────────────────────────────────────────────────────────────────────

class SSLProbeManager:
    """
    Manages attachment and detachment of SSL/TLS uprobes.

    Usage
    -----
        mgr = SSLProbeManager(bpf_loader, config.ssl)
        mgr.attach()
        # ... agent runs ...
        mgr.detach()   # or let BPF object GC handle it

    The BPF program must define:
        uprobe_ssl_write   — entry probe for SSL_write / SSL_write_ex
        uprobe_ssl_read    — return probe for SSL_read / SSL_read_ex

    These handler names are passed as fn_name to BCC attach_uprobe /
    attach_uretprobe. They must match the SEC("uprobe/...") annotations
    in the BPF C source.

    Parameters
    ----------
    bpf_loader : BPFLoader
        Loaded BPF object (from bpf_loader.py). Must have .bpf attribute.

    ssl_config : SSLConfig
        Configuration from AgentConfig.ssl.
    """

    # BPF handler function names (must match http_capture.c SEC annotations)
    _WRITE_HANDLER = "uprobe_ssl_write"
    _READ_HANDLER  = "uprobe_ssl_read_ret"

    def __init__(self, bpf_loader: Any, ssl_config: Any) -> None:
        self._bpf_loader  = bpf_loader
        self._ssl_config  = ssl_config
        self._attached:   List[Dict[str, Any]] = []  # records for detach
        self._lib_count   = 0
        self._probe_count = 0

    # ── Public interface ──────────────────────────────────────────────────────

    def attach(self) -> int:
        """
        Discover libssl and attach uprobes to all found libraries.

        Returns the number of probe pairs successfully attached.
        Logs a warning if no libraries are found — agent continues
        without TLS capture rather than aborting.
        """
        if not self._ssl_config.enabled:
            logger.info("ssl_probe.disabled", reason="ssl.enabled=false in config")
            return 0

        libs = discover_ssl_libs(self._ssl_config.lib_paths or None)

        if not libs:
            logger.warning(
                "ssl_probe.no_libs_found",
                msg="No libssl.so found — TLS plaintext capture disabled. "
                    "Set ssl.lib_paths in config to specify paths explicitly.",
            )
            return 0

        self._lib_count = len(libs)
        logger.info("ssl_probe.libs_discovered",
                    count=len(libs), paths=libs[:5])  # log at most 5

        for lib_path in libs:
            self._attach_lib(lib_path)

        logger.info("ssl_probe.attached",
                    libs=self._lib_count,
                    probes=self._probe_count)
        return self._probe_count

    def attach_to_pid(self, pid: int) -> int:
        """
        Attach uprobes for SSL in a specific process (statically linked).

        Scans /proc/<pid>/maps to find SSL regions, then attaches
        per-process uprobes (BCC's pid= parameter restricts the probe
        to fire only when that PID executes the instrumented function).

        Returns the number of probes attached.
        """
        regions = get_ssl_regions_for_pid(pid)
        if not regions:
            logger.debug("ssl_probe.no_ssl_regions", pid=pid)
            return 0

        count = 0
        for lib_path, _ in regions:
            count += self._attach_lib(lib_path, pid=pid)

        logger.info("ssl_probe.pid_attached", pid=pid, probes=count)
        return count

    def detach(self) -> None:
        """
        Detach all uprobes. Idempotent.
        BCC also cleans up automatically when the BPF object is destroyed,
        so this is only needed for explicit mid-run detachment.
        """
        bpf = self._bpf_loader.bpf

        for record in self._attached:
            lib  = record["lib"]
            sym  = record["symbol"]
            kind = record["kind"]  # "uprobe" or "uretprobe"
            pid  = record.get("pid")

            try:
                if kind == "uprobe":
                    if pid:
                        bpf.detach_uprobe(name=lib, sym=sym, pid=pid)
                    else:
                        bpf.detach_uprobe(name=lib, sym=sym)
                else:
                    if pid:
                        bpf.detach_uretprobe(name=lib, sym=sym, pid=pid)
                    else:
                        bpf.detach_uretprobe(name=lib, sym=sym)
                logger.debug("ssl_probe.detached", lib=lib, sym=sym, kind=kind)
            except Exception as exc:
                logger.debug("ssl_probe.detach_error",
                             lib=lib, sym=sym, error=str(exc))

        self._attached.clear()
        self._probe_count = 0
        logger.info("ssl_probe.all_detached")

    @property
    def probe_count(self) -> int:
        return self._probe_count

    @property
    def lib_count(self) -> int:
        return self._lib_count

    def health(self) -> dict:
        return {
            "enabled":     self._ssl_config.enabled,
            "lib_count":   self._lib_count,
            "probe_count": self._probe_count,
            "attached":    [
                {"lib": r["lib"], "symbol": r["symbol"], "kind": r["kind"]}
                for r in self._attached
            ],
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _attach_lib(self, lib_path: str, pid: Optional[int] = None) -> int:
        """
        Attach write + read uprobes to one library path.
        Returns the number of probes attached (0, 1, or 2).
        """
        bpf    = self._bpf_loader.bpf
        count  = 0

        # Write probe (entry) — buf is plaintext being sent
        for sym in _WRITE_SYMBOLS:
            if not symbol_exists_in_lib(lib_path, sym):
                continue
            try:
                kwargs = {"name": lib_path, "sym": sym,
                          "fn_name": self._WRITE_HANDLER}
                if pid:
                    kwargs["pid"] = pid
                bpf.attach_uprobe(**kwargs)
                self._attached.append({
                    "lib": lib_path, "symbol": sym,
                    "kind": "uprobe", "pid": pid,
                })
                self._probe_count += 1
                count             += 1
                logger.debug("ssl_probe.write_attached",
                             lib=lib_path, sym=sym, pid=pid)
                break  # one write probe per lib is sufficient
            except Exception as exc:
                logger.debug("ssl_probe.write_attach_failed",
                             lib=lib_path, sym=sym, error=str(exc))

        # Read probe (return) — buf contains plaintext just received
        for sym in _READ_SYMBOLS:
            if not symbol_exists_in_lib(lib_path, sym):
                continue
            try:
                kwargs = {"name": lib_path, "sym": sym,
                          "fn_name": self._READ_HANDLER}
                if pid:
                    kwargs["pid"] = pid
                bpf.attach_uretprobe(**kwargs)
                self._attached.append({
                    "lib": lib_path, "symbol": sym,
                    "kind": "uretprobe", "pid": pid,
                })
                self._probe_count += 1
                count             += 1
                logger.debug("ssl_probe.read_attached",
                             lib=lib_path, sym=sym, pid=pid)
                break  # one read probe per lib is sufficient
            except Exception as exc:
                logger.debug("ssl_probe.read_attach_failed",
                             lib=lib_path, sym=sym, error=str(exc))

        return count