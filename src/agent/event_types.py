"""
ctypes structs that exactly mirror the C structs.
Any mismatch = silent corruption bugs, so these are carefully aligned.
Also contains Pythonic EventMeta, HTTPEvent dataclasses.
"""
"""
event_types.py
==============
Python mirror of every C struct defined in src/bpf/http_capture.c.

Rules that MUST be maintained when the C source changes:
  1. Field order must be identical to the C struct.
  2. ctypes type widths must match __u8/__u16/__u32/__u64/char exactly.
  3. Explicit padding fields (pad[N]) must be present — never let ctypes
     infer them; use pack=1 is intentionally NOT used so natural alignment
     is preserved and matches what the C compiler produces on x86-64.
  4. Run verify_layout() after any struct change to catch mismatches
     before they silently corrupt events at runtime.

Verified struct sizes (x86-64, gcc/clang default alignment):
  ConnTupleCT   = 16 bytes
  ConnMetaCT    = 56 bytes
  EventHeaderCT = 72 bytes

Byte layout diagram for EventHeaderCT (most performance-critical):
  offset  0:  timestamp_ns  (u64,  8 bytes)
  offset  8:  conn_id       (u64,  8 bytes)
  offset 16:  pid           (u32,  4 bytes)
  offset 20:  tid           (u32,  4 bytes)
  offset 24:  uid           (u32,  4 bytes)
  offset 28:  src_ip4       (u32,  4 bytes)
  offset 32:  dst_ip4       (u32,  4 bytes)
  offset 36:  src_port      (u16,  2 bytes)
  offset 38:  dst_port      (u16,  2 bytes)
  offset 40:  direction     (u8,   1 byte )
  offset 41:  protocol      (u8,   1 byte )
  offset 42:  ip_version    (u8,   1 byte )
  offset 43:  truncated     (u8,   1 byte )
  offset 44:  comm          (char, 16 bytes)
  offset 60:  payload_len   (u32,  4 bytes)
  offset 64:  original_len  (u32,  4 bytes)
  total:      72 bytes
"""

from __future__ import annotations

import ctypes
import enum
import ipaddress
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Constants — must match #define values in http_capture.c exactly
# ─────────────────────────────────────────────────────────────────────────────

COMM_LEN        = 16    # COMM_LEN in C (matches kernel TASK_COMM_LEN)
MAX_PAYLOAD     = 65536 # MAX_PAYLOAD_SIZE in C

# Direction values (DIR_* in C)
DIR_EGRESS      = 1
DIR_INGRESS     = 2
DIR_CLOSE       = 3

# Protocol values (PROTO_* in C)
PROTO_UNKNOWN   = 0
PROTO_HTTP1     = 1
PROTO_HTTP2     = 2
PROTO_GRPC      = 3
PROTO_WEBSOCKET = 4
PROTO_MCP       = 5
PROTO_TLS       = 6
PROTO_HTTP1_TLS = 7
PROTO_HTTP2_TLS = 8


# ─────────────────────────────────────────────────────────────────────────────
# Enums — Python-friendly wrappers around the C integer constants
# ─────────────────────────────────────────────────────────────────────────────

class Direction(enum.IntEnum):
    """Maps to DIR_* constants in http_capture.c."""
    EGRESS  = DIR_EGRESS    # tcp_sendmsg  (client → server)
    INGRESS = DIR_INGRESS   # tcp_recvmsg  (server → client)
    CLOSE   = DIR_CLOSE     # tcp_close    (connection teardown)

    @property
    def label(self) -> str:
        return {
            Direction.EGRESS:  "→",
            Direction.INGRESS: "←",
            Direction.CLOSE:   "✕",
        }[self]


class Protocol(enum.IntEnum):
    """Maps to PROTO_* constants in http_capture.c."""
    UNKNOWN   = PROTO_UNKNOWN
    HTTP1     = PROTO_HTTP1
    HTTP2     = PROTO_HTTP2
    GRPC      = PROTO_GRPC
    WEBSOCKET = PROTO_WEBSOCKET
    MCP       = PROTO_MCP
    TLS       = PROTO_TLS
    HTTP1_TLS = PROTO_HTTP1_TLS
    HTTP2_TLS = PROTO_HTTP2_TLS

    @property
    def display_name(self) -> str:
        return {
            Protocol.UNKNOWN:   "unknown",
            Protocol.HTTP1:     "HTTP/1.x",
            Protocol.HTTP2:     "HTTP/2",
            Protocol.GRPC:      "gRPC",
            Protocol.WEBSOCKET: "WebSocket",
            Protocol.MCP:       "MCP",
            Protocol.TLS:       "TLS",
            Protocol.HTTP1_TLS: "HTTP/1.x+TLS",
            Protocol.HTTP2_TLS: "HTTP/2+TLS",
        }[self]

    @property
    def is_encrypted(self) -> bool:
        return self in (Protocol.TLS, Protocol.HTTP1_TLS, Protocol.HTTP2_TLS)

    @property
    def is_http(self) -> bool:
        return self in (Protocol.HTTP1, Protocol.HTTP2,
                        Protocol.HTTP1_TLS, Protocol.HTTP2_TLS,
                        Protocol.GRPC)


# ─────────────────────────────────────────────────────────────────────────────
# ctypes structs — byte-exact mirrors of C structs in http_capture.c
#
# Naming convention: suffix CT (CType) distinguishes raw C-mirror structs
# from the higher-level Python dataclasses below.
# ─────────────────────────────────────────────────────────────────────────────

class ConnTupleCT(ctypes.Structure):
    """
    Mirror of:  struct conn_tuple  (http_capture.c)
    Size:       16 bytes
    Used as:    hash map key in BPF connections map

    Field notes:
      src_ip4 / dst_ip4 — network byte order (big-endian) as stored by kernel
      src_port / dst_port — host byte order (kernel converts skc_dport)
    """
    _fields_ = [
        ("src_ip4",   ctypes.c_uint32),   # +0  network byte order
        ("dst_ip4",   ctypes.c_uint32),   # +4  network byte order
        ("src_port",  ctypes.c_uint16),   # +8  host byte order
        ("dst_port",  ctypes.c_uint16),   # +10 host byte order
        ("pid",       ctypes.c_uint32),   # +12
    ]
    # Expected size: 16 bytes


class ConnMetaCT(ctypes.Structure):
    """
    Mirror of:  struct conn_meta  (http_capture.c)
    Size:       56 bytes
    Used as:    hash map value in BPF connections map

    Field notes:
      pad[3] is explicit in both C and Python — never elide it.
      comm[16] is null-padded (may not be null-terminated if process name
      fills all 16 bytes exactly).
    """
    _fields_ = [
        ("conn_id",       ctypes.c_uint64),       # +0
        ("first_seen_ns", ctypes.c_uint64),       # +8
        ("last_seen_ns",  ctypes.c_uint64),       # +16
        ("src_ip4",       ctypes.c_uint32),       # +24
        ("dst_ip4",       ctypes.c_uint32),       # +28
        ("src_port",      ctypes.c_uint16),       # +32
        ("dst_port",      ctypes.c_uint16),       # +34
        ("protocol",      ctypes.c_uint8),        # +36
        ("_pad",          ctypes.c_uint8 * 3),    # +37 explicit padding
        ("comm",          ctypes.c_char * COMM_LEN),  # +40
    ]
    # Expected size: 56 bytes


class EventHeaderCT(ctypes.Structure):
    """
    Mirror of:  struct event_header  (http_capture.c)
    Size:       72 bytes

    This is the fixed-size prefix of every ring buffer event.
    It is immediately followed in memory by `payload_len` bytes of raw
    TCP payload data.

    Zero-copy access pattern:
        hdr  = ctypes.cast(data_ptr, ctypes.POINTER(EventHeaderCT)).contents
        body = bytes(ctypes.cast(data_ptr + 72, ctypes.POINTER(
                   ctypes.c_char * hdr.payload_len)).contents)

    Field notes:
      timestamp_ns  — kernel monotonic clock (ktime_get_ns), NOT wall clock.
                      Convert to wall time by adding the boot-time offset.
      conn_id       — stable for the lifetime of one TCP connection.
                      Reset on reconnect even to the same port.
      direction     — DIR_EGRESS(1) / DIR_INGRESS(2) / DIR_CLOSE(3)
      protocol      — PROTO_* value detected at kernel probe time.
                      May be PROTO_UNKNOWN(0) for non-HTTP traffic.
      ip_version    — always 4 currently; IPv6 support in future revision.
      truncated     — 1 if payload was clipped; original_len shows true size.
      payload_len   — bytes of payload actually stored in this event.
      original_len  — bytes in the original TCP segment before clipping.
    """
    _fields_ = [
        ("timestamp_ns",  ctypes.c_uint64),           # +0
        ("conn_id",       ctypes.c_uint64),           # +8
        ("pid",           ctypes.c_uint32),           # +16
        ("tid",           ctypes.c_uint32),           # +20
        ("uid",           ctypes.c_uint32),           # +24
        ("src_ip4",       ctypes.c_uint32),           # +28
        ("dst_ip4",       ctypes.c_uint32),           # +32
        ("src_port",      ctypes.c_uint16),           # +36
        ("dst_port",      ctypes.c_uint16),           # +38
        ("direction",     ctypes.c_uint8),            # +40
        ("protocol",      ctypes.c_uint8),            # +41
        ("ip_version",    ctypes.c_uint8),            # +42
        ("truncated",     ctypes.c_uint8),            # +43
        ("comm",          ctypes.c_char * COMM_LEN),  # +44  (16 bytes)
        ("payload_len",   ctypes.c_uint32),           # +60
        ("original_len",  ctypes.c_uint32),           # +64
    ]
    # Expected size: 72 bytes

    EXPECTED_SIZE = 72

    def payload_ptr(self) -> ctypes.c_void_p:
        """
        Returns a void pointer to the payload bytes that immediately
        follow this header in the ring buffer reservation.

        Usage:
            raw = ctypes.string_at(hdr.payload_ptr(), hdr.payload_len)
        """
        base = ctypes.addressof(self)
        return ctypes.c_void_p(base + ctypes.sizeof(EventHeaderCT))


# ─────────────────────────────────────────────────────────────────────────────
# Layout verification
#
# Called once at import time and whenever the module is run directly.
# Raises AssertionError immediately if any size or offset is wrong,
# making struct mismatches fail loudly rather than silently corrupt data.
# ─────────────────────────────────────────────────────────────────────────────

def verify_layout() -> None:
    """
    Assert that all ctypes struct sizes and critical field offsets match
    the values computed from the C source.

    This is a canary — if you change a struct in http_capture.c without
    updating this file, this function will raise AssertionError before
    any events are processed.
    """

    # ── ConnTupleCT ───────────────────────────────────────────────
    assert ctypes.sizeof(ConnTupleCT) == 16, (
        f"ConnTupleCT size mismatch: got {ctypes.sizeof(ConnTupleCT)}, expected 16"
    )
    assert ConnTupleCT.src_ip4.offset  == 0
    assert ConnTupleCT.dst_ip4.offset  == 4
    assert ConnTupleCT.src_port.offset == 8
    assert ConnTupleCT.dst_port.offset == 10
    assert ConnTupleCT.pid.offset      == 12

    # ── ConnMetaCT ────────────────────────────────────────────────
    assert ctypes.sizeof(ConnMetaCT) == 56, (
        f"ConnMetaCT size mismatch: got {ctypes.sizeof(ConnMetaCT)}, expected 56"
    )
    assert ConnMetaCT.conn_id.offset       == 0
    assert ConnMetaCT.first_seen_ns.offset == 8
    assert ConnMetaCT.last_seen_ns.offset  == 16
    assert ConnMetaCT.src_ip4.offset       == 24
    assert ConnMetaCT.dst_ip4.offset       == 28
    assert ConnMetaCT.src_port.offset      == 32
    assert ConnMetaCT.dst_port.offset      == 34
    assert ConnMetaCT.protocol.offset      == 36
    assert ConnMetaCT.comm.offset          == 40

    # ── EventHeaderCT ─────────────────────────────────────────────
    assert ctypes.sizeof(EventHeaderCT) == EventHeaderCT.EXPECTED_SIZE, (
        f"EventHeaderCT size mismatch: "
        f"got {ctypes.sizeof(EventHeaderCT)}, "
        f"expected {EventHeaderCT.EXPECTED_SIZE}"
    )
    assert EventHeaderCT.timestamp_ns.offset == 0
    assert EventHeaderCT.conn_id.offset      == 8
    assert EventHeaderCT.pid.offset          == 16
    assert EventHeaderCT.tid.offset          == 20
    assert EventHeaderCT.uid.offset          == 24
    assert EventHeaderCT.src_ip4.offset      == 28
    assert EventHeaderCT.dst_ip4.offset      == 32
    assert EventHeaderCT.src_port.offset     == 36
    assert EventHeaderCT.dst_port.offset     == 38
    assert EventHeaderCT.direction.offset    == 40
    assert EventHeaderCT.protocol.offset     == 41
    assert EventHeaderCT.ip_version.offset   == 42
    assert EventHeaderCT.truncated.offset    == 43
    assert EventHeaderCT.comm.offset         == 44
    assert EventHeaderCT.payload_len.offset  == 60
    assert EventHeaderCT.original_len.offset == 64


# Run at import time — fail fast if structs are wrong
verify_layout()


# ─────────────────────────────────────────────────────────────────────────────
# Helper: decode IPv4 from kernel's network-byte-order uint32
# ─────────────────────────────────────────────────────────────────────────────

def _decode_ip4(raw: int) -> str:
    """
    Convert a uint32 in network byte order (as stored by the kernel in
    skc_rcv_saddr / skc_daddr) to a dotted-decimal string.

    The kernel stores IP addresses in network byte order. Python's
    socket.inet_ntoa expects a 4-byte big-endian bytes object, so we
    pack the integer as big-endian before decoding.
    """
    return socket.inet_ntoa(struct.pack(">I", raw))


# ─────────────────────────────────────────────────────────────────────────────
# High-level Python dataclasses
#
# These are what the rest of the agent works with. They are decoded from the
# raw ctypes structs at the ring buffer boundary — nowhere else.
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class ConnectionKey:
    """
    Immutable 4-tuple + PID, suitable as a dict key or set member.
    Decoded from ConnTupleCT.

    frozen=True ensures accidental mutation doesn't corrupt tracking state.
    """
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    pid:      int

    @classmethod
    def from_ctype(cls, ct: ConnTupleCT) -> "ConnectionKey":
        return cls(
            src_ip   = _decode_ip4(ct.src_ip4),
            dst_ip   = _decode_ip4(ct.dst_ip4),
            src_port = ct.src_port,
            dst_port = ct.dst_port,
            pid      = ct.pid,
        )

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}"


@dataclass(slots=True)
class EventMeta:
    """
    Decoded metadata from EventHeaderCT.

    This is the immutable identity of one captured TCP event.
    The raw payload bytes are stored separately in RawEvent to keep
    this struct cheap to copy and log.

    Timestamp note:
        timestamp_ns is kernel monotonic time (ktime_get_ns).
        It is NOT a Unix timestamp. To convert to wall time, add
        the boot-time offset available in /proc/stat or via clock_gettime
        with CLOCK_REALTIME vs CLOCK_MONOTONIC comparison at startup.
    """
    # Timing
    timestamp_ns:   int         # kernel monotonic nanoseconds

    # Connection identity
    conn_id:        int         # stable per-connection 64-bit ID

    # Process identity
    pid:            int
    tid:            int
    uid:            int
    comm:           str         # process name (up to 15 chars + null)

    # Network 4-tuple (decoded to strings for easy use)
    src_ip:         str         # dotted-decimal
    dst_ip:         str
    src_port:       int         # host byte order
    dst_port:       int

    # Event classification
    direction:      Direction
    protocol:       Protocol
    ip_version:     int         # 4 (IPv6 reserved for future use)

    # Payload descriptor
    payload_len:    int         # bytes stored in this event
    original_len:   int         # bytes in original TCP segment
    truncated:      bool        # payload_len < original_len

    @classmethod
    def from_ctype(cls, hdr: EventHeaderCT) -> "EventMeta":
        """
        Decode a raw EventHeaderCT into a Python EventMeta.

        This is the only place EventMeta instances are created — all
        other code receives EventMeta by value, never constructs it.
        """
        # Decode process name: strip null bytes, fallback to hex pid
        try:
            comm = hdr.comm.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            comm = f"pid:{hdr.pid}"

        # Safe enum conversion — unknown values map to sentinel
        try:
            direction = Direction(hdr.direction)
        except ValueError:
            direction = Direction.EGRESS   # safest assumption

        try:
            protocol = Protocol(hdr.protocol)
        except ValueError:
            protocol = Protocol.UNKNOWN

        return cls(
            timestamp_ns  = hdr.timestamp_ns,
            conn_id       = hdr.conn_id,
            pid           = hdr.pid,
            tid           = hdr.tid,
            uid           = hdr.uid,
            comm          = comm,
            src_ip        = _decode_ip4(hdr.src_ip4),
            dst_ip        = _decode_ip4(hdr.dst_ip4),
            src_port      = hdr.src_port,
            dst_port      = hdr.dst_port,
            direction     = direction,
            protocol      = protocol,
            ip_version    = hdr.ip_version,
            payload_len   = hdr.payload_len,
            original_len  = hdr.original_len,
            truncated     = bool(hdr.truncated),
        )

    @property
    def conn_id_hex(self) -> str:
        """Connection ID as a compact hex string for logging."""
        return f"0x{self.conn_id:016x}"

    @property
    def src(self) -> str:
        """Source endpoint as 'ip:port'."""
        return f"{self.src_ip}:{self.src_port}"

    @property
    def dst(self) -> str:
        """Destination endpoint as 'ip:port'."""
        return f"{self.dst_ip}:{self.dst_port}"

    @property
    def is_close(self) -> bool:
        return self.direction == Direction.CLOSE

    @property
    def is_egress(self) -> bool:
        return self.direction == Direction.EGRESS

    @property
    def is_ingress(self) -> bool:
        return self.direction == Direction.INGRESS

    def to_dict(self) -> dict:
        """
        Serialise to a plain dict safe for JSON output.
        No bytes values — all fields are ints, strings, or bools.
        """
        return {
            "timestamp_ns":  self.timestamp_ns,
            "conn_id":       self.conn_id_hex,
            "pid":           self.pid,
            "tid":           self.tid,
            "uid":           self.uid,
            "comm":          self.comm,
            "src":           self.src,
            "dst":           self.dst,
            "direction":     self.direction.name,
            "protocol":      self.protocol.display_name,
            "ip_version":    self.ip_version,
            "payload_len":   self.payload_len,
            "original_len":  self.original_len,
            "truncated":     self.truncated,
        }


@dataclass(slots=True)
class RawEvent:
    """
    One complete ring buffer event: metadata + raw payload bytes.

    This is the type that crosses from the ring buffer poll loop into
    the protocol processor pipeline. Keep it small — payload is bytes
    (immutable, reference-counted) so it is safe to pass between threads.

    Lifecycle:
        1. Ring buffer callback creates RawEvent from ctypes memory.
        2. Protocol dispatcher routes on meta.protocol.
        3. Parser (HTTP1Parser, HTTP2Parser, etc.) decodes payload.
        4. Output dispatcher serialises to JSON / Kafka / file.
    """
    meta:    EventMeta
    payload: bytes      # raw TCP payload (may be empty for CLOSE events)

    @classmethod
    def from_ring_buffer(cls,
                          data: ctypes.c_void_p,
                          size: int) -> Optional["RawEvent"]:
        """
        Construct a RawEvent from the raw memory pointer delivered by
        BCC's ring buffer callback.

        Parameters
        ----------
        data : ctypes.c_void_p
            Pointer to start of ring buffer reservation.
            Layout: [EventHeaderCT (72 bytes)][payload bytes...]
        size : int
            Total reservation size in bytes (header + payload).

        Returns None if the event is malformed (too small, bad size).

        This method must be fast — it is called once per captured packet
        on the ring buffer poll thread.
        """
        header_size = ctypes.sizeof(EventHeaderCT)

        # Minimum sanity check: must be at least a full header
        if size < header_size:
            return None

        # Map ctypes struct over the raw memory (zero-copy)
        hdr = ctypes.cast(data, ctypes.POINTER(EventHeaderCT)).contents

        # Validate payload_len is consistent with reservation size
        # (guards against ring buffer corruption or BPF verifier bugs)
        claimed_total = header_size + hdr.payload_len
        if claimed_total > size:
            # Truncate to what we actually have rather than segfaulting
            safe_payload_len = size - header_size
        else:
            safe_payload_len = hdr.payload_len

        # Extract payload bytes — copy out of ring buffer memory immediately
        # because the ring buffer slot may be overwritten after we return.
        if safe_payload_len > 0:
            payload_ptr = ctypes.cast(
                ctypes.addressof(hdr) + header_size,
                ctypes.POINTER(ctypes.c_char * safe_payload_len)
            )
            payload = bytes(payload_ptr.contents)
        else:
            payload = b""

        meta = EventMeta.from_ctype(hdr)
        return cls(meta=meta, payload=payload)

    @property
    def is_close(self) -> bool:
        return self.meta.is_close

    @property
    def protocol(self) -> Protocol:
        return self.meta.protocol

    @property
    def conn_id(self) -> int:
        return self.meta.conn_id

    def payload_preview(self, n: int = 128) -> str:
        """
        First `n` bytes of payload as a printable string.
        Non-printable bytes are replaced with '.'.
        Useful for log lines without bloating them.
        """
        chunk = self.payload[:n]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

    def to_dict(self, include_payload: bool = False) -> dict:
        """
        Serialise to a plain dict.

        Parameters
        ----------
        include_payload : bool
            If True, include payload as a hex string.
            Default False to keep log volume manageable.
        """
        d = self.meta.to_dict()
        d["payload_preview"] = self.payload_preview()
        if include_payload:
            d["payload_hex"] = self.payload.hex()
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Module self-test
# Run with: python3 -m src.agent.event_types
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Verifying struct layout...")
    verify_layout()
    print(f"  ConnTupleCT   = {ctypes.sizeof(ConnTupleCT)} bytes  (expected 16)")
    print(f"  ConnMetaCT    = {ctypes.sizeof(ConnMetaCT)} bytes  (expected 56)")
    print(f"  EventHeaderCT = {ctypes.sizeof(EventHeaderCT)} bytes  (expected 72)")

    print("\nField offsets for EventHeaderCT:")
    for fname, ftype in EventHeaderCT._fields_:
        off = getattr(EventHeaderCT, fname).offset
        sz  = getattr(EventHeaderCT, fname).size
        print(f"  +{off:3d}  {fname:<16} ({sz} bytes)")

    print("\nProtocol enum:")
    for p in Protocol:
        print(f"  {p.value}  {p.display_name:<16}  "
              f"encrypted={p.is_encrypted}  http={p.is_http}")

    print("\nAll checks passed.")