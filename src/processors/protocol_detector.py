"""
protocol_detector.py
====================
Userspace protocol detection and refinement layer.

The eBPF kernel probe performs fast, coarse protocol detection using only
the first 8 bytes of each TCP segment. This module performs a deeper,
stateful analysis in userspace to:

  1. CONFIRM  — validate the kernel's guess with full payload inspection
  2. UPGRADE  — promote to a more specific protocol
                e.g. HTTP2 → GRPC  (Content-Type: application/grpc)
                     HTTP1 → WEBSOCKET (after Upgrade handshake)
                     HTTP1 → MCP   (JSON-RPC on HTTP/1.1)
                     TLS   → HTTP1_TLS / HTTP2_TLS (post-SSL-probe)
  3. CORRECT  — fix outright wrong kernel guesses caused by mid-stream
                capture (the kernel may see a continuation frame without
                the initial handshake)
  4. ANNOTATE — extract protocol-level metadata that belongs here, not in
                per-protocol parsers:
                  - TLS version and cipher suite (from ClientHello)
                  - HTTP/2 SETTINGS frame parameters
                  - WebSocket subprotocol from Upgrade headers
                  - gRPC service/method from :path pseudo-header
                  - MCP JSON-RPC method name

Design constraints:
  - Stateful per connection (DetectionState stored in conn_tracker)
  - Called once per RawEvent before the payload reaches a parser
  - Must be fast: O(1) byte comparisons, no regex on hot path
  - Never raises — all errors caught and stored in DetectionResult

Protocol coverage:
  ┌────────────────┬────────────────────────────────────────────────────┐
  │ Protocol       │ Detection signals                                   │
  ├────────────────┼────────────────────────────────────────────────────┤
  │ HTTP/1.x       │ ASCII verb OR "HTTP/" response prefix               │
  │ HTTP/2         │ PRI preface (client) OR frame header structure      │
  │ gRPC           │ HTTP/2 + HEADERS frame with :path containing '/'    │
  │                │ OR Content-Type: application/grpc                   │
  │ WebSocket      │ HTTP/1.1 Upgrade: websocket request OR              │
  │                │ 101 Switching Protocols response OR WS frame byte   │
  │ MCP            │ JSON-RPC method ∈ known MCP method set OR           │
  │                │ HTTP/1.1 POST with application/json + jsonrpc field │
  │ TLS            │ Record layer content-type byte + version bytes      │
  │ TLS ClientHello│ Handshake type 0x01 inside TLS record               │
  │ TLS ServerHello│ Handshake type 0x02 inside TLS record               │
  └────────────────┴────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Dict, FrozenSet, Optional, Set, Tuple

from src.agent.event_types import Direction, Protocol, RawEvent


# ─────────────────────────────────────────────────────────────────────────────
# TLS constants
# ─────────────────────────────────────────────────────────────────────────────

# TLS record layer content type byte (RFC 5246 §6.2.1)
TLS_CONTENT_CHANGE_CIPHER = 0x14
TLS_CONTENT_ALERT         = 0x15
TLS_CONTENT_HANDSHAKE     = 0x16
TLS_CONTENT_APPDATA       = 0x17

# TLS handshake message types (RFC 5246 §7.4)
TLS_HS_CLIENT_HELLO = 0x01
TLS_HS_SERVER_HELLO = 0x02
TLS_HS_CERTIFICATE  = 0x0B
TLS_HS_SERVER_DONE  = 0x0E
TLS_HS_FINISHED     = 0x14

# TLS versions (major=0x03, minor varies)
TLS_VERSIONS: Dict[Tuple[int, int], str] = {
    (0x03, 0x01): "TLS 1.0",
    (0x03, 0x02): "TLS 1.1",
    (0x03, 0x03): "TLS 1.2",
    (0x03, 0x04): "TLS 1.3",
}

# ─────────────────────────────────────────────────────────────────────────────
# HTTP/2 constants (RFC 9113)
# ─────────────────────────────────────────────────────────────────────────────

# HTTP/2 client connection preface (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n)
H2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# HTTP/2 frame types
H2_FRAME_DATA         = 0x00
H2_FRAME_HEADERS      = 0x01
H2_FRAME_PRIORITY     = 0x02
H2_FRAME_RST_STREAM   = 0x03
H2_FRAME_SETTINGS     = 0x04
H2_FRAME_PUSH_PROMISE = 0x05
H2_FRAME_PING         = 0x06
H2_FRAME_GOAWAY       = 0x07
H2_FRAME_WINDOW_UPDATE = 0x08
H2_FRAME_CONTINUATION = 0x09

# Minimum HTTP/2 frame size (3-byte length + 1 type + 1 flags + 4 stream ID)
H2_FRAME_HEADER_SIZE = 9

# ─────────────────────────────────────────────────────────────────────────────
# gRPC constants (gRPC over HTTP/2)
# ─────────────────────────────────────────────────────────────────────────────

# Content-Type values that indicate gRPC
GRPC_CONTENT_TYPES: FrozenSet[str] = frozenset({
    "application/grpc",
    "application/grpc+proto",
    "application/grpc+json",
    "application/grpc-web",
    "application/grpc-web+proto",
    "application/grpc-web-text",
})

# gRPC status codes (for response annotation)
GRPC_STATUS_CODES: Dict[int, str] = {
    0:  "OK",           1:  "CANCELLED",     2:  "UNKNOWN",
    3:  "INVALID_ARG",  4:  "DEADLINE",       5:  "NOT_FOUND",
    6:  "ALREADY_EXISTS", 7: "PERMISSION",   8:  "RESOURCE_EXHAUSTED",
    9:  "PRECONDITION", 10: "ABORTED",       11: "OUT_OF_RANGE",
    12: "UNIMPLEMENTED",13: "INTERNAL",      14: "UNAVAILABLE",
    15: "DATA_LOSS",    16: "UNAUTHENTICATED",
}

# gRPC message frame prefix: 1 compression flag byte + 4 byte message length
GRPC_FRAME_HEADER_SIZE = 5

# ─────────────────────────────────────────────────────────────────────────────
# WebSocket constants (RFC 6455)
# ─────────────────────────────────────────────────────────────────────────────

# HTTP header triggering WebSocket upgrade
WS_UPGRADE_HEADER    = b"upgrade: websocket"
WS_CONNECTION_HEADER = b"connection: upgrade"
WS_HTTP_101          = b"HTTP/1.1 101"

# WebSocket opcodes
WS_OPCODE_CONTINUATION = 0x00
WS_OPCODE_TEXT         = 0x01
WS_OPCODE_BINARY       = 0x02
WS_OPCODE_CLOSE        = 0x08
WS_OPCODE_PING         = 0x09
WS_OPCODE_PONG         = 0x0A

# ─────────────────────────────────────────────────────────────────────────────
# MCP (Model Context Protocol) constants
# ─────────────────────────────────────────────────────────────────────────────

# All MCP method names defined in the MCP specification (2024-11-05)
MCP_METHODS: FrozenSet[str] = frozenset({
    # Lifecycle
    "initialize",
    "notifications/initialized",
    "ping",
    # Resources
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "resources/unsubscribe",
    "notifications/resources/updated",
    "notifications/resources/list_changed",
    # Prompts
    "prompts/list",
    "prompts/get",
    "notifications/prompts/list_changed",
    # Tools
    "tools/list",
    "tools/call",
    "notifications/tools/list_changed",
    # Sampling
    "sampling/createMessage",
    # Roots
    "roots/list",
    "notifications/roots/list_changed",
    # Logging
    "logging/setLevel",
    "notifications/message",
    # Completion
    "completion/complete",
})

# ─────────────────────────────────────────────────────────────────────────────
# Result dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class TLSInfo:
    """
    Metadata extracted from a TLS record.
    Populated only when protocol is PROTO_TLS.
    """
    record_type:  int             # TLS content type byte
    version:      Optional[str]   # e.g. "TLS 1.3"
    is_handshake: bool = False
    hs_type:      Optional[int]   = None  # handshake message type byte
    hs_type_name: Optional[str]   = None  # "ClientHello", "ServerHello", etc.


@dataclass(slots=True)
class HTTP2Info:
    """
    Metadata from the first HTTP/2 frame in a payload.
    Populated when protocol is PROTO_HTTP2 or PROTO_GRPC.
    """
    has_preface:  bool  = False   # client connection preface seen
    frame_type:   Optional[int]   = None
    stream_id:    Optional[int]   = None
    flags:        Optional[int]   = None


@dataclass(slots=True)
class GRPCInfo:
    """
    Metadata extracted from a gRPC message.
    Populated when protocol is PROTO_GRPC.
    """
    service:      Optional[str]   = None  # extracted from :path  e.g. "helloworld.Greeter"
    method:       Optional[str]   = None  # extracted from :path  e.g. "SayHello"
    compressed:   Optional[bool]  = None  # from gRPC frame header compression flag
    message_len:  Optional[int]   = None  # from gRPC frame header


@dataclass(slots=True)
class WebSocketInfo:
    """
    Metadata from a WebSocket frame or upgrade handshake.
    Populated when protocol is PROTO_WEBSOCKET.
    """
    is_upgrade_request:  bool = False  # HTTP/1.1 Upgrade: websocket
    is_upgrade_response: bool = False  # HTTP/1.1 101 Switching Protocols
    opcode:              Optional[int]  = None
    opcode_name:         Optional[str]  = None
    masked:              Optional[bool] = None
    payload_len:         Optional[int]  = None
    subprotocol:         Optional[str]  = None  # Sec-WebSocket-Protocol value


@dataclass(slots=True)
class MCPInfo:
    """
    Metadata from a detected MCP (Model Context Protocol) message.
    Populated when protocol is PROTO_MCP.
    """
    jsonrpc_version: Optional[str]  = None   # always "2.0"
    method:          Optional[str]  = None   # e.g. "tools/call"
    msg_id:          Optional[str]  = None   # request/response correlation ID
    is_request:      bool           = False
    is_response:     bool           = False
    is_notification: bool           = False  # no "id" field


@dataclass(slots=True)
class DetectionResult:
    """
    Output of ProtocolDetector.detect().

    Contains:
      - final_protocol : the definitive protocol, may differ from
                         raw_event.meta.protocol if the kernel was wrong
                         or detection was refined
      - confidence     : HIGH / MEDIUM / LOW — callers may log or discard
                         LOW-confidence results
      - protocol-specific info structs (only one is non-None per event)
      - correction_reason : set when final_protocol != kernel_protocol,
                            explains what signal triggered the change
    """

    # Core result
    final_protocol:    Protocol
    kernel_protocol:   Protocol  # what the BPF probe reported
    confidence:        "Confidence"

    # Protocol-specific annotations (at most one is non-None)
    tls_info:          Optional[TLSInfo]       = None
    http2_info:        Optional[HTTP2Info]     = None
    grpc_info:         Optional[GRPCInfo]      = None
    websocket_info:    Optional[WebSocketInfo] = None
    mcp_info:          Optional[MCPInfo]       = None

    # Diagnostic fields
    correction_reason: Optional[str] = None   # set when kernel was wrong/coarse
    detection_notes:   list          = field(default_factory=list)

    @property
    def was_upgraded(self) -> bool:
        """True if userspace refined the kernel's initial guess."""
        return self.final_protocol != self.kernel_protocol

    @property
    def is_confirmed(self) -> bool:
        return self.confidence == Confidence.HIGH

    def to_dict(self) -> dict:
        d: dict = {
            "final_protocol":  self.final_protocol.display_name,
            "kernel_protocol": self.kernel_protocol.display_name,
            "confidence":      self.confidence.name,
            "was_upgraded":    self.was_upgraded,
        }
        if self.correction_reason:
            d["correction_reason"] = self.correction_reason
        if self.detection_notes:
            d["detection_notes"] = self.detection_notes
        if self.tls_info:
            d["tls"] = {
                "record_type":  self.tls_info.record_type,
                "version":      self.tls_info.version,
                "is_handshake": self.tls_info.is_handshake,
                "hs_type_name": self.tls_info.hs_type_name,
            }
        if self.http2_info:
            d["http2"] = {
                "has_preface": self.http2_info.has_preface,
                "frame_type":  self.http2_info.frame_type,
                "stream_id":   self.http2_info.stream_id,
            }
        if self.grpc_info:
            d["grpc"] = {
                "service":    self.grpc_info.service,
                "method":     self.grpc_info.method,
                "compressed": self.grpc_info.compressed,
            }
        if self.websocket_info:
            d["websocket"] = {
                "is_upgrade_request":  self.websocket_info.is_upgrade_request,
                "is_upgrade_response": self.websocket_info.is_upgrade_response,
                "opcode_name":         self.websocket_info.opcode_name,
                "subprotocol":         self.websocket_info.subprotocol,
            }
        if self.mcp_info:
            d["mcp"] = {
                "method":         self.mcp_info.method,
                "msg_id":         self.mcp_info.msg_id,
                "is_request":     self.mcp_info.is_request,
                "is_response":    self.mcp_info.is_response,
                "is_notification": self.mcp_info.is_notification,
            }
        return d


class Confidence(IntEnum):
    """
    Detection confidence level.

    HIGH   — multiple independent signals agree; parse this payload.
    MEDIUM — single strong signal; parse with caution, note truncation.
    LOW    — heuristic only; log for debugging but do not parse body.
    """
    LOW    = 1
    MEDIUM = 2
    HIGH   = 3


# ─────────────────────────────────────────────────────────────────────────────
# Per-connection detection state
#
# Stored in ConnectionTracker (next module). Allows the detector to carry
# state across multiple packets on the same TCP stream, e.g.:
#   - Once WebSocket upgrade is confirmed, all subsequent frames are WS
#   - Once gRPC is confirmed, no need to re-check Content-Type headers
#   - TLS version seen in ClientHello is remembered for all records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class DetectionState:
    """
    Per-connection state carried across multiple RawEvents on the same stream.

    Fields are updated by ProtocolDetector.detect() and read on subsequent
    calls for the same conn_id.
    """
    conn_id:          int
    confirmed_proto:  Optional[Protocol] = None  # set once we're certain
    ws_upgraded:      bool               = False  # WebSocket handshake complete
    h2_preface_seen:  bool               = False  # HTTP/2 client preface seen
    grpc_confirmed:   bool               = False  # gRPC content-type seen
    mcp_confirmed:    bool               = False  # MCP method seen
    tls_version:      Optional[str]      = None   # from TLS ClientHello/ServerHello
    ws_subprotocol:   Optional[str]      = None   # from Sec-WebSocket-Protocol
    grpc_service:     Optional[str]      = None   # from :path pseudo-header
    grpc_method_name: Optional[str]      = None   # from :path pseudo-header
    packet_count:     int                = 0      # total packets seen on this conn


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

_WS_OPCODE_NAMES: Dict[int, str] = {
    WS_OPCODE_CONTINUATION: "continuation",
    WS_OPCODE_TEXT:         "text",
    WS_OPCODE_BINARY:       "binary",
    WS_OPCODE_CLOSE:        "close",
    WS_OPCODE_PING:         "ping",
    WS_OPCODE_PONG:         "pong",
}

_TLS_HS_NAMES: Dict[int, str] = {
    TLS_HS_CLIENT_HELLO: "ClientHello",
    TLS_HS_SERVER_HELLO: "ServerHello",
    TLS_HS_CERTIFICATE:  "Certificate",
    TLS_HS_SERVER_DONE:  "ServerHelloDone",
    TLS_HS_FINISHED:     "Finished",
}


def _starts_with(buf: bytes, prefix: bytes, offset: int = 0) -> bool:
    """Fast prefix check without slicing (avoids allocation)."""
    end = offset + len(prefix)
    if len(buf) < end:
        return False
    return buf[offset:end] == prefix


def _find_header_value(raw: bytes, header_name_lower: bytes) -> Optional[bytes]:
    """
    Extract the value of an HTTP header from raw bytes.

    Scans line by line for `header_name_lower: <value>`.
    Case-insensitive on the header name side (caller lowercases the needle).
    Stops at the blank line separating headers from body.
    Returns the raw value bytes, stripped of leading/trailing whitespace.
    """
    # Work only within the header section
    header_end = raw.find(b"\r\n\r\n")
    search_area = raw[:header_end] if header_end != -1 else raw

    needle = header_name_lower + b":"
    pos = 0
    while pos < len(search_area):
        line_end = search_area.find(b"\r\n", pos)
        if line_end == -1:
            line = search_area[pos:]
        else:
            line = search_area[pos:line_end]

        if line.lower().startswith(needle):
            value = line[len(needle):].strip()
            return value

        if line_end == -1:
            break
        pos = line_end + 2

    return None


def _is_valid_h2_frame_type(ftype: int) -> bool:
    """Return True if the frame type byte is a known HTTP/2 frame type."""
    return 0x00 <= ftype <= 0x09


# ─────────────────────────────────────────────────────────────────────────────
# ProtocolDetector
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolDetector:
    """
    Stateful protocol detection and refinement for eBPF-captured events.

    Usage
    -----
    One ProtocolDetector instance per agent (singleton). It is called
    once per RawEvent and maintains per-connection DetectionState in an
    internal dict keyed by conn_id.

    Thread safety: NOT thread-safe. The agent's ring buffer poll loop is
    single-threaded; if you add worker threads, wrap detect() in a lock
    or shard by conn_id.

    Example
    -------
        detector = ProtocolDetector()

        for raw_event in ring_buffer:
            result = detector.detect(raw_event)
            if result.final_protocol == Protocol.GRPC:
                grpc_parser.parse(raw_event, result.grpc_info)
            elif result.final_protocol == Protocol.MCP:
                mcp_handler.handle(raw_event, result.mcp_info)
    """

    def __init__(self, max_conn_states: int = 65536):
        """
        Parameters
        ----------
        max_conn_states : int
            Maximum number of per-connection states to hold in memory.
            When exceeded, oldest entries are evicted (LRU not implemented
            here for simplicity — ConnectionTracker handles eviction).
        """
        # conn_id → DetectionState
        self._states: Dict[int, DetectionState] = {}
        self._max_states = max_conn_states

    # ── Public API ────────────────────────────────────────────────────────────

    def detect(self, event: RawEvent) -> DetectionResult:
        """
        Analyse one RawEvent and return a DetectionResult.

        This is the main entry point. It:
          1. Retrieves or creates DetectionState for this conn_id
          2. If protocol already confirmed on this conn, fast-paths to
             re-annotation (no re-detection needed)
          3. Otherwise runs the appropriate detector for the kernel's
             initial protocol guess
          4. Updates DetectionState with any new knowledge
          5. Returns a DetectionResult with final_protocol and annotations

        Parameters
        ----------
        event : RawEvent
            Event from the ring buffer, as produced by RawEvent.from_ring_buffer()

        Returns
        -------
        DetectionResult
            Always returns a valid result; never raises.
        """
        try:
            return self._detect_safe(event)
        except Exception as exc:
            # Detection must never crash the agent
            return DetectionResult(
                final_protocol  = event.protocol,
                kernel_protocol = event.protocol,
                confidence      = Confidence.LOW,
                detection_notes = [f"detection_error: {exc!r}"],
            )

    def on_connection_close(self, conn_id: int) -> None:
        """
        Remove per-connection state when tcp_close fires.
        Called by ConnectionTracker.
        """
        self._states.pop(conn_id, None)

    def state_count(self) -> int:
        """Number of active connection states (for metrics)."""
        return len(self._states)

    # ── Internal dispatcher ───────────────────────────────────────────────────

    def _detect_safe(self, event: RawEvent) -> DetectionResult:
        """Inner detect — may raise; wrapped by detect()."""

        # Handle CLOSE events immediately — no payload to analyse
        if event.is_close:
            self.on_connection_close(event.conn_id)
            state = self._states.get(event.conn_id)
            proto = state.confirmed_proto if state else event.protocol
            return DetectionResult(
                final_protocol  = proto or Protocol.UNKNOWN,
                kernel_protocol = event.protocol,
                confidence      = Confidence.HIGH,
            )

        state = self._get_or_create_state(event.conn_id)
        state.packet_count += 1
        buf = event.payload

        # ── Fast-path: protocol already confirmed on this connection ──────
        if state.confirmed_proto is not None:
            return self._reannotate(event, state, buf)

        # ── Dispatch to per-protocol detector ─────────────────────────────
        kproto = event.protocol   # kernel's initial guess

        if kproto == Protocol.TLS:
            result = self._detect_tls(buf, kproto, state)

        elif kproto in (Protocol.HTTP2, Protocol.HTTP2_TLS):
            result = self._detect_http2(buf, kproto, state)

        elif kproto in (Protocol.HTTP1, Protocol.HTTP1_TLS):
            result = self._detect_http1(buf, kproto, state, event)

        elif kproto == Protocol.WEBSOCKET:
            result = self._detect_websocket(buf, kproto, state)

        elif kproto == Protocol.MCP:
            result = self._detect_mcp(buf, kproto, state)

        elif kproto == Protocol.GRPC:
            result = self._detect_grpc_standalone(buf, kproto, state)

        else:
            # PROTO_UNKNOWN — try all detectors in priority order
            result = self._detect_unknown(buf, event, state)

        # ── Lock in confirmed protocol ─────────────────────────────────────
        if result.confidence >= Confidence.HIGH:
            state.confirmed_proto = result.final_protocol

        return result

    # ── Re-annotation (fast path for confirmed connections) ────────────────

    def _reannotate(self, event: RawEvent,
                    state: DetectionState, buf: bytes) -> DetectionResult:
        """
        Protocol already confirmed for this connection.
        Skip full detection; just extract per-packet annotations.
        """
        proto = state.confirmed_proto

        result = DetectionResult(
            final_protocol  = proto,
            kernel_protocol = event.protocol,
            confidence      = Confidence.HIGH,
        )

        if proto == Protocol.TLS:
            result.tls_info = self._extract_tls_info(buf)

        elif proto in (Protocol.HTTP2, Protocol.HTTP2_TLS):
            result.http2_info = self._extract_h2_info(buf, state)

        elif proto == Protocol.GRPC:
            result.http2_info = self._extract_h2_info(buf, state)
            result.grpc_info  = GRPCInfo(
                service = state.grpc_service,
                method  = state.grpc_method_name,
            )
            self._extract_grpc_frame_info(buf, result.grpc_info)

        elif proto == Protocol.WEBSOCKET:
            result.websocket_info = self._extract_ws_frame(buf, state)

        elif proto == Protocol.MCP:
            result.mcp_info = self._extract_mcp_info(buf)

        return result

    # ── TLS detector ──────────────────────────────────────────────────────────

    def _detect_tls(self, buf: bytes, kproto: Protocol,
                    state: DetectionState) -> DetectionResult:
        """
        Validate TLS record layer and extract handshake information.

        TLS record structure (RFC 5246 §6.2):
          byte 0:    content type  (0x14..0x17)
          bytes 1-2: protocol version  (0x03 0x01..0x04)
          bytes 3-4: record length  (big-endian uint16)
          bytes 5+:  record payload

        If content type is Handshake (0x16), the payload begins with:
          byte 5:    handshake type  (0x01=ClientHello, 0x02=ServerHello, ...)
          bytes 6-8: handshake length (big-endian uint24)
        """
        if len(buf) < 5:
            return DetectionResult(
                final_protocol  = Protocol.TLS,
                kernel_protocol = kproto,
                confidence      = Confidence.MEDIUM,
                detection_notes = ["tls: payload too short for full record header"],
            )

        record_type  = buf[0]
        version_major = buf[1]
        version_minor = buf[2]

        # Validate content type
        if record_type not in (0x14, 0x15, 0x16, 0x17):
            return DetectionResult(
                final_protocol  = Protocol.UNKNOWN,
                kernel_protocol = kproto,
                confidence      = Confidence.LOW,
                correction_reason = f"tls: unexpected content type 0x{record_type:02x}",
            )

        version_str = TLS_VERSIONS.get((version_major, version_minor))
        if version_str:
            state.tls_version = version_str

        tls_info = TLSInfo(
            record_type  = record_type,
            version      = version_str or f"unknown(0x{version_major:02x}{version_minor:02x})",
            is_handshake = (record_type == TLS_CONTENT_HANDSHAKE),
        )

        # Extract handshake type from the record payload
        if tls_info.is_handshake and len(buf) >= 6:
            hs_type = buf[5]
            tls_info.hs_type      = hs_type
            tls_info.hs_type_name = _TLS_HS_NAMES.get(hs_type,
                                    f"unknown(0x{hs_type:02x})")

        confidence = Confidence.HIGH if version_str else Confidence.MEDIUM

        result = DetectionResult(
            final_protocol  = Protocol.TLS,
            kernel_protocol = kproto,
            confidence      = confidence,
            tls_info        = tls_info,
        )
        return result

    def _extract_tls_info(self, buf: bytes) -> Optional[TLSInfo]:
        """Lightweight TLS info extraction for re-annotation path."""
        if len(buf) < 5:
            return None
        record_type = buf[0]
        version_str = TLS_VERSIONS.get((buf[1], buf[2]))
        info = TLSInfo(
            record_type  = record_type,
            version      = version_str,
            is_handshake = (record_type == TLS_CONTENT_HANDSHAKE),
        )
        if info.is_handshake and len(buf) >= 6:
            hs_type = buf[5]
            info.hs_type      = hs_type
            info.hs_type_name = _TLS_HS_NAMES.get(hs_type)
        return info

    # ── HTTP/2 detector ───────────────────────────────────────────────────────

    def _detect_http2(self, buf: bytes, kproto: Protocol,
                      state: DetectionState) -> DetectionResult:
        """
        Validate HTTP/2 and check for gRPC upgrade.

        HTTP/2 detection signals (in priority order):
          1. Client connection preface (24-byte magic string)
          2. Valid frame header: 3-byte length, known type, valid stream ID

        gRPC upgrade: if a HEADERS frame is detected, scan its payload
        for "content-type: application/grpc" to promote to PROTO_GRPC.
        """
        notes = []
        has_preface = False
        final_proto = kproto
        confidence  = Confidence.MEDIUM

        # ── Signal 1: client connection preface ───────────────────────────
        if _starts_with(buf, H2_CLIENT_PREFACE):
            has_preface = True
            state.h2_preface_seen = True
            confidence = Confidence.HIGH
            notes.append("h2: client preface detected")

        elif state.h2_preface_seen:
            # We already saw the preface on this connection
            has_preface = True
            confidence  = Confidence.HIGH

        # ── Signal 2: frame header validation ─────────────────────────────
        frame_offset = 24 if has_preface else 0
        h2_info = self._extract_h2_info_at(buf, frame_offset, state)

        if h2_info:
            if h2_info.frame_type is not None and confidence < Confidence.HIGH:
                confidence = Confidence.HIGH
                notes.append(f"h2: valid frame type 0x{h2_info.frame_type:02x}")
            h2_info.has_preface = has_preface
        else:
            if not has_preface:
                # No preface and no valid frame — downgrade confidence
                confidence  = Confidence.LOW
                notes.append("h2: no preface and no valid frame header")

        # ── Signal 3: gRPC promotion ───────────────────────────────────────
        grpc_info = None
        if confidence >= Confidence.MEDIUM:
            grpc_info = self._try_grpc_from_h2(buf, frame_offset, state)
            if grpc_info is not None:
                final_proto = Protocol.GRPC
                state.grpc_confirmed = True
                notes.append("grpc: content-type or :path detected")

        result = DetectionResult(
            final_protocol  = final_proto,
            kernel_protocol = kproto,
            confidence      = confidence,
            http2_info      = h2_info,
            grpc_info       = grpc_info,
            detection_notes = notes,
        )
        if final_proto != kproto:
            result.correction_reason = "http2→grpc: grpc signals found"

        return result

    def _extract_h2_info(self, buf: bytes,
                          state: DetectionState) -> Optional[HTTP2Info]:
        """Extract HTTP/2 frame info, accounting for preface offset."""
        offset = 24 if (state.h2_preface_seen and
                        _starts_with(buf, H2_CLIENT_PREFACE)) else 0
        return self._extract_h2_info_at(buf, offset, state)

    def _extract_h2_info_at(self, buf: bytes, offset: int,
                              state: DetectionState) -> Optional[HTTP2Info]:
        """
        Parse the HTTP/2 frame header at `offset` bytes into `buf`.

        Frame header format (RFC 9113 §4.1):
          bytes 0-2:  payload length  (24-bit big-endian)
          byte  3:    type
          byte  4:    flags
          bytes 5-8:  stream identifier (31-bit, MSB reserved/zero)
        """
        needed = offset + H2_FRAME_HEADER_SIZE
        if len(buf) < needed:
            return HTTP2Info()

        ftype     = buf[offset + 3]
        flags     = buf[offset + 4]
        stream_id = struct.unpack_from(">I", buf, offset + 5)[0] & 0x7FFFFFFF

        if not _is_valid_h2_frame_type(ftype):
            return HTTP2Info()

        return HTTP2Info(
            has_preface = state.h2_preface_seen,
            frame_type  = ftype,
            stream_id   = stream_id,
            flags       = flags,
        )

    def _try_grpc_from_h2(self, buf: bytes, frame_offset: int,
                           state: DetectionState) -> Optional[GRPCInfo]:
        """
        Look for gRPC signals in an HTTP/2 HEADERS frame payload.

        Scans the raw HPACK-compressed headers for literal header fields
        (type 0x00 or 0x40) containing "content-type" with a grpc value,
        or ":path" with a service/method pattern.

        Note: We do NOT implement a full HPACK decoder here — that belongs
        in the HTTP/2 parser. Instead we look for the literal string bytes
        directly, which works for uncompressed / first-occurrence headers.
        """
        # Only inspect HEADERS frames
        needed = frame_offset + H2_FRAME_HEADER_SIZE
        if len(buf) < needed:
            return None

        ftype = buf[frame_offset + 3]
        if ftype != H2_FRAME_HEADERS:
            # Check for a gRPC DATA frame instead (has gRPC frame header)
            if ftype == H2_FRAME_DATA:
                return self._try_grpc_from_data_frame(
                    buf, frame_offset, state)
            return None

        # Scan HEADERS payload for content-type and :path
        payload_start = frame_offset + H2_FRAME_HEADER_SIZE
        payload       = buf[payload_start:]
        lower_payload = payload.lower()

        grpc_info = GRPCInfo()

        # Content-type check (literal match in HPACK payload)
        for ct in GRPC_CONTENT_TYPES:
            if ct.encode() in lower_payload:
                state.grpc_confirmed = True
                grpc_info = GRPCInfo()
                break

        # :path check for service/method pattern "/package.Service/Method"
        path_idx = lower_payload.find(b":path")
        if path_idx != -1:
            # Skip the ":path" bytes and find the value portion
            rest = payload[path_idx + 5:]
            slash_idx = rest.find(b"/")
            if slash_idx != -1:
                path_bytes = rest[slash_idx:]
                parts = path_bytes.split(b"/")
                if len(parts) >= 3:
                    svc  = parts[1].decode("utf-8", errors="replace")
                    meth = parts[2].split(b"\x00")[0].split(b" ")[0]
                    meth = meth.decode("utf-8", errors="replace")
                    if svc and meth:
                        grpc_info.service = svc
                        grpc_info.method  = meth
                        state.grpc_service      = svc
                        state.grpc_method_name  = meth
                        state.grpc_confirmed    = True

        if state.grpc_confirmed:
            return grpc_info
        return None

    def _try_grpc_from_data_frame(self, buf: bytes, frame_offset: int,
                                   state: DetectionState) -> Optional[GRPCInfo]:
        """
        Detect gRPC from an HTTP/2 DATA frame.

        gRPC DATA frame payload structure (gRPC over HTTP/2 spec):
          byte  0:    Compressed-Flag (0x00 = no compression, 0x01 = compressed)
          bytes 1-4:  Message-Length  (32-bit big-endian)
          bytes 5+:   message body (Protocol Buffer or other encoding)
        """
        if not state.grpc_confirmed:
            return None

        payload_start = frame_offset + H2_FRAME_HEADER_SIZE
        if len(buf) < payload_start + GRPC_FRAME_HEADER_SIZE:
            return None

        compressed  = buf[payload_start] == 0x01
        message_len = struct.unpack_from(">I", buf, payload_start + 1)[0]

        return GRPCInfo(
            service      = state.grpc_service,
            method       = state.grpc_method_name,
            compressed   = compressed,
            message_len  = message_len,
        )

    def _extract_grpc_frame_info(self, buf: bytes,
                                  grpc_info: GRPCInfo) -> None:
        """Mutate grpc_info in-place with DATA frame metadata."""
        # Find first DATA frame (type 0x00)
        offset = 0
        if _starts_with(buf, H2_CLIENT_PREFACE):
            offset = 24
        if len(buf) < offset + H2_FRAME_HEADER_SIZE:
            return
        ftype = buf[offset + 3]
        if ftype == H2_FRAME_DATA:
            payload_start = offset + H2_FRAME_HEADER_SIZE
            if len(buf) >= payload_start + GRPC_FRAME_HEADER_SIZE:
                grpc_info.compressed  = buf[payload_start] == 0x01
                grpc_info.message_len = struct.unpack_from(
                    ">I", buf, payload_start + 1)[0]

    def _detect_grpc_standalone(self, buf: bytes, kproto: Protocol,
                                  state: DetectionState) -> DetectionResult:
        """Handle events the kernel already labelled PROTO_GRPC."""
        # Kernel labelling GRPC directly shouldn't happen (we set GRPC in
        # userspace), but handle gracefully.
        state.grpc_confirmed = True
        grpc_info = GRPCInfo(
            service = state.grpc_service,
            method  = state.grpc_method_name,
        )
        return DetectionResult(
            final_protocol  = Protocol.GRPC,
            kernel_protocol = kproto,
            confidence      = Confidence.HIGH,
            grpc_info       = grpc_info,
        )

    # ── HTTP/1.x detector ─────────────────────────────────────────────────────

    def _detect_http1(self, buf: bytes, kproto: Protocol,
                      state: DetectionState,
                      event: RawEvent) -> DetectionResult:
        """
        Validate HTTP/1.x and check for protocol upgrades.

        Upgrades detected:
          - WebSocket: "Upgrade: websocket" request or 101 response
          - MCP:       application/json body with jsonrpc field
          - HTTP/2:    "Upgrade: h2c" header (HTTP/1.1 cleartext upgrade)

        Detection is line-by-line on the header section only; body
        parsing belongs in the HTTP1Parser.
        """
        notes   = []
        is_req  = self._is_http1_request(buf)
        is_resp = self._is_http1_response(buf)

        if not is_req and not is_resp:
            # Mid-stream continuation — trust kernel if packet count > 1
            if state.packet_count > 1:
                return DetectionResult(
                    final_protocol  = kproto,
                    kernel_protocol = kproto,
                    confidence      = Confidence.MEDIUM,
                    detection_notes = ["http1: mid-stream continuation"],
                )
            return DetectionResult(
                final_protocol  = Protocol.UNKNOWN,
                kernel_protocol = kproto,
                confidence      = Confidence.LOW,
                correction_reason = "http1: no valid request/response line",
            )

        lower_buf = buf.lower()

        # ── WebSocket upgrade? ─────────────────────────────────────────────
        # Guard: only apply upgrade-request detection to actual requests.
        # A 101 response also contains "Upgrade: websocket" in its headers,
        # so checking is_req first prevents misclassifying the response.
        if is_req and WS_UPGRADE_HEADER in lower_buf:
            ws_info = WebSocketInfo(is_upgrade_request=True)
            # Extract Sec-WebSocket-Protocol if present
            proto_val = _find_header_value(buf, b"sec-websocket-protocol")
            if proto_val:
                ws_info.subprotocol  = proto_val.decode("utf-8", errors="replace")
                state.ws_subprotocol = ws_info.subprotocol
            return DetectionResult(
                final_protocol    = Protocol.WEBSOCKET,
                kernel_protocol   = kproto,
                confidence        = Confidence.HIGH,
                websocket_info    = ws_info,
                correction_reason = "http1→websocket: Upgrade header",
            )

        if _starts_with(buf, WS_HTTP_101):
            state.ws_upgraded = True
            ws_info = WebSocketInfo(
                is_upgrade_response = True,
                subprotocol         = state.ws_subprotocol,
            )
            return DetectionResult(
                final_protocol    = Protocol.WEBSOCKET,
                kernel_protocol   = kproto,
                confidence        = Confidence.HIGH,
                websocket_info    = ws_info,
                correction_reason = "http1→websocket: 101 Switching Protocols",
            )

        # ── MCP over HTTP/1.1? ─────────────────────────────────────────────
        # MCP can run over plain HTTP/1.1 POST with JSON-RPC body
        ct_val = _find_header_value(lower_buf, b"content-type")
        if ct_val and b"application/json" in ct_val:
            # Look for jsonrpc field in first 512 bytes of body
            body_start = buf.find(b"\r\n\r\n")
            if body_start != -1:
                body_preview = buf[body_start + 4 : body_start + 512]
                mcp_info = self._try_mcp_from_json(body_preview)
                if mcp_info is not None:
                    state.mcp_confirmed = True
                    return DetectionResult(
                        final_protocol    = Protocol.MCP,
                        kernel_protocol   = kproto,
                        confidence        = Confidence.HIGH,
                        mcp_info          = mcp_info,
                        correction_reason = "http1→mcp: JSON-RPC method in body",
                    )

        # ── Confirmed HTTP/1.x ─────────────────────────────────────────────
        notes.append("http1: request" if is_req else "http1: response")
        return DetectionResult(
            final_protocol  = kproto,
            kernel_protocol = kproto,
            confidence      = Confidence.HIGH,
            detection_notes = notes,
        )

    def _is_http1_request(self, buf: bytes) -> bool:
        """Check if buffer starts with a valid HTTP/1.x request line."""
        for method in (b"GET ", b"POST ", b"PUT ", b"DELETE ",
                       b"PATCH ", b"HEAD ", b"OPTIONS ", b"CONNECT ", b"TRACE "):
            if _starts_with(buf, method):
                return True
        return False

    def _is_http1_response(self, buf: bytes) -> bool:
        """Check if buffer starts with a valid HTTP/1.x response line."""
        return _starts_with(buf, b"HTTP/1.")

    # ── WebSocket detector ────────────────────────────────────────────────────

    def _detect_websocket(self, buf: bytes, kproto: Protocol,
                           state: DetectionState) -> DetectionResult:
        """
        Validate a WebSocket frame.

        WebSocket frame structure (RFC 6455 §5.2):
          byte 0:  FIN (bit 7), RSV1-3 (bits 6-4), opcode (bits 3-0)
          byte 1:  MASK (bit 7), payload length (bits 6-0)
          bytes 2-3 (if payload_len == 126): extended payload length (uint16)
          bytes 2-9 (if payload_len == 127): extended payload length (uint64)
          bytes N..N+3 (if MASK): masking key (4 bytes)
          bytes M+: payload data

        RSV1-3 must all be zero unless a WebSocket extension is negotiated.
        We treat RSV bits as a signal: if non-zero and we haven't seen an
        extension negotiation, confidence is MEDIUM.
        """
        if len(buf) < 2:
            return DetectionResult(
                final_protocol  = Protocol.WEBSOCKET,
                kernel_protocol = kproto,
                confidence      = Confidence.LOW,
                detection_notes = ["ws: payload too short"],
            )

        byte0  = buf[0]
        byte1  = buf[1]
        opcode = byte0 & 0x0F
        rsv    = (byte0 >> 4) & 0x07  # RSV1, RSV2, RSV3
        masked = bool(byte1 & 0x80)
        plen   = byte1 & 0x7F

        # RSV bits non-zero without known extension = suspicious
        confidence = Confidence.HIGH if rsv == 0 else Confidence.MEDIUM

        # Validate opcode
        valid_opcodes = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A}
        if opcode not in valid_opcodes:
            return DetectionResult(
                final_protocol  = Protocol.UNKNOWN,
                kernel_protocol = kproto,
                confidence      = Confidence.LOW,
                correction_reason = f"ws: invalid opcode 0x{opcode:02x}",
            )

        ws_info = WebSocketInfo(
            opcode       = opcode,
            opcode_name  = _WS_OPCODE_NAMES.get(opcode, f"0x{opcode:02x}"),
            masked       = masked,
            payload_len  = plen,
            subprotocol  = state.ws_subprotocol,
        )

        return DetectionResult(
            final_protocol  = Protocol.WEBSOCKET,
            kernel_protocol = kproto,
            confidence      = confidence,
            websocket_info  = ws_info,
        )

    def _extract_ws_frame(self, buf: bytes,
                           state: DetectionState) -> Optional[WebSocketInfo]:
        """Lightweight WS frame extraction for re-annotation."""
        if len(buf) < 2:
            return None
        opcode = buf[0] & 0x0F
        return WebSocketInfo(
            opcode      = opcode,
            opcode_name = _WS_OPCODE_NAMES.get(opcode),
            masked      = bool(buf[1] & 0x80),
            payload_len = buf[1] & 0x7F,
            subprotocol = state.ws_subprotocol,
        )

    # ── MCP detector ──────────────────────────────────────────────────────────

    def _detect_mcp(self, buf: bytes, kproto: Protocol,
                    state: DetectionState) -> DetectionResult:
        """
        Validate MCP (Model Context Protocol) message.

        MCP uses JSON-RPC 2.0 as its transport format (spec: 2024-11-05).
        Each message is a JSON object with:
          - "jsonrpc": "2.0"           (required)
          - "method": "<mcp_method>"   (requests and notifications)
          - "id": <number|string|null> (requests and responses, absent for notifications)
          - "result": ...              (success responses)
          - "error": {...}             (error responses)

        We parse the first MAX_JSON_PEEK bytes as JSON. If that fails, we
        fall back to byte-level scanning for "jsonrpc" and known MCP method
        strings.

        MCP can be carried over:
          - HTTP/1.1 POST (with Content-Type: application/json)
          - HTTP/2 (with same content-type)
          - WebSocket (after upgrade)
          - stdio (future: for local process MCP servers)
        """
        MAX_JSON_PEEK = 4096

        mcp_info = self._try_mcp_from_json(buf[:MAX_JSON_PEEK])
        if mcp_info is not None:
            state.mcp_confirmed = True
            return DetectionResult(
                final_protocol  = Protocol.MCP,
                kernel_protocol = kproto,
                confidence      = Confidence.HIGH,
                mcp_info        = mcp_info,
            )

        # Fallback: byte-level scan (only when JSON parse fails, e.g. truncated)
        lower = buf[:MAX_JSON_PEEK].lower()
        if b'"jsonrpc"' in lower and b'"2.0"' in lower:
            mcp_info = MCPInfo(jsonrpc_version="2.0")
            # Try to find method name and validate it is an MCP method.
            # If the method is present but not in MCP_METHODS, this is a
            # non-MCP JSON-RPC call (e.g. Ethereum JSON-RPC) — reject it.
            method_idx = lower.find(b'"method"')
            if method_idx != -1:
                rest = buf[method_idx + 8 : method_idx + 80].lstrip(b' \t\r\n:')
                if rest.startswith(b'"'):
                    end = rest.find(b'"', 1)
                    if end != -1:
                        method_str = rest[1:end].decode("utf-8", errors="replace")
                        if method_str not in MCP_METHODS:
                            # Non-MCP JSON-RPC — do not claim as MCP
                            return DetectionResult(
                                final_protocol  = Protocol.UNKNOWN,
                                kernel_protocol = kproto,
                                confidence      = Confidence.LOW,
                                correction_reason=f"mcp: jsonrpc method {method_str!r} not in MCP spec",
                            )
                        mcp_info.method     = method_str
                        mcp_info.is_request = True

            state.mcp_confirmed = True
            return DetectionResult(
                final_protocol  = Protocol.MCP,
                kernel_protocol = kproto,
                confidence      = Confidence.MEDIUM,
                mcp_info        = mcp_info,
                detection_notes = ["mcp: byte-scan fallback (json parse failed)"],
            )

        # Not MCP
        return DetectionResult(
            final_protocol  = Protocol.UNKNOWN,
            kernel_protocol = kproto,
            confidence      = Confidence.LOW,
            correction_reason = "mcp: no jsonrpc 2.0 envelope found",
        )

    def _try_mcp_from_json(self, raw: bytes) -> Optional[MCPInfo]:
        """
        Attempt to parse `raw` as JSON and extract MCP fields.
        Returns None if JSON parse fails or required fields are absent.
        """
        if not raw or raw[0:1] != b"{":
            return None

        # Find the end of the first top-level JSON object by tracking braces.
        # We stop at MAX_JSON_PEEK to avoid O(N) scanning.
        depth = 0
        in_str = False
        escape = False
        end_idx = -1
        for i, c in enumerate(raw):
            if escape:
                escape = False
                continue
            if c == ord("\\") and in_str:
                escape = True
                continue
            if c == ord('"'):
                in_str = not in_str
                continue
            if not in_str:
                if c == ord("{"):
                    depth += 1
                elif c == ord("}"):
                    depth -= 1
                    if depth == 0:
                        end_idx = i + 1
                        break

        json_bytes = raw[:end_idx] if end_idx != -1 else raw
        try:
            obj = json.loads(json_bytes)
        except (json.JSONDecodeError, ValueError):
            return None

        # Must have jsonrpc: "2.0"
        if obj.get("jsonrpc") != "2.0":
            return None

        method   = obj.get("method")
        msg_id   = obj.get("id")
        has_result = "result" in obj
        has_error  = "error"  in obj
        has_id     = "id"     in obj

        # Classify: request (method + id), notification (method, no id),
        # response (result/error + id, no method)
        is_request      = method is not None and has_id
        is_notification = method is not None and not has_id
        is_response     = (has_result or has_error) and has_id and not method

        # MCP-specific: method must be in known MCP method set
        # (or treat as generic JSON-RPC if unknown method)
        if method is not None and method not in MCP_METHODS and not is_response:
            return None  # Known JSON-RPC but not MCP

        return MCPInfo(
            jsonrpc_version = "2.0",
            method          = method,
            msg_id          = str(msg_id) if msg_id is not None else None,
            is_request      = is_request,
            is_response     = is_response,
            is_notification = is_notification,
        )

    def _extract_mcp_info(self, buf: bytes) -> Optional[MCPInfo]:
        """Lightweight MCP info extraction for re-annotation."""
        return self._try_mcp_from_json(buf[:4096])

    # ── Unknown protocol detector ─────────────────────────────────────────────

    def _detect_unknown(self, buf: bytes, event: RawEvent,
                         state: DetectionState) -> DetectionResult:
        """
        Try all detectors in priority order for PROTO_UNKNOWN events.
        Returns the first confident match, or UNKNOWN with LOW confidence.
        """
        if len(buf) < 3:
            return DetectionResult(
                final_protocol  = Protocol.UNKNOWN,
                kernel_protocol = event.protocol,
                confidence      = Confidence.LOW,
                detection_notes = ["unknown: payload too short to classify"],
            )

        # TLS (highest priority — encrypted traffic identified first)
        b = buf[0]
        if b in (0x14, 0x15, 0x16, 0x17) and len(buf) >= 3 and buf[1] == 0x03:
            return self._detect_tls(buf, event.protocol, state)

        # HTTP/2 preface
        if _starts_with(buf, H2_CLIENT_PREFACE[:8]):
            return self._detect_http2(buf, Protocol.HTTP2, state)

        # HTTP/1.x
        if (b in (ord("G"), ord("P"), ord("D"), ord("H"), ord("O"),
                  ord("C"), ord("T"))):
            r = self._detect_http1(buf, Protocol.HTTP1, state, event)
            if r.confidence >= Confidence.MEDIUM:
                return r

        # WebSocket frame (after upgrade already confirmed on this conn)
        if state.ws_upgraded:
            return self._detect_websocket(buf, Protocol.WEBSOCKET, state)

        # JSON-RPC / MCP
        if buf[0:1] == b"{":
            r = self._detect_mcp(buf, Protocol.MCP, state)
            if r.confidence >= Confidence.MEDIUM:
                return r

        # HTTP/2 server-side frame (no preface)
        if (len(buf) >= H2_FRAME_HEADER_SIZE and
                _is_valid_h2_frame_type(buf[3])):
            frame_len = struct.unpack_from(">I", b"\x00" + buf[0:3])[0]
            if frame_len <= len(buf):
                return self._detect_http2(buf, Protocol.HTTP2, state)

        return DetectionResult(
            final_protocol  = Protocol.UNKNOWN,
            kernel_protocol = event.protocol,
            confidence      = Confidence.LOW,
            detection_notes = [f"unknown: no protocol matched (first byte 0x{b:02x})"],
        )

    # ── State management ──────────────────────────────────────────────────────

    def _get_or_create_state(self, conn_id: int) -> DetectionState:
        """
        Return existing DetectionState for conn_id or create a new one.
        Evicts oldest entry when at capacity (simple FIFO — connection
        tracker handles proper LRU eviction via on_connection_close()).
        """
        state = self._states.get(conn_id)
        if state is not None:
            return state

        if len(self._states) >= self._max_states:
            # Evict oldest: CPython dicts preserve insertion order since 3.7
            oldest_key = next(iter(self._states))
            del self._states[oldest_key]

        state = DetectionState(conn_id=conn_id)
        self._states[conn_id] = state
        return state