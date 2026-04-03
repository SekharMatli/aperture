"""
app/processing/event_parser.py
================================
Deserialises a raw Kafka message (bytes) into a ParsedAgentEvent dataclass.

Agent key is extracted from the Kafka message header: X-Agent-Key.
Supports HTTP/1.x, HTTP/2, gRPC, MCP, WebSocket sub-objects.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ParsedAgentEvent:
    # Auth
    agent_key:   str = ""

    # Resolved after DB key lookup
    project_id:  Optional[str] = None
    tenant_id:   Optional[str] = None

    # Enriched by processor
    path_pattern: Optional[str] = None
    auth_type:    str = "none"
    latency_ms:   Optional[float] = None

    # Network
    timestamp_ns: int = 0
    occurred_at:  Optional[datetime] = None
    conn_id:      int = 0
    pid:          int = 0
    process_name: str = ""
    src_ip:       str = ""
    dst_port:     int = 0
    protocol:     str = ""
    direction:    str = ""

    # HTTP
    method:        Optional[str] = None
    host:          Optional[str] = None
    raw_path:      Optional[str] = None
    query:         Optional[str] = None
    status_code:   Optional[int] = None
    request_size:  Optional[int] = None
    response_size: Optional[int] = None
    headers:       Dict[str, str] = field(default_factory=dict)

    # Schemas from agent
    request_schema:  Optional[Dict[str, Any]] = None
    response_schema: Optional[Dict[str, Any]] = None

    # gRPC
    grpc_service: Optional[str] = None
    grpc_method:  Optional[str] = None

    # MCP
    mcp_method:        Optional[str] = None
    mcp_params_schema: Optional[Dict[str, Any]] = None
    mcp_result_schema: Optional[Dict[str, Any]] = None

    # Raw payload (stored for 7 days)
    raw_event:   Optional[Dict[str, Any]] = None
    parse_error: Optional[str] = None

    # ── Schema v2 fields (Phase 0) ────────────────────────────────────────────
    schema_version:     int           = 1

    # SSL content (ssl_content.bpf.c)
    ssl_direction:      Optional[str] = None
    ssl_data:           Optional[str] = None
    ssl_data_len:       Optional[int] = None
    ssl_truncated:      bool          = False
    ssl_seq:            Optional[int] = None
    ssl_is_reassembled: bool          = False
    ssl_root_pid:       Optional[int] = None

    # Process/kernel (process_monitor.bpf.c)
    proc_event_type:  Optional[str] = None
    proc_root_pid:    Optional[int] = None
    proc_ppid:        Optional[int] = None
    proc_retval:      Optional[int] = None
    proc_path:        Optional[str] = None
    proc_flags:       Optional[int] = None
    proc_dst_addr:    Optional[str] = None
    proc_dst_port:    Optional[int] = None
    proc_bytes_count: Optional[int] = None


def parse_event(
    message_value: bytes,
    message_headers: Optional[List] = None,
) -> Optional[ParsedAgentEvent]:
    """
    Parse one Kafka message into a ParsedAgentEvent.
    Returns None if the message should be discarded (missing key, bad JSON).
    """
    agent_key = _extract_agent_key(message_headers)
    if not agent_key:
        logger.warning("event_parser: missing X-Agent-Key header — discarded")
        return None

    try:
        raw = json.loads(message_value.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("event_parser: JSON decode failed — %s", exc)
        return None

    if not isinstance(raw, dict):
        logger.warning("event_parser: unexpected payload type %s", type(raw))
        return None

    ev = ParsedAgentEvent(agent_key=agent_key, raw_event=raw)
    ev.parse_error   = raw.get("parse_error")
    ev.timestamp_ns  = raw.get("timestamp_ns", 0)
    ev.conn_id       = raw.get("conn_id", 0)
    ev.pid           = raw.get("pid", 0)
    ev.process_name  = raw.get("comm", "")
    ev.src_ip        = raw.get("src_ip", "")
    ev.dst_port      = raw.get("dst_port", 0)
    ev.protocol      = raw.get("protocol", "")
    ev.direction     = raw.get("direction", "")

    if ev.timestamp_ns:
        try:
            ev.occurred_at = datetime.fromtimestamp(ev.timestamp_ns / 1e9, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            ev.occurred_at = None

    ev.schema_version = int(raw.get("schema_version", 1))

    if "http1" in raw:
        _fill_http1(ev, raw["http1"])
    elif "http2" in raw:
        _fill_http2(ev, raw["http2"])
    elif "grpc" in raw:
        _fill_grpc(ev, raw["grpc"])
    elif "mcp" in raw:
        _fill_mcp(ev, raw["mcp"])

    if "ssl_content" in raw:
        _fill_ssl_content(ev, raw["ssl_content"])
    if "proc_event" in raw:
        _fill_proc_event(ev, raw["proc_event"])

    return ev


# ---------------------------------------------------------------------------
# Protocol extractors
# ---------------------------------------------------------------------------

def _fill_http1(ev: ParsedAgentEvent, h1: dict) -> None:
    ev.headers = h1.get("headers", {})
    ev.host    = ev.headers.get("host") or ev.headers.get(":authority")
    if h1.get("is_request"):
        ev.method         = h1.get("method")
        ev.raw_path       = h1.get("path")
        ev.query          = h1.get("query")
        ev.request_size   = h1.get("body_len")
        ev.request_schema = h1.get("body_schema")
    if h1.get("is_response"):
        ev.status_code     = h1.get("status_code")
        ev.response_size   = h1.get("body_len")
        ev.response_schema = h1.get("body_schema")


def _fill_http2(ev: ParsedAgentEvent, h2: dict) -> None:
    req        = h2.get("request", {})
    ev.method  = req.get("method")
    ev.raw_path = req.get("path")
    ev.host    = req.get("authority")
    ev.headers = req.get("headers", {})
    status     = req.get("status")
    if status is not None:
        ev.status_code = status
    for frame in h2.get("frames", []):
        if frame.get("type") == "DATA" and frame.get("data_schema"):
            if not ev.response_schema:
                ev.response_schema = frame["data_schema"]
            break


def _fill_grpc(ev: ParsedAgentEvent, grpc: dict) -> None:
    ev.grpc_service  = grpc.get("service")
    ev.grpc_method   = grpc.get("method")
    ev.raw_path      = f"/{ev.grpc_service}/{ev.grpc_method}" if ev.grpc_service else None
    ev.method        = "POST"
    ev.request_size  = grpc.get("message_len")


def _fill_mcp(ev: ParsedAgentEvent, mcp: dict) -> None:
    ev.mcp_method        = mcp.get("method")
    ev.mcp_params_schema = mcp.get("params_schema")
    ev.mcp_result_schema = mcp.get("result_schema")
    ev.raw_path          = f"/mcp/{mcp.get('method', 'unknown')}"
    ev.method            = "POST"


# ---------------------------------------------------------------------------
# Phase 0: SSL content and process event extractors
# ---------------------------------------------------------------------------

def _fill_ssl_content(ev: ParsedAgentEvent, ssl: dict) -> None:
    ev.ssl_direction      = ssl.get("direction")
    ev.ssl_data           = ssl.get("data")
    ev.ssl_data_len       = ssl.get("data_len")
    ev.ssl_truncated      = bool(ssl.get("truncated", False))
    ev.ssl_seq            = ssl.get("seq")
    ev.ssl_is_reassembled = bool(ssl.get("is_reassembled", False))
    ev.ssl_root_pid       = ssl.get("root_pid")
    ev.protocol           = "HTTPS"
    # If the ssl_data looks like an HTTP payload, extract method/path/host
    data = (ev.ssl_data or "").encode("utf-8", errors="replace")
    if data.startswith(b"POST ") or data.startswith(b"GET "):
        _try_fill_http_from_ssl(ev, data)
    elif ev.ssl_data and ('"messages"' in ev.ssl_data or '"model"' in ev.ssl_data):
        ev.method   = ev.method   or "POST"
        ev.protocol = "HTTPS"


def _try_fill_http_from_ssl(ev: ParsedAgentEvent, raw: bytes) -> None:
    try:
        lines = raw.split(b"\r\n")
        if not lines: return
        parts = lines[0].split(b" ")
        if len(parts) >= 2:
            ev.method   = parts[0].decode("ascii", errors="replace")
            ev.raw_path = parts[1].decode("utf-8", errors="replace")
        for line in lines[1:]:
            if b": " in line:
                k, _, v = line.partition(b": ")
                key = k.decode("ascii", errors="replace").lower()
                val = v.decode("utf-8", errors="replace").strip()
                if key == "host":
                    ev.host = val
                ev.headers[key] = val
    except Exception:
        pass


def _fill_proc_event(ev: ParsedAgentEvent, proc: dict) -> None:
    ev.proc_event_type  = proc.get("event_type")
    ev.proc_root_pid    = proc.get("root_pid")
    ev.proc_ppid        = proc.get("ppid")
    ev.proc_retval      = proc.get("retval")
    ev.proc_path        = proc.get("path")
    ev.proc_flags       = proc.get("flags")
    ev.proc_dst_addr    = proc.get("dst_addr")
    ev.proc_dst_port    = proc.get("dst_port")
    ev.proc_bytes_count = proc.get("bytes_count")
    ev.protocol         = "KERNEL"
    if ev.proc_event_type == "exec" and ev.proc_path and not ev.process_name:
        ev.process_name = ev.proc_path.rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------
# Agent key extraction
# ---------------------------------------------------------------------------

def _extract_agent_key(headers: Optional[List]) -> Optional[str]:
    """Extract X-Agent-Key from Kafka message headers [(name, value_bytes)]."""
    if not headers:
        return None
    for name, value in headers:
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        if name.lower() == "x-agent-key":
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace").strip()
            return str(value).strip()
    return None