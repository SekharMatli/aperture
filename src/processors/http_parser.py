"""
Stateless HTTP/1.x + HTTP/2 parser.
Best-effort on truncated captures (eBPF may not see all fragments).
Stores parse errors in the event rather than raising.
"""
"""
http_parser.py
==============
Protocol-aware payload parser for the eBPF capture agent.

Converts raw TCP payload bytes (from RawEvent) + protocol context
(from DetectionResult) into structured ParsedEvent objects ready for
output. One parser function per protocol, dispatched through parse().

Protocols handled
-----------------
  HTTP/1.x    Full request/response line, headers, body preview.
              Handles pipelining (multiple requests in one payload),
              chunked transfer encoding, and partial/truncated captures.
              JSON/form body schema inferred for OpenAPI generation.

  HTTP/2      Frame-level decode: type, flags, stream ID, payload.
              HEADERS frames: pseudo-headers (:method, :path, :status).
              DATA frames: body length + preview + JSON schema inference.
              SETTINGS, PING, GOAWAY, RST_STREAM: key fields extracted.

  gRPC        HTTP/2 HEADERS (service/method from :path) +
              DATA frame gRPC envelope (compression flag, message length).
              Does not decode protobuf bodies — returns raw bytes.

  WebSocket   Frame decode: opcode, mask, extended length, unmasked payload.
              Upgrade handshake (HTTP/1.1 request / 101 response) extracted
              and forwarded as-is from the HTTP/1.x parser.
              JSON text frames: schema inferred.

  MCP         JSON-RPC 2.0 envelope parse: method, id, params/result fully
              decoded (up to 4 KB). Separate params_schema / result_schema
              fields carry structural type trees for OpenAPI generation.

  TLS         Record layer metadata only (version, content type, HS type).
              No decryption — treated as opaque.

Schema inference (new — for OpenAPI spec generation)
-----------------------------------------------------
  _infer_schema_from_bytes(body, content_type) parses JSON bodies up to
  SCHEMA_INFERENCE_LIMIT (32 KB) and returns a BodySchema dict:

    {
      "schema":    <type tree — all values replaced with type tokens>,
      "truncated": <bool — True if body exceeded SCHEMA_INFERENCE_LIMIT>,
      "root_type": "object" | "array" | "scalar" | "form"
    }

  _schema_of(value) walks parsed JSON and replaces every leaf with a
  type token. String leaves are analysed by _infer_string_format() which
  detects email, uuid, datetime, date, uri, ipv4, jwt, semver, hex,
  base64, phone, and country-code formats.

  body_schema is populated in:
    HTTP1Parsed      — request and response bodies
    H2Frame          — DATA frame payloads (data_schema)
    WSParsed         — JSON text frame payloads (payload_schema)
    MCPParsed        — params_schema and result_schema (inferred from
                       fully-decoded dicts, not raw bytes)

  Values are never stored in schema fields — only field names and types.
  Schema output is safe to forward to the governance cloud for OpenAPI
  spec generation without containing PII or sensitive content.

Design principles
-----------------
- Never raises: all errors caught; returned as ParsedEvent with
  parse_error set and raw_preview included for debugging.
- Stateless: parse() takes a RawEvent + DetectionResult and returns a
  ParsedEvent. No per-connection state is stored here (that is conn_tracker).
- Safe on truncated captures: payload may be clipped to MAX_PAYLOAD_SIZE
  (64 KB). Parsers check lengths before reading and set truncated=True
  in the result when the payload is known to be incomplete.
- No regex on the hot path: HTTP/1.x header parsing is line-split +
  str.partition(), not re.search(). Regex is only used in
  _infer_string_format() which runs off-hot-path after body parsing.

Output hierarchy
----------------
  ParsedEvent               -- top-level container for all protocols
    .meta      EventMeta    -- network/process identity (from RawEvent)
    .detection DetectionResult -- protocol detection context
    .http1     HTTP1Parsed  -- populated for PROTO_HTTP1 / HTTP1_TLS
    .http2     HTTP2Parsed  -- populated for PROTO_HTTP2 / HTTP2_TLS
    .grpc      GRPCParsed   -- populated for PROTO_GRPC
    .ws        WSParsed     -- populated for PROTO_WEBSOCKET
    .mcp       MCPParsed    -- populated for PROTO_MCP
    .tls       TLSParsed    -- populated for PROTO_TLS
    .parse_error  str|None  -- set on any parse failure
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.agent.event_types import Direction, EventMeta, Protocol, RawEvent
from src.processors.protocol_detector import (
    DetectionResult,
    GRPCInfo,
    HTTP2Info,
    MCPInfo,
    TLSInfo,
    WebSocketInfo,
)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Maximum bytes of header value stored in ParsedEvent (prevents log bloat)
MAX_HEADER_VALUE = 512

# Maximum bytes of body preview stored (human-readable snippet for debugging)
BODY_PREVIEW_LEN = 256

# Maximum bytes fed to JSON parser for schema inference.
# 32 KB covers virtually all real-world JSON API bodies. Bodies larger than
# this are schema-inferred from the first 32 KB only; body_schema["truncated"]
# is set True so the cloud-side builder knows the schema may be incomplete.
SCHEMA_INFERENCE_LIMIT = 32_768

# Maximum JSON bytes decoded for full MCP body storage
MAX_JSON_BYTES = 4096

# Maximum recursion depth for _schema_of().
# Prevents stack overflow on pathological deeply-nested JSON inputs.
SCHEMA_MAX_DEPTH = 12

# Maximum object keys written per level in the schema tree.
# Limits schema payload size for objects with hundreds of fields.
SCHEMA_MAX_KEYS = 64

# Number of array items sampled and merged to form the array element schema.
SCHEMA_ARRAY_SAMPLE = 3

# gRPC frame header: 1 byte compression flag + 4 bytes message length
GRPC_FRAME_HDR = 5

# HTTP/2 frame header: 3 bytes length + 1 type + 1 flags + 4 stream ID
H2_FRAME_HDR = 9

# HTTP/2 frame types (RFC 9113 section 6)
H2_DATA         = 0x00
H2_HEADERS      = 0x01
H2_PRIORITY     = 0x02
H2_RST_STREAM   = 0x03
H2_SETTINGS     = 0x04
H2_PUSH_PROMISE = 0x05
H2_PING         = 0x06
H2_GOAWAY       = 0x07
H2_WINDOW_UPD   = 0x08
H2_CONTINUATION = 0x09

H2_FRAME_NAMES = {
    H2_DATA:         "DATA",
    H2_HEADERS:      "HEADERS",
    H2_PRIORITY:     "PRIORITY",
    H2_RST_STREAM:   "RST_STREAM",
    H2_SETTINGS:     "SETTINGS",
    H2_PUSH_PROMISE: "PUSH_PROMISE",
    H2_PING:         "PING",
    H2_GOAWAY:       "GOAWAY",
    H2_WINDOW_UPD:   "WINDOW_UPDATE",
    H2_CONTINUATION: "CONTINUATION",
}

# HTTP/2 SETTINGS parameters (RFC 9113 section 6.5.2)
H2_SETTINGS_NAMES = {
    0x1: "HEADER_TABLE_SIZE",
    0x2: "ENABLE_PUSH",
    0x3: "MAX_CONCURRENT_STREAMS",
    0x4: "INITIAL_WINDOW_SIZE",
    0x5: "MAX_FRAME_SIZE",
    0x6: "MAX_HEADER_LIST_SIZE",
}

# HTTP/2 error codes for RST_STREAM and GOAWAY (RFC 9113 section 7)
H2_ERROR_NAMES = {
    0x0: "NO_ERROR",           0x1: "PROTOCOL_ERROR",
    0x2: "INTERNAL_ERROR",     0x3: "FLOW_CONTROL_ERROR",
    0x4: "SETTINGS_TIMEOUT",   0x5: "STREAM_CLOSED",
    0x6: "FRAME_SIZE_ERROR",   0x7: "REFUSED_STREAM",
    0x8: "CANCEL",             0x9: "COMPRESSION_ERROR",
    0xa: "CONNECT_ERROR",      0xb: "ENHANCE_YOUR_CALM",
    0xc: "INADEQUATE_SECURITY", 0xd: "HTTP_1_1_REQUIRED",
}

# TLS record content types
TLS_CONTENT_NAMES = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
}

# WebSocket opcode names
WS_OPCODE_NAMES = {
    0x0: "continuation", 0x1: "text",   0x2: "binary",
    0x8: "close",        0x9: "ping",   0xa: "pong",
}

# Content-type prefixes that indicate a JSON body worth schema-inferring
_JSON_CONTENT_TYPES = (
    "application/json",
    "application/json-rpc",
    "application/ld+json",
    "application/vnd.",   # catches application/vnd.api+json etc.
    "text/json",
)

# Content-type for form-encoded bodies
_FORM_CONTENT_TYPES = (
    "application/x-www-form-urlencoded",
)


# -----------------------------------------------------------------------------
# Schema inference helpers
# -----------------------------------------------------------------------------

# Compiled at module load — regex only runs off hot path (after body parsing)
_RE_EMAIL    = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_RE_DATE     = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_RE_DATETIME = re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}')
_RE_UUID     = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_RE_URI      = re.compile(r'^https?://')
_RE_IP4      = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_RE_PHONE    = re.compile(r'^\+?[\d\s\-().]{7,20}$')
_RE_SEMVER   = re.compile(r'^\d+\.\d+\.\d+')
_RE_JWT      = re.compile(r'^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
_RE_HEX      = re.compile(r'^(0x)?[0-9a-f]+$', re.I)
_RE_BASE64   = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
_RE_COUNTRY  = re.compile(r'^[A-Z]{2}$')


def _infer_string_format(s: str) -> str:
    """
    Return a type token describing the format of string value s.

    Checks are ordered from most- to least-specific; first match wins.
    Falls back to plain "string" when no format is detected.

    Tokens map to OpenAPI string formats:
      "string:email"    → format: email
      "string:uuid"     → format: uuid
      "string:datetime" → format: date-time
      "string:date"     → format: date
      "string:uri"      → format: uri
      "string:ipv4"     → format: ipv4
      "string:jwt"      → (custom) JWT bearer token
      "string:semver"   → (custom) semantic version
      "string:hex"      → (custom) hexadecimal string
      "string:base64"   → format: byte
      "string:phone"    → (custom) phone number
      "string:country-code" → ISO 3166-1 alpha-2
    """
    if not s:
        return "string"
    ln = len(s)

    # JWT: always starts "ey", three base64url segments
    if ln > 20 and s.startswith("ey") and _RE_JWT.match(s):
        return "string:jwt"
    # ISO datetime (check before date — datetime is more specific)
    if ln >= 16 and _RE_DATETIME.match(s):
        return "string:datetime"
    if ln == 10 and _RE_DATE.match(s):
        return "string:date"
    # UUID: exactly 36 chars with dashes
    if ln == 36 and _RE_UUID.match(s):
        return "string:uuid"
    # URI / URL
    if ln > 7 and _RE_URI.match(s):
        return "string:uri"
    # Email
    if 5 < ln < 254 and "@" in s and _RE_EMAIL.match(s):
        return "string:email"
    # IPv4
    if 7 <= ln <= 15 and _RE_IP4.match(s):
        return "string:ipv4"
    # Semantic version
    if ln < 20 and _RE_SEMVER.match(s):
        return "string:semver"
    # Two-letter uppercase country code (only flag unambiguous cases)
    if ln == 2 and _RE_COUNTRY.match(s):
        return "string:country-code"
    # Phone (rough heuristic — only flag if no other format matched)
    if 7 <= ln <= 20 and _RE_PHONE.match(s):
        return "string:phone"
    # Hex string (only flag longer strings to avoid false positives on short words)
    if ln > 8 and _RE_HEX.match(s):
        return "string:hex"
    # Base64 (long strings only)
    if ln > 32 and _RE_BASE64.match(s):
        return "string:base64"

    return "string"


def _schema_of(value: Any, depth: int = 0) -> Any:
    """
    Recursively replace all leaf values with type tokens.

    dict  → same keys, values replaced recursively. Keys beyond
            SCHEMA_MAX_KEYS are omitted; "_additional_keys": N is
            added to record how many were dropped.
    list  → single-element list containing the merged schema of the
            first SCHEMA_ARRAY_SAMPLE items.
    bool  → "boolean"   (checked before int — bool subclasses int)
    int   → "integer"
    float → "number"
    str   → "string" or "string:<format>"
    None  → "null"

    Depth is capped at SCHEMA_MAX_DEPTH; returns {"_depth_limit": True}
    when exceeded.
    """
    if depth > SCHEMA_MAX_DEPTH:
        return {"_depth_limit": True}

    if isinstance(value, dict):
        items = list(value.items())
        result: Dict[str, Any] = {}
        for k, v in items[:SCHEMA_MAX_KEYS]:
            result[str(k)] = _schema_of(v, depth + 1)
        if len(items) > SCHEMA_MAX_KEYS:
            result["_additional_keys"] = len(items) - SCHEMA_MAX_KEYS
        return result

    if isinstance(value, list):
        if not value:
            return []
        schemas = [_schema_of(item, depth + 1) for item in value[:SCHEMA_ARRAY_SAMPLE]]
        return [_merge_schemas(schemas)]

    if isinstance(value, bool):  return "boolean"
    if isinstance(value, int):   return "integer"
    if isinstance(value, float): return "number"
    if isinstance(value, str):   return _infer_string_format(value)
    if value is None:            return "null"
    return "unknown"


def _merge_schemas(schemas: List[Any]) -> Any:
    """
    Merge a list of schema values into one representative schema.

    All dicts → merge keys (union); conflicting values merged recursively.
    All same scalar → return that scalar.
    Mixed         → return deduplicated list of observed types.
    """
    if not schemas:
        return "unknown"
    if len(schemas) == 1:
        return schemas[0]

    if all(isinstance(s, dict) for s in schemas):
        merged: Dict[str, Any] = {}
        for s in schemas:
            for k, v in s.items():
                if k not in merged:
                    merged[k] = v
                else:
                    merged[k] = _merge_schemas([merged[k], v])
        return merged

    unique = list(dict.fromkeys(str(s) for s in schemas))
    if len(unique) == 1:
        return schemas[0]
    return schemas  # heterogeneous — return the list of seen types


def _is_json_content_type(ct: Optional[str]) -> bool:
    """Return True if Content-Type header indicates a JSON body."""
    if not ct:
        return False
    ct_lower = ct.lower().split(";")[0].strip()
    return any(ct_lower.startswith(j) for j in _JSON_CONTENT_TYPES)


def _is_form_content_type(ct: Optional[str]) -> bool:
    """Return True if Content-Type indicates a URL-encoded form body."""
    if not ct:
        return False
    ct_lower = ct.lower().split(";")[0].strip()
    return any(ct_lower.startswith(f) for f in _FORM_CONTENT_TYPES)


def _infer_schema_from_bytes(
    body: bytes,
    content_type: Optional[str] = None,
    limit: int = SCHEMA_INFERENCE_LIMIT,
) -> Optional[Dict[str, Any]]:
    """
    Attempt to infer a JSON body schema from raw bytes.
    Parse JSON body up to `limit` bytes and return its structural schema
    with all leaf values replaced by type tokens.
    Values are discarded — only field names and types are retained.
    Safe to send to cloud: no PII, no content.
    Parameters
    ----------
    body : bytes
        Raw body bytes (may be a partial capture truncated at the BPF layer).
    content_type : str, optional
        Content-Type header value. When provided and not a JSON type,
        inference is skipped without attempting json.loads().
        Form-encoded bodies are inferred via _infer_form_schema() instead.
    limit : int
        Maximum bytes fed to json.loads(). Defaults to SCHEMA_INFERENCE_LIMIT.

    Returns
    -------
    dict with keys:
        schema    : type tree (all leaf values replaced with type tokens)
        truncated : True if body exceeded limit (schema may be incomplete)
        root_type : "object" | "array" | "scalar" | "form"

    Returns None if the body is empty, not JSON-parseable, or the
    content-type explicitly indicates a non-JSON format.
    """
    if not body:
        return None

    # Fast-path: skip non-JSON bodies when content-type is explicit
    if content_type:
        if _is_form_content_type(content_type):
            return _infer_form_schema(body[:limit])
        if not _is_json_content_type(content_type):
            return None

    # Even without a content-type header, attempt inference if the body
    # starts with a JSON delimiter (common for APIs that omit the header)
    stripped = body.lstrip()
    if not stripped or stripped[0:1] not in (b"{", b"["):
        return None

    truncated = len(body) > limit
    sample    = body[:limit]

    try:
        parsed = json.loads(sample)
    except (json.JSONDecodeError, ValueError):
        # Body truncated mid-JSON: attempt recovery from a valid prefix
        parsed = _parse_partial_json(sample)
        if parsed is None:
            return None
        truncated = True
    except Exception:
        return None

    schema = _schema_of(parsed)
    if isinstance(parsed, dict):
        root_type = "object"
    elif isinstance(parsed, list):
        root_type = "array"
    else:
        root_type = "scalar"

    return {"schema": schema, "truncated": truncated, "root_type": root_type}


def _infer_form_schema(body: bytes) -> Optional[Dict[str, Any]]:
    """
    Infer schema from application/x-www-form-urlencoded body.

    Returns field names with type "string" (form values are always strings
    after URL-decoding). Useful for OpenAPI requestBody with form encoding.
    """
    try:
        text = body.decode("utf-8", errors="replace")
        schema: Dict[str, str] = {}
        for pair in text.split("&"):
            if "=" in pair:
                key = pair.split("=", 1)[0].strip()
                if key:
                    schema[key] = "string"
        if not schema:
            return None
        return {"schema": schema, "truncated": False, "root_type": "form"}
    except Exception:
        return None


def _parse_partial_json(data: bytes) -> Optional[Any]:
    """
    Attempt to parse a truncated JSON fragment by finding a valid prefix.

    Scans backwards for the last closing brace or bracket and tries to
    parse progressively shorter slices. Handles the common case of a large
    JSON response body truncated mid-string or mid-value by the 64 KB BPF
    capture cap.
    """
    text = data.decode("utf-8", errors="replace")
    for closer, _ in [('}', '{'), (']', '[')]:
        idx = text.rfind(closer)
        while idx > 0:
            try:
                return json.loads(text[:idx + 1])
            except json.JSONDecodeError:
                idx = text.rfind(closer, 0, idx)
    return None


# -----------------------------------------------------------------------------
# Per-protocol parsed result dataclasses
# -----------------------------------------------------------------------------

@dataclass(slots=True)
class HTTP1Parsed:
    """
    Parsed HTTP/1.x request or response.

    Both request and response fields are on the same object;
    which are populated depends on is_request / is_response.

    body_schema contains the structural type tree of the body (values
    replaced with type tokens). Populated for JSON and form-encoded
    bodies. None for binary, empty, or unknown content types.

    And in the governance cloud, the spec builder accumulates these schemas across requests,
    merges them into a single schema per endpoint, infers required vs optional fields,
    and emits OpenAPI 3.0 YAML.

    Pipelining note:
        A single TCP segment can carry multiple HTTP/1.1 pipelined
        requests/responses. additional_messages holds any beyond the first.

    ## The full picture of what generates a complete OpenAPI spec

    Agent emits per-request:          Cloud accumulates across N requests:
    ──────────────────────────        ──────────────────────────────────────
    method:       POST                path pattern:  /v1/chat/completions
    path:         /v1/chat/           (clustered from raw paths)
                  completions
    host:         api.openai.com      request body schema:
                                        model:       string (required)
    request       {                     messages:    array<object> (required)
    body_schema:    model: string       temperature: number (optional)
                    messages: [...]     stream:      boolean (optional)
                    temperature:        max_tokens:  integer (optional)
                      number
                  }                   response body schema:
                                        id:          string:uuid
    response      {                     object:      string:enum
    body_schema:    id: string:uuid     choices:     array<object>
                    choices: [...]      usage:       object
                    usage: {...}
                  }                   → emits OpenAPI 3.0 YAML
    status: 200
    latency: 342ms

    Your agent already emits everything in the left column except body_schema.
    That's the one addition needed. The right column — path clustering, schema merging,
    optional/required inference, OpenAPI YAML generation — lives in the governance cloud, not the agent.
    """
    is_request:   bool
    is_response:  bool

    # Request-only fields
    method:       Optional[str]        = None  # "GET", "POST", etc.
    path:         Optional[str]        = None  # "/api/v1/users"
    query:        Optional[str]        = None  # "page=2" (split from path)
    http_version: Optional[str]        = None  # "HTTP/1.1"

    # Response-only fields
    status_code:  Optional[int]        = None  # 200, 404, etc.
    status_text:  Optional[str]        = None  # "OK", "Not Found"

    # Common fields
    headers:      Dict[str, str]       = field(default_factory=dict)
    body_len:     int                  = 0
    body_preview: bytes                = b""
    body_schema:  Optional[Dict]       = None   # NEW: structural type tree
    chunked:      bool                 = False
    keep_alive:   bool                 = True
    truncated:    bool                 = False

    # Pipelined messages beyond the first
    additional_messages: List["HTTP1Parsed"] = field(default_factory=list)

    @property
    def content_type(self) -> Optional[str]:
        return self.headers.get("content-type")

    @property
    def host(self) -> Optional[str]:
        return self.headers.get("host")

    def to_dict(self) -> dict:
        d: dict = {
            "is_request":   self.is_request,
            "is_response":  self.is_response,
            "http_version": self.http_version,
            "headers": {
                k: v for k, v in self.headers.items()
                if k.lower() not in ("authorization", "cookie", "set-cookie")
            },
            "body_len":     self.body_len,
            "body_preview": self.body_preview.decode("utf-8", errors="replace"),
            "chunked":      self.chunked,
            "keep_alive":   self.keep_alive,
            "truncated":    self.truncated,
        }
        if self.is_request:
            d.update({"method": self.method, "path": self.path, "query": self.query})
        if self.is_response:
            d.update({"status_code": self.status_code, "status_text": self.status_text})
        if self.body_schema is not None:
            d["body_schema"] = self.body_schema
        if self.additional_messages:
            d["pipelined_count"] = len(self.additional_messages)
        return d


@dataclass(slots=True)
class HTTP2Parsed:
    """
    Parsed HTTP/2 frame(s) from one TCP payload.

    All frames in the payload are decoded. The first HEADERS frame's
    pseudo-headers are promoted to top-level fields for convenience.
    """
    has_client_preface: bool            = False
    frames:             List["H2Frame"] = field(default_factory=list)

    # Promoted from first HEADERS frame
    method:    Optional[str]            = None
    path:      Optional[str]            = None
    scheme:    Optional[str]            = None
    authority: Optional[str]            = None
    status:    Optional[int]            = None
    headers:   Dict[str, str]           = field(default_factory=dict)
    truncated: bool                     = False

    def to_dict(self) -> dict:
        d: dict = {
            "has_client_preface": self.has_client_preface,
            "frame_count":        len(self.frames),
            "frames":             [f.to_dict() for f in self.frames],
            "truncated":          self.truncated,
        }
        if self.method or self.path or self.status:
            d["request"] = {
                "method":    self.method,
                "path":      self.path,
                "scheme":    self.scheme,
                "authority": self.authority,
                "status":    self.status,
                "headers": {
                    k: v for k, v in self.headers.items()
                    if k.lower() not in ("authorization",)
                },
            }
        return d


@dataclass(slots=True)
class H2Frame:
    """One decoded HTTP/2 frame."""
    frame_type:       int
    type_name:        str
    flags:            int
    stream_id:        int
    payload_len:      int

    pseudo_headers:   Dict[str, str]  = field(default_factory=dict)
    regular_headers:  Dict[str, str]  = field(default_factory=dict)
    data_preview:     bytes           = b""
    data_schema:      Optional[Dict]  = None   # NEW: schema for DATA frames
    settings:         Dict[str, int]  = field(default_factory=dict)
    error_code:       Optional[int]   = None
    error_name:       Optional[str]   = None
    window_increment: Optional[int]   = None
    last_stream_id:   Optional[int]   = None

    def to_dict(self) -> dict:
        d: dict = {
            "type":        self.type_name,
            "flags":       f"0x{self.flags:02x}",
            "stream_id":   self.stream_id,
            "payload_len": self.payload_len,
        }
        if self.pseudo_headers:
            d["pseudo_headers"] = self.pseudo_headers
        if self.regular_headers:
            d["headers"] = {k: v for k, v in self.regular_headers.items()
                            if k not in ("authorization",)}
        if self.data_preview:
            d["data_preview"] = self.data_preview.decode("utf-8", errors="replace")
        if self.data_schema is not None:
            d["data_schema"] = self.data_schema
        if self.settings:
            d["settings"] = self.settings
        if self.error_code is not None:
            d["error_code"] = self.error_code
            d["error_name"] = self.error_name
        if self.window_increment is not None:
            d["window_increment"] = self.window_increment
        if self.last_stream_id is not None:
            d["last_stream_id"] = self.last_stream_id
        return d


@dataclass(slots=True)
class GRPCParsed:
    """Parsed gRPC message (HTTP/2 DATA frame with gRPC framing)."""
    service:         Optional[str]         = None
    method_name:     Optional[str]         = None
    compressed:      Optional[bool]        = None
    message_len:     Optional[int]         = None
    message_preview: bytes                 = b""
    http2:           Optional[HTTP2Parsed] = None
    truncated:       bool                  = False

    @property
    def full_method(self) -> Optional[str]:
        if self.service and self.method_name:
            return f"/{self.service}/{self.method_name}"
        return None

    def to_dict(self) -> dict:
        return {
            "service":         self.service,
            "method":          self.method_name,
            "full_method":     self.full_method,
            "compressed":      self.compressed,
            "message_len":     self.message_len,
            "message_preview": self.message_preview.decode("utf-8", errors="replace"),
            "truncated":       self.truncated,
            "http2_frames":    self.http2.to_dict() if self.http2 else None,
        }


@dataclass(slots=True)
class WSParsed:
    """Parsed WebSocket frame or upgrade handshake."""
    http1:          Optional[HTTP1Parsed] = None  # upgrade handshake

    fin:            Optional[bool]        = None
    opcode:         Optional[int]         = None
    opcode_name:    Optional[str]         = None
    masked:         Optional[bool]        = None
    payload_len:    Optional[int]         = None
    payload:        bytes                 = b""
    payload_schema: Optional[Dict]        = None  # NEW: schema for JSON text frames
    truncated:      bool                  = False

    def to_dict(self) -> dict:
        if self.http1:
            return {"upgrade": self.http1.to_dict()}
        d: dict = {
            "fin":          self.fin,
            "opcode":       self.opcode,
            "opcode_name":  self.opcode_name,
            "masked":       self.masked,
            "payload_len":  self.payload_len,
            "payload_preview": self.payload[:BODY_PREVIEW_LEN].decode(
                "utf-8", errors="replace"),
            "truncated":    self.truncated,
        }
        if self.payload_schema is not None:
            d["payload_schema"] = self.payload_schema
        return d


@dataclass(slots=True)
class MCPParsed:
    """
    Parsed MCP (Model Context Protocol) JSON-RPC 2.0 message.

    params_schema and result_schema are inferred from the already-decoded
    params/result dicts (not from raw bytes), giving the most accurate
    structural schema possible for MCP tool call auditing and OpenAPI
    generation.
    """
    jsonrpc_version: Optional[str]  = None
    method:          Optional[str]  = None
    msg_id:          Optional[str]  = None
    is_request:      bool           = False
    is_response:     bool           = False
    is_notification: bool           = False
    is_error:        bool           = False
    params:          Optional[dict] = None
    result:          Optional[dict] = None
    error:           Optional[dict] = None
    params_schema:   Optional[dict] = None  # NEW: structural type tree of params
    result_schema:   Optional[dict] = None  # NEW: structural type tree of result
    truncated:       bool           = False

    def to_dict(self) -> dict:
        d: dict = {
            "jsonrpc":         self.jsonrpc_version,
            "method":          self.method,
            "id":              self.msg_id,
            "is_request":      self.is_request,
            "is_response":     self.is_response,
            "is_notification": self.is_notification,
            "is_error":        self.is_error,
            "truncated":       self.truncated,
        }
        if self.params         is not None: d["params"]         = self.params
        if self.result         is not None: d["result"]         = self.result
        if self.error          is not None: d["error"]          = self.error
        if self.params_schema  is not None: d["params_schema"]  = self.params_schema
        if self.result_schema  is not None: d["result_schema"]  = self.result_schema
        return d


@dataclass(slots=True)
class TLSParsed:
    """Parsed TLS record layer metadata. No decryption."""
    record_type:   int
    record_name:   str
    version:       Optional[str]  = None
    is_handshake:  bool           = False
    hs_type:       Optional[int]  = None
    hs_type_name:  Optional[str]  = None
    record_length: Optional[int]  = None

    def to_dict(self) -> dict:
        return {
            "record_type":  self.record_name,
            "version":      self.version,
            "is_handshake": self.is_handshake,
            "hs_type":      self.hs_type_name,
            "record_len":   self.record_length,
        }


# -----------------------------------------------------------------------------
# Top-level ParsedEvent
# -----------------------------------------------------------------------------

@dataclass(slots=True)
class ParsedEvent:
    """
    Fully parsed eBPF capture event, ready for output.

    Exactly one of http1/http2/grpc/ws/mcp/tls is non-None,
    matching the detected protocol. parse_error is set on failure.
    raw_preview is always populated for debuggability.

    Lifecycle:
        RawEvent -> ProtocolDetector.detect() -> parse() -> ParsedEvent
        ParsedEvent -> OutputDispatcher -> stdout/file/Kafka/webhook
    """
    meta:        EventMeta
    detection:   DetectionResult

    http1:       Optional[HTTP1Parsed]  = None
    http2:       Optional[HTTP2Parsed]  = None
    grpc:        Optional[GRPCParsed]   = None
    ws:          Optional[WSParsed]     = None
    mcp:         Optional[MCPParsed]    = None
    tls:         Optional[TLSParsed]    = None

    parse_error: Optional[str]          = None
    raw_preview: str                    = ""

    def to_dict(self, include_detection: bool = False) -> dict:
        d = self.meta.to_dict()
        d["raw_preview"] = self.raw_preview

        if   self.http1: d["http1"]     = self.http1.to_dict()
        elif self.http2: d["http2"]     = self.http2.to_dict()
        elif self.grpc:  d["grpc"]      = self.grpc.to_dict()
        elif self.ws:    d["websocket"] = self.ws.to_dict()
        elif self.mcp:   d["mcp"]       = self.mcp.to_dict()
        elif self.tls:   d["tls"]       = self.tls.to_dict()

        if self.parse_error:
            d["parse_error"] = self.parse_error
        if include_detection:
            d["detection"] = self.detection.to_dict()
        return d


# -----------------------------------------------------------------------------
# HTTPParser -- main dispatcher
# -----------------------------------------------------------------------------

class HTTPParser:
    """
    Stateless multi-protocol payload parser.

    One singleton instance per agent. All parsing is done in parse(),
    called once per RawEvent after ProtocolDetector.detect().

    Usage
    -----
        parser = HTTPParser()
        result = detector.detect(event)
        parsed = parser.parse(event, result)
        dispatcher.dispatch(parsed)
    """

    def parse(self, event: RawEvent, detection: DetectionResult) -> ParsedEvent:
        """
        Parse one RawEvent using the protocol identified by detection.

        Always returns a ParsedEvent -- never raises.
        On any parse failure, parse_error is set and parsing falls back
        to a raw preview only.
        """
        raw_preview = _printable_preview(event.payload, 128)
        base = dict(meta=event.meta, detection=detection, raw_preview=raw_preview)

        try:
            proto = detection.final_protocol

            if proto in (Protocol.HTTP1, Protocol.HTTP1_TLS):
                return ParsedEvent(**base, http1=self._parse_http1(event.payload, event.meta))

            elif proto in (Protocol.HTTP2, Protocol.HTTP2_TLS):
                return ParsedEvent(**base, http2=self._parse_http2(event.payload))

            elif proto == Protocol.GRPC:
                return ParsedEvent(**base, grpc=self._parse_grpc(event.payload, detection.grpc_info))

            elif proto == Protocol.WEBSOCKET:
                return ParsedEvent(**base, ws=self._parse_websocket(event.payload, detection.websocket_info))

            elif proto == Protocol.MCP:
                return ParsedEvent(**base, mcp=self._parse_mcp(event.payload, detection.mcp_info))

            elif proto == Protocol.TLS:
                return ParsedEvent(**base, tls=self._parse_tls(event.payload, detection.tls_info))

            else:
                return ParsedEvent(**base)  # UNKNOWN -- raw preview only

        except Exception as exc:
            return ParsedEvent(**base, parse_error=f"{type(exc).__name__}: {exc}")

    # -------------------------------------------------------------------------
    # HTTP/1.x parser
    # -------------------------------------------------------------------------

    def _parse_http1(self, buf: bytes, meta: EventMeta) -> HTTP1Parsed:
        """
        Parse an HTTP/1.x request or response from raw bytes.

        Handles:
          - Request:  METHOD SP request-target SP HTTP-version CRLF headers CRLF body
          - Response: HTTP-version SP status-code SP reason-phrase CRLF headers CRLF body
          - Pipelining: multiple messages in one segment
          - Chunked Transfer-Encoding: chunk sizes decoded, body not reassembled
          - Truncation: payload clipped at MAX_PAYLOAD_SIZE
          - Schema inference: JSON and form-encoded bodies
        """
        messages = _split_http1_messages(buf)
        if not messages:
            return self._parse_http1_partial(buf, meta)

        primary = self._parse_single_http1(messages[0], meta,
                                           truncated=len(messages) == 1 and meta.truncated)
        for extra_buf in messages[1:]:
            primary.additional_messages.append(
                self._parse_single_http1(extra_buf, meta, truncated=False))
        return primary

    def _parse_http1_partial(self, buf: bytes, meta: EventMeta) -> HTTP1Parsed:
        """Handle a payload with no CRLFCRLF separator -- partial capture."""
        first_line_end = buf.find(b"\r\n")
        if first_line_end == -1:
            result = HTTP1Parsed(is_request=False, is_response=False, truncated=True)
            result.body_preview = buf[:BODY_PREVIEW_LEN]
            return result
        return self._parse_single_http1(buf, meta, truncated=True)

    def _parse_single_http1(self, buf: bytes, meta: EventMeta,
                             truncated: bool) -> HTTP1Parsed:
        """Parse exactly one HTTP/1.x message from buf."""
        result = HTTP1Parsed(is_request=False, is_response=False, truncated=truncated)

        # First line
        first_line_end = buf.find(b"\r\n")
        if first_line_end == -1:
            first_line_end = min(len(buf), 256)
        first_line = buf[:first_line_end].decode("latin-1", errors="replace")

        if first_line.startswith("HTTP/"):
            result.is_response  = True
            parts               = first_line.split(" ", 2)
            result.http_version = parts[0] if parts else None
            if len(parts) >= 2:
                try:
                    result.status_code = int(parts[1])
                except ValueError:
                    pass
            result.status_text = parts[2].strip() if len(parts) >= 3 else None
        else:
            result.is_request   = True
            parts               = first_line.split(" ", 2)
            result.method       = parts[0].upper() if parts else None
            if len(parts) >= 2:
                raw_path = parts[1]
                if "?" in raw_path:
                    result.path, result.query = raw_path.split("?", 1)
                else:
                    result.path = raw_path
            result.http_version = parts[2].strip() if len(parts) >= 3 else None

        # Headers
        header_end = buf.find(b"\r\n\r\n")
        if header_end == -1:
            header_section   = buf[first_line_end + 2:]
            result.truncated = True
        else:
            header_section = buf[first_line_end + 2 : header_end]

        result.headers = _parse_headers(header_section)

        # Connection / Transfer flags
        conn_hdr          = result.headers.get("connection", "").lower()
        result.keep_alive = "close" not in conn_hdr
        te_hdr            = result.headers.get("transfer-encoding", "").lower()
        result.chunked    = "chunked" in te_hdr

        # Body + schema inference
        if header_end != -1:
            body = buf[header_end + 4:]
            ct   = result.headers.get("content-type")

            if result.chunked:
                result.body_len, result.body_preview = _decode_chunked_body(body)
                # Use decoded preview bytes for schema — reassembled chunk data
                body_for_schema = result.body_preview
            else:
                cl = result.headers.get("content-length", "")
                try:
                    result.body_len = int(cl)
                except ValueError:
                    result.body_len = len(body)
                result.body_preview = body[:BODY_PREVIEW_LEN]
                body_for_schema     = body  # full captured body, up to 64 KB

            # Infer schema from the full captured body bytes (up to SCHEMA_INFERENCE_LIMIT).
            # This is the primary data path for OpenAPI spec generation.
            result.body_schema = _infer_schema_from_bytes(body_for_schema, content_type=ct)

        return result

    # -------------------------------------------------------------------------
    # HTTP/2 parser
    # -------------------------------------------------------------------------

    def _parse_http2(self, buf: bytes) -> HTTP2Parsed:
        """
        Decode all HTTP/2 frames present in the payload.

        HTTP/2 frame format (RFC 9113 section 4.1):
          bytes 0-2:  payload length (24-bit big-endian)
          byte  3:    type
          byte  4:    flags
          bytes 5-8:  stream identifier (31-bit unsigned, MSB reserved)
          bytes 9+:   frame payload

        The client connection preface (24 bytes) is skipped if present.
        Frames are decoded until buffer exhaustion or a malformed header.
        DATA frames have their JSON body schema inferred when the payload
        starts with '{' or '['.
        """
        result = HTTP2Parsed()
        offset = 0

        PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        if buf[:24] == PREFACE:
            result.has_client_preface = True
            offset = 24

        first_headers_done = False
        _content_type: Optional[str] = None  # propagated from HEADERS to DATA frames

        while offset + H2_FRAME_HDR <= len(buf):
            length = struct.unpack_from(">I", b"\x00" + buf[offset:offset+3])[0]
            ftype  = buf[offset + 3]
            flags  = buf[offset + 4]
            sid    = struct.unpack_from(">I", buf, offset + 5)[0] & 0x7FFFFFFF
            offset += H2_FRAME_HDR

            available       = len(buf) - offset
            truncated_frame = length > available
            actual_len      = min(length, available)
            frame_payload   = buf[offset : offset + actual_len]

            frame = H2Frame(
                frame_type  = ftype,
                type_name   = H2_FRAME_NAMES.get(ftype, f"0x{ftype:02x}"),
                flags       = flags,
                stream_id   = sid,
                payload_len = length,
            )

            if ftype == H2_HEADERS:
                _decode_h2_headers_frame(frame, frame_payload, flags)
                if not first_headers_done:
                    ph                 = frame.pseudo_headers
                    result.method      = ph.get(":method")
                    result.path        = ph.get(":path")
                    result.scheme      = ph.get(":scheme")
                    result.authority   = ph.get(":authority")
                    status_str         = ph.get(":status")
                    if status_str:
                        try:
                            result.status = int(status_str)
                        except ValueError:
                            pass
                    result.headers     = dict(frame.regular_headers)
                    first_headers_done = True
                    # Capture content-type so DATA frame schema inference can use it
                    _content_type = frame.regular_headers.get("content-type")

            elif ftype == H2_DATA:
                frame.data_preview = frame_payload[:BODY_PREVIEW_LEN]
                # Infer JSON schema for DATA frames (carries request/response body)
                if frame_payload:
                    frame.data_schema = _infer_schema_from_bytes(
                        frame_payload, content_type=_content_type)

            elif ftype == H2_SETTINGS:
                _decode_h2_settings_frame(frame, frame_payload)

            elif ftype == H2_RST_STREAM:
                if len(frame_payload) >= 4:
                    code             = struct.unpack_from(">I", frame_payload)[0]
                    frame.error_code = code
                    frame.error_name = H2_ERROR_NAMES.get(code, f"0x{code:04x}")

            elif ftype == H2_GOAWAY:
                if len(frame_payload) >= 8:
                    frame.last_stream_id = struct.unpack_from(">I", frame_payload)[0] & 0x7FFFFFFF
                    code                 = struct.unpack_from(">I", frame_payload, 4)[0]
                    frame.error_code     = code
                    frame.error_name     = H2_ERROR_NAMES.get(code, f"0x{code:04x}")

            elif ftype == H2_WINDOW_UPD:
                if len(frame_payload) >= 4:
                    frame.window_increment = struct.unpack_from(">I", frame_payload)[0] & 0x7FFFFFFF

            result.frames.append(frame)

            if truncated_frame:
                result.truncated = True
                break
            offset += length

        return result

    # -------------------------------------------------------------------------
    # gRPC parser
    # -------------------------------------------------------------------------

    def _parse_grpc(self, buf: bytes, grpc_info: Optional[GRPCInfo]) -> GRPCParsed:
        """
        Parse a gRPC message from HTTP/2 DATA frame(s).

        gRPC wire format:
          byte  0:    Compressed-Flag (0x00 uncompressed, 0x01 compressed)
          bytes 1-4:  Message-Length (32-bit big-endian)
          bytes 5+:   message body (Protocol Buffer or other codec)

        The H2 frame structure is decoded first; the gRPC envelope is
        extracted from the first DATA frame payload.

        Schema inference is not performed for gRPC: protobuf wire format is
        binary (not JSON) and requires the compiled .proto descriptor to
        decode. Service and method name from :path are the primary signals
        for gRPC schema generation on the cloud side.
        """
        result = GRPCParsed()
        h2     = self._parse_http2(buf)
        result.http2 = h2

        if grpc_info:
            result.service     = grpc_info.service
            result.method_name = grpc_info.method

        for frame in h2.frames:
            if frame.frame_type == H2_DATA and len(frame.data_preview) >= GRPC_FRAME_HDR:
                data               = frame.data_preview
                result.compressed  = data[0] == 0x01
                result.message_len = struct.unpack_from(">I", data, 1)[0]
                result.message_preview = data[GRPC_FRAME_HDR : GRPC_FRAME_HDR + BODY_PREVIEW_LEN]
                break

        result.truncated = h2.truncated
        return result

    # -------------------------------------------------------------------------
    # WebSocket parser
    # -------------------------------------------------------------------------

    def _parse_websocket(self, buf: bytes,
                          ws_info: Optional[WebSocketInfo]) -> WSParsed:
        """
        Parse a WebSocket frame or HTTP/1.1 upgrade handshake.

        Upgrade messages (Upgrade: websocket request / 101 response)
        are delegated to the HTTP/1.x parser.

        WS data frame structure (RFC 6455 section 5.2):
          byte 0: FIN(7) RSV1-3(6-4) opcode(3-0)
          byte 1: MASK(7) payload-len(6-0)
          [2 bytes extended length if plen==126]
          [8 bytes extended length if plen==127]
          [4 bytes masking key if MASK=1]
          payload bytes (XOR-unmasked if MASK=1)

        Schema inference: opcode=0x1 (text) frames are inferred as JSON
        when the unmasked payload starts with '{' or '['. This covers
        MCP-over-WebSocket and other JSON-based WS protocols.
        """
        if ws_info and (ws_info.is_upgrade_request or ws_info.is_upgrade_response):
            http1 = self._parse_http1(buf, _dummy_meta())
            return WSParsed(http1=http1)

        if len(buf) < 2:
            return WSParsed(truncated=True)

        byte0  = buf[0]
        byte1  = buf[1]
        fin    = bool(byte0 & 0x80)
        opcode = byte0 & 0x0F
        masked = bool(byte1 & 0x80)
        plen   = byte1 & 0x7F
        offset = 2

        if plen == 126:
            if len(buf) < 4:
                return WSParsed(opcode=opcode, truncated=True)
            plen, offset = struct.unpack_from(">H", buf, offset)[0], offset + 2
        elif plen == 127:
            if len(buf) < 10:
                return WSParsed(opcode=opcode, truncated=True)
            plen, offset = struct.unpack_from(">Q", buf, offset)[0], offset + 8

        mask_key = None
        if masked:
            if len(buf) < offset + 4:
                return WSParsed(opcode=opcode, masked=masked, truncated=True)
            mask_key = buf[offset : offset + 4]
            offset  += 4

        raw_payload = buf[offset : offset + plen]
        truncated   = len(raw_payload) < plen

        if masked and mask_key and raw_payload:
            unmasked = bytearray(raw_payload)
            for i, b in enumerate(unmasked):
                unmasked[i] = b ^ mask_key[i % 4]
            payload = bytes(unmasked)
        else:
            payload = raw_payload

        # Schema inference for JSON text frames (opcode 0x1)
        payload_schema: Optional[Dict] = None
        if opcode == 0x1:
            payload_schema = _infer_schema_from_bytes(payload)

        return WSParsed(
            fin            = fin,
            opcode         = opcode,
            opcode_name    = WS_OPCODE_NAMES.get(opcode, f"0x{opcode:02x}"),
            masked         = masked,
            payload_len    = plen,
            payload        = payload[:BODY_PREVIEW_LEN],
            payload_schema = payload_schema,
            truncated      = truncated,
        )

    # -------------------------------------------------------------------------
    # MCP parser
    # -------------------------------------------------------------------------

    def _parse_mcp(self, buf: bytes, mcp_info: Optional[MCPInfo]) -> MCPParsed:
        """
        Parse a Model Context Protocol JSON-RPC 2.0 message.

        Merges fields from mcp_info (fast detector extraction) with a full
        JSON decode for params/result/error. Caps at MAX_JSON_BYTES to avoid
        holding large blobs in memory.

        If buf starts with an HTTP method, the MCP payload is inside an
        HTTP/1.1 POST body -- _find_json_body() skips the HTTP envelope.

        Schema inference:
            params_schema and result_schema are inferred from the decoded
            dicts (not raw bytes), giving the most accurate type tree.
            This is the highest-fidelity schema path in the agent because
            MCP messages are always fully decoded (not just previewed).
        """
        result = MCPParsed()

        if mcp_info:
            result.jsonrpc_version = mcp_info.jsonrpc_version
            result.method          = mcp_info.method
            result.msg_id          = mcp_info.msg_id
            result.is_request      = mcp_info.is_request
            result.is_response     = mcp_info.is_response
            result.is_notification = mcp_info.is_notification

        json_buf = _find_json_body(buf)
        if not json_buf:
            return result

        result.truncated = len(json_buf) >= MAX_JSON_BYTES
        try:
            obj = json.loads(json_buf[:MAX_JSON_BYTES])
        except (json.JSONDecodeError, ValueError):
            return result  # use whatever detector extracted

        result.jsonrpc_version = obj.get("jsonrpc",  result.jsonrpc_version)
        result.method          = obj.get("method",   result.method)
        raw_id                 = obj.get("id")
        result.msg_id          = str(raw_id) if raw_id is not None else result.msg_id
        result.is_request      = result.method is not None and "id" in obj
        result.is_notification = result.method is not None and "id" not in obj
        result.is_response     = "result" in obj or "error" in obj

        if "params" in obj:
            result.params = obj["params"]
            # Infer from decoded dict — most accurate schema path for MCP
            result.params_schema = {
                "schema":    _schema_of(obj["params"]),
                "truncated": False,
                "root_type": "object" if isinstance(obj["params"], dict) else "array",
            }

        if "result" in obj:
            result.result = obj["result"]
            result.result_schema = {
                "schema":    _schema_of(obj["result"]),
                "truncated": False,
                "root_type": "object" if isinstance(obj["result"], dict) else "array",
            }

        if "error" in obj:
            result.error    = obj["error"]
            result.is_error = True

        return result

    # -------------------------------------------------------------------------
    # TLS parser
    # -------------------------------------------------------------------------

    def _parse_tls(self, buf: bytes, tls_info: Optional[TLSInfo]) -> TLSParsed:
        """
        Parse TLS record layer metadata. Does not decrypt.

        Uses tls_info from the detector when available; falls back to
        reading the 5-byte record header directly.
        """
        if tls_info:
            return TLSParsed(
                record_type   = tls_info.record_type,
                record_name   = TLS_CONTENT_NAMES.get(tls_info.record_type,
                                    f"0x{tls_info.record_type:02x}"),
                version       = tls_info.version,
                is_handshake  = tls_info.is_handshake,
                hs_type       = tls_info.hs_type,
                hs_type_name  = tls_info.hs_type_name,
                record_length = struct.unpack_from(">H", buf, 3)[0] if len(buf) >= 5 else None,
            )

        if len(buf) < 5:
            return TLSParsed(record_type=0, record_name="unknown")

        rt   = buf[0]
        ver  = (buf[1], buf[2])
        rlen = struct.unpack_from(">H", buf, 3)[0]

        from src.processors.protocol_detector import TLS_VERSIONS, _TLS_HS_NAMES
        version_str = TLS_VERSIONS.get(ver)
        is_hs = rt == 0x16
        hs_type = None; hs_name = None
        if is_hs and len(buf) >= 6:
            hs_type = buf[5]
            hs_name = _TLS_HS_NAMES.get(hs_type, f"0x{hs_type:02x}")

        return TLSParsed(
            record_type   = rt,
            record_name   = TLS_CONTENT_NAMES.get(rt, f"0x{rt:02x}"),
            version       = version_str,
            is_handshake  = is_hs,
            hs_type       = hs_type,
            hs_type_name  = hs_name,
            record_length = rlen,
        )


# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------

def _printable_preview(data: bytes, n: int = 128) -> str:
    """First n bytes as printable ASCII; non-printable -> '.'."""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:n])


def _split_http1_messages(buf: bytes) -> List[bytes]:
    """
    Split a TCP payload into individual HTTP/1.x messages for pipelining.

    Returns a list of byte strings each containing one complete message
    (headers + body based on Content-Length). An empty list means no
    complete message found (partial capture).
    """
    messages = []
    pos = 0
    while pos < len(buf):
        end = buf.find(b"\r\n\r\n", pos)
        if end == -1:
            if pos == 0:
                messages.append(buf)
            break
        msg_end = end + 4

        # Determine body length from headers
        header_section = buf[pos:end]
        content_length = 0
        is_chunked = False
        for line in header_section.split(b"\r\n")[1:]:
            ll = line.lower()
            if ll.startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    pass
            elif ll.startswith(b"transfer-encoding:") and b"chunked" in ll:
                is_chunked = True

        if is_chunked:
            # For chunked bodies we cannot know the boundary statically;
            # include everything remaining and let the parser decode it.
            messages.append(buf[pos:])
            break
        else:
            total_end = msg_end + content_length
            messages.append(buf[pos : min(total_end, len(buf))])
            pos = total_end

        if pos < len(buf) and not _is_http_start(buf[pos : pos + 8]):
            break

    return messages


def _is_http_start(chunk: bytes) -> bool:
    """Return True if chunk looks like the start of an HTTP/1.x message."""
    for method in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ",
                   b"HEAD ", b"OPTIONS ", b"CONNECT ", b"TRACE ", b"HTTP/"):
        if chunk.startswith(method):
            return True
    return False


def _parse_headers(raw: bytes) -> Dict[str, str]:
    """
    Parse HTTP header lines into a lowercase-key dict.

    Trims values to MAX_HEADER_VALUE bytes. Set-Cookie is joined with ';'
    when duplicated. First occurrence wins for all other headers.
    """
    headers: Dict[str, str] = {}
    for line in raw.split(b"\r\n"):
        if not line or b":" not in line:
            continue
        name, _, value = line.partition(b":")
        key = name.strip().lower().decode("latin-1", errors="replace")
        val = value.strip().decode("latin-1", errors="replace")[:MAX_HEADER_VALUE]
        if key == "set-cookie" and key in headers:
            headers[key] = headers[key] + "; " + val
        else:
            headers.setdefault(key, val)
    return headers


def _decode_chunked_body(body: bytes) -> Tuple[int, bytes]:
    """
    Walk a chunked-encoded body, counting total bytes and capturing preview.

    Chunked format: <hex-size> CRLF <data> CRLF ... 0 CRLF CRLF
    Returns (total_decoded_bytes, preview_bytes).
    """
    total   = 0
    preview = bytearray()
    pos     = 0

    while pos < len(body):
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            break
        size_str = body[pos:line_end].split(b";")[0].strip()
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        pos    = line_end + 2
        chunk  = body[pos : pos + chunk_size]
        total += chunk_size
        if len(preview) < BODY_PREVIEW_LEN:
            preview.extend(chunk[:BODY_PREVIEW_LEN - len(preview)])
        pos += chunk_size + 2  # skip chunk data + CRLF

    return total, bytes(preview)


def _decode_h2_headers_frame(frame: H2Frame, payload: bytes, flags: int) -> None:
    """
    Decode an HTTP/2 HEADERS frame payload using a lightweight HPACK scanner.

    A full HPACK decoder (with static/dynamic tables) is out of scope.
    We scan for literal header fields, which handles uncompressed headers
    and first occurrences of indexed fields effectively.

    PADDED flag (0x08): byte 0 is pad length, trailing bytes are padding.
    PRIORITY flag (0x20): bytes 0-4 are stream dependency + weight.

    HPACK literal field types (RFC 7541 sections 6.2/6.3):
      0x40 (incremental indexing): name + value
      0x00 (without indexing):     name + value
      0x10 (never indexed):        name + value
    Indexed representations (0x80) require the full table -- skipped here.
    """
    if not payload:
        return

    offset  = 0
    pad_len = 0

    if flags & 0x08:  # PADDED
        if offset >= len(payload):
            return
        pad_len  = payload[offset]
        offset  += 1

    if flags & 0x20:  # PRIORITY
        offset += 5

    effective_end = len(payload) - pad_len

    while offset < effective_end:
        b = payload[offset]

        if b & 0x80:            # indexed -- skip
            offset += 1
            continue
        if (b & 0xE0) == 0x20:  # table size update -- skip
            offset += 1
            continue
        if b & 0x40:            # incremental indexing
            offset += 1
        elif b in (0x00, 0x10): # without / never indexing
            offset += 1
        else:
            offset += 1
            continue

        name,  offset = _hpack_read_string(payload, offset, effective_end)
        if name is None:
            break
        value, offset = _hpack_read_string(payload, offset, effective_end)
        if value is None:
            break

        if name.startswith(":"):
            frame.pseudo_headers[name]  = value[:MAX_HEADER_VALUE]
        else:
            frame.regular_headers[name] = value[:MAX_HEADER_VALUE]


def _hpack_read_string(buf: bytes, offset: int, end: int
                       ) -> Tuple[Optional[str], int]:
    """
    Read one HPACK length-prefixed string.

    Returns (string, new_offset) or (None, offset) on error.
    Huffman-encoded strings are returned as the placeholder "<huffman>"
    since decoding requires the full Huffman table.
    """
    if offset >= end:
        return None, offset

    hbit   = buf[offset] & 0x80
    length = buf[offset] & 0x7F
    offset += 1

    if offset + length > end:
        return None, offset

    raw    = buf[offset : offset + length]
    offset += length

    if hbit:
        return "<huffman>", offset

    try:
        return raw.decode("utf-8", errors="replace"), offset
    except Exception:
        return raw.decode("latin-1", errors="replace"), offset


def _decode_h2_settings_frame(frame: H2Frame, payload: bytes) -> None:
    """
    Decode HTTP/2 SETTINGS payload: sequence of 6-byte (uint16 id, uint32 value) entries.
    """
    offset = 0
    while offset + 6 <= len(payload):
        pid  = struct.unpack_from(">H", payload, offset)[0]
        pval = struct.unpack_from(">I", payload, offset + 2)[0]
        frame.settings[H2_SETTINGS_NAMES.get(pid, f"0x{pid:04x}")] = pval
        offset += 6


def _find_json_body(buf: bytes) -> Optional[bytes]:
    """
    Locate JSON body in buf.

    Handles:
      1. Raw JSON starting with '{' or '[' (MCP over WebSocket / stdio)
      2. HTTP/1.1 envelope: body follows the CRLFCRLF separator
    """
    if buf and buf[0:1] in (b"{", b"["):
        return buf
    sep = buf.find(b"\r\n\r\n")
    if sep != -1:
        body = buf[sep + 4:].lstrip()
        if body and body[0:1] in (b"{", b"["):
            return body
    return None


def _dummy_meta() -> EventMeta:
    """
    Minimal EventMeta for internal use when parsing WS upgrade handshakes
    via the HTTP/1.x parser path (no real EventMeta available).
    """
    return EventMeta(
        timestamp_ns=0, conn_id=0, pid=0, tid=0, uid=0,
        comm="", src_ip="0.0.0.0", dst_ip="0.0.0.0",
        src_port=0, dst_port=0,
        direction=Direction.EGRESS, protocol=Protocol.WEBSOCKET,
        ip_version=4, payload_len=0, original_len=0, truncated=False,
    )
