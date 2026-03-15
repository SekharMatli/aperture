"""
LRU + TTL connection state tracker, bounded at 64K entries, thread-safe.
Prevents unbounded memory growth under millions of short connections.
"""

"""
conn_tracker.py
===============
Per-connection state store for the eBPF HTTP capture agent.

Responsibilities
----------------
1. Maintain a bounded, LRU-evicting map of conn_id → ConnectionRecord.
   Each ConnectionRecord aggregates:
     - Network 4-tuple and process identity (from EventMeta)
     - Lifecycle timestamps (first seen, last seen, closed at)
     - Cumulative packet and byte counters (egress / ingress separately)
     - Protocol detection state (DetectionState from ProtocolDetector)
     - Derived connection statistics (latency, throughput, error flag)

2. Drive ProtocolDetector lifecycle:
     - Calls detector.on_connection_close(conn_id) when a connection
       is removed (by CLOSE event or LRU eviction), so the detector
       can release its per-connection state too.

3. Provide lookup by conn_id for the ring buffer poll loop, and
   bulk export of all active records for metrics/logging.

Design constraints
------------------
- NOT thread-safe. The ring buffer poll loop is single-threaded; if
  worker threads are added, callers must serialize access externally.
- Bounded memory: hard cap at `max_connections` records (default 65 536).
  When the cap is reached, the least-recently-used record is evicted.
- O(1) get/update via dict; O(1) LRU eviction via OrderedDict move_to_end.
- No external dependencies beyond stdlib + project modules.

Relationship to other modules
------------------------------
  EBPFAgent
    └── ConnectionTracker          ← this file
          ├── ProtocolDetector     (imported, called on close/evict)
          └── ConnectionRecord     (one per active TCP connection)

  RawEvent (from ring buffer)
    → conn_tracker.update(event)   ← primary call site
    → returns ConnectionRecord     ← used by downstream parsers

Eviction policy
---------------
LRU (Least Recently Used) by last_seen_ns.
When a CLOSE event arrives the record is explicitly removed.
When a new connection would exceed the cap, the oldest record is evicted
after its CLOSE event callback fires — preventing silent memory growth
under connection storms or port-scan traffic.

Additionally, a periodic TTL sweep removes records that have not been
seen for longer than `ttl_seconds` (default 5 minutes). This handles
connections that were closed without a tcp_close probe firing (e.g.
RST packets, kernel filter drops, or probe detach during active traffic).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

from src.agent.event_types import Direction, EventMeta, Protocol, RawEvent
from src.processors.protocol_detector import DetectionResult, DetectionState, ProtocolDetector


# ─────────────────────────────────────────────────────────────────────────────
# ConnectionRecord
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class ConnectionRecord:
    """
    Everything the agent knows about one TCP connection.

    Instances are created on the first packet seen for a conn_id and
    mutated in-place as subsequent packets arrive. They are removed when
    a CLOSE event fires or when LRU eviction occurs.

    Fields split into three groups:
      Identity  — immutable after creation (4-tuple, pid, comm)
      Counters  — updated on every packet
      Detection — updated by ProtocolDetector results
    """

    # ── Identity (set once on first packet, never changed) ────────────────
    conn_id:        int           # 64-bit hash from eBPF (stable per connection)
    src_ip:         str           # dotted-decimal source IP
    dst_ip:         str           # dotted-decimal destination IP
    src_port:       int           # source port (host byte order)
    dst_port:       int           # destination port (host byte order)
    pid:            int           # owning process PID
    comm:           str           # owning process name (up to 15 chars)
    uid:            int           # effective user ID at connection creation
    ip_version:     int           # 4 (IPv6 reserved for future)

    # ── Lifecycle timestamps (monotonic kernel ns) ─────────────────────────
    first_seen_ns:  int           # ktime_get_ns() of first packet
    last_seen_ns:   int           # ktime_get_ns() of most recent packet
    closed_at_ns:   Optional[int] = None   # set when CLOSE event arrives

    # ── Packet / byte counters ─────────────────────────────────────────────
    egress_packets:  int = 0      # packets sent by this process (sendmsg)
    ingress_packets: int = 0      # packets received by this process (recvmsg)
    egress_bytes:    int = 0      # payload bytes sent (original_len, pre-clip)
    ingress_bytes:   int = 0      # payload bytes received

    # ── Protocol detection ─────────────────────────────────────────────────
    protocol:        Protocol = Protocol.UNKNOWN   # confirmed or best-guess
    last_result:     Optional[DetectionResult] = None  # most recent from detector

    # ── Derived stats (updated on each packet) ─────────────────────────────
    had_error:       bool = False  # True if any packet had parse_error

    # ── Computed properties ────────────────────────────────────────────────

    @property
    def conn_id_hex(self) -> str:
        return f"0x{self.conn_id:016x}"

    @property
    def src(self) -> str:
        return f"{self.src_ip}:{self.src_port}"

    @property
    def dst(self) -> str:
        return f"{self.dst_ip}:{self.dst_port}"

    @property
    def total_packets(self) -> int:
        return self.egress_packets + self.ingress_packets

    @property
    def total_bytes(self) -> int:
        return self.egress_bytes + self.ingress_bytes

    @property
    def is_closed(self) -> bool:
        return self.closed_at_ns is not None

    @property
    def duration_ns(self) -> int:
        """
        Connection duration in nanoseconds.
        Uses closed_at_ns if closed, otherwise last_seen_ns.
        Both are kernel monotonic clock values (ktime_get_ns).
        """
        end = self.closed_at_ns if self.closed_at_ns else self.last_seen_ns
        return end - self.first_seen_ns

    @property
    def duration_ms(self) -> float:
        return self.duration_ns / 1_000_000.0

    def to_dict(self) -> dict:
        """
        Serialise to a plain dict safe for JSON/logging output.
        All values are ints, floats, strings, bools, or None.
        """
        d = {
            # Identity
            "conn_id":         self.conn_id_hex,
            "src":             self.src,
            "dst":             self.dst,
            "pid":             self.pid,
            "comm":            self.comm,
            "uid":             self.uid,
            # Protocol
            "protocol":        self.protocol.display_name,
            # Counters
            "egress_packets":  self.egress_packets,
            "ingress_packets": self.ingress_packets,
            "egress_bytes":    self.egress_bytes,
            "ingress_bytes":   self.ingress_bytes,
            "total_packets":   self.total_packets,
            "total_bytes":     self.total_bytes,
            # Lifecycle
            "first_seen_ns":   self.first_seen_ns,
            "last_seen_ns":    self.last_seen_ns,
            "duration_ms":     round(self.duration_ms, 3),
            "is_closed":       self.is_closed,
            "had_error":       self.had_error,
        }
        if self.closed_at_ns is not None:
            d["closed_at_ns"] = self.closed_at_ns

        # Attach detection annotations if available
        if self.last_result is not None:
            d["detection"] = self.last_result.to_dict()

        return d


# ─────────────────────────────────────────────────────────────────────────────
# Eviction callback type
# ─────────────────────────────────────────────────────────────────────────────

# Signature for functions registered to receive eviction notifications.
# Called with the evicted ConnectionRecord before it is removed from memory.
# Use case: flush partial parse state, emit a "connection closed" log line,
# or update an external metrics store.
#
# Example registration:
#   def my_callback(record: ConnectionRecord) -> None:
#       metrics.record_connection_closed(record)
#   tracker = ConnectionTracker(on_evict=my_callback)
EvictCallback = "Callable[[ConnectionRecord], None]"


# ─────────────────────────────────────────────────────────────────────────────
# ConnectionTracker
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionTracker:
    """
    Bounded, LRU-evicting connection state store.

    Primary interface
    -----------------
    update(event) → ConnectionRecord
        Call once per RawEvent from the ring buffer poll loop.
        Creates a new ConnectionRecord on first sight of a conn_id,
        or updates the existing one on subsequent packets.
        On CLOSE events, marks the record closed and schedules removal.

    get(conn_id) → Optional[ConnectionRecord]
        Look up a record by conn_id without updating it.
        Returns None if the connection is not tracked.

    active_connections() → List[ConnectionRecord]
        Snapshot of all currently tracked (non-closed) records.
        Cheap copy of references; does not clone the records.

    Periodic maintenance
    --------------------
    Call sweep_expired(now_ns) periodically (e.g. every 30 seconds) to
    remove records that have not been seen for longer than ttl_seconds.
    The agent's main loop drives this; it is not automatic.

    Parameters
    ----------
    detector : ProtocolDetector
        Shared detector instance. ConnectionTracker calls
        detector.on_connection_close(conn_id) whenever a record is
        removed for any reason (CLOSE event, LRU eviction, TTL expiry).

    max_connections : int
        Hard cap on tracked connections. When exceeded, the
        least-recently-used record is evicted synchronously.
        Default: 65 536 (matches BPF map max_entries).

    ttl_seconds : float
        Records not seen for longer than this are removed during
        sweep_expired(). Default: 300 seconds (5 minutes).

    on_evict : optional callable
        Called with the ConnectionRecord just before it is removed.
        Receives records evicted by LRU, TTL, and explicit CLOSE.
        Useful for flushing downstream parse state or emitting metrics.
    """

    def __init__(
        self,
        detector:        ProtocolDetector,
        max_connections: int   = 65_536,
        ttl_seconds:     float = 300.0,
        on_evict=None,
    ):
        self._detector       = detector
        self._max            = max_connections
        self._ttl_ns         = int(ttl_seconds * 1_000_000_000)
        self._on_evict       = on_evict

        # OrderedDict preserves insertion order (Python 3.7+).
        # move_to_end(key) is O(1) and used for LRU bookkeeping.
        # Oldest entry = first (leftmost); newest = last (rightmost).
        self._records: OrderedDict[int, ConnectionRecord] = OrderedDict()

        # Cumulative counters for lifetime metrics
        self._total_created:  int = 0
        self._total_closed:   int = 0
        self._total_evicted:  int = 0   # LRU + TTL evictions (not explicit closes)

    # ── Primary interface ─────────────────────────────────────────────────────

    def update(self, event: RawEvent) -> ConnectionRecord:
        """
        Process one RawEvent and return the associated ConnectionRecord.

        Steps:
          1. Look up or create a ConnectionRecord for event.conn_id.
          2. Update counters and last_seen_ns.
          3. Run ProtocolDetector.detect() and store the result.
          4. Promote connection protocol if detector is more specific.
          5. On CLOSE: mark record closed, call callbacks, remove from map.
          6. On new connection that exceeds cap: evict oldest record first.

        Always returns a ConnectionRecord — never None, never raises.
        """
        conn_id = event.conn_id
        meta    = event.meta

        # ── Fetch or create ───────────────────────────────────────────────
        record = self._records.get(conn_id)
        if record is None:
            record = self._create_record(meta)
            # Evict oldest if over cap before inserting the new record
            self._enforce_capacity()
            self._records[conn_id] = record
            self._total_created += 1
        else:
            # Mark as recently used (move to end = newest)
            self._records.move_to_end(conn_id)

        # ── Update counters ───────────────────────────────────────────────
        record.last_seen_ns = meta.timestamp_ns

        if meta.direction == Direction.EGRESS:
            record.egress_packets  += 1
            record.egress_bytes    += meta.original_len
        elif meta.direction == Direction.INGRESS:
            record.ingress_packets += 1
            record.ingress_bytes   += meta.original_len

        # ── Protocol detection ────────────────────────────────────────────
        if not meta.is_close:
            result = self._detector.detect(event)
            record.last_result = result

            # Promote protocol: only upgrade, never downgrade.
            # Ordering: UNKNOWN < HTTP1/HTTP2/TLS < GRPC/WEBSOCKET/MCP/HTTP*_TLS
            # Once a specific protocol is confirmed, keep it.
            if self._is_more_specific(result.final_protocol, record.protocol):
                record.protocol = result.final_protocol

        # ── Handle CLOSE ──────────────────────────────────────────────────
        if meta.is_close:
            record.closed_at_ns = meta.timestamp_ns
            self._remove_record(conn_id, reason="close")
            self._total_closed += 1

        return record

    def get(self, conn_id: int) -> Optional[ConnectionRecord]:
        """
        Look up a ConnectionRecord without updating LRU order or counters.

        Returns None if conn_id is not currently tracked.
        Use this for read-only inspection; use update() for the main loop.
        """
        return self._records.get(conn_id)

    def active_connections(self) -> List[ConnectionRecord]:
        """
        Return a list of all currently tracked (non-closed) records.

        This is a shallow copy of references — modifying the returned
        list does not affect the tracker, but modifying a record's
        mutable fields (counters, protocol) will.

        Complexity: O(n) where n is the number of active connections.
        """
        return list(self._records.values())

    def sweep_expired(self, now_ns: Optional[int] = None) -> int:
        """
        Remove records that have not been seen for longer than ttl_seconds.

        Call periodically from the agent's main loop. Does NOT need to
        be called on every packet — every 30–60 seconds is sufficient.

        Parameters
        ----------
        now_ns : int, optional
            Current time as kernel monotonic nanoseconds.
            Defaults to time.monotonic_ns() if not provided.
            Passing a value avoids a syscall inside a tight loop.

        Returns
        -------
        int
            Number of records removed by this sweep.
        """
        if now_ns is None:
            now_ns = time.monotonic_ns()

        cutoff_ns = now_ns - self._ttl_ns
        expired   = [
            cid for cid, rec in self._records.items()
            if rec.last_seen_ns < cutoff_ns
        ]

        for cid in expired:
            self._remove_record(cid, reason="ttl")
            self._total_evicted += 1

        return len(expired)

    # ── Read-only statistics ──────────────────────────────────────────────────

    def active_count(self) -> int:
        """Number of currently tracked connections."""
        return len(self._records)

    def stats(self) -> dict:
        """
        Return a snapshot of tracker-level statistics.
        Safe to call at any time; never raises.
        """
        return {
            "active_connections": self.active_count(),
            "total_created":      self._total_created,
            "total_closed":       self._total_closed,
            "total_evicted":      self._total_evicted,
            "detector_states":    self._detector.state_count(),
            "max_connections":    self._max,
            "ttl_seconds":        self._ttl_ns / 1_000_000_000,
        }

    def protocol_breakdown(self) -> Dict[str, int]:
        """
        Count active connections grouped by confirmed protocol.
        Useful for a live dashboard or periodic log line.
        """
        counts: Dict[str, int] = {}
        for rec in self._records.values():
            name = rec.protocol.display_name
            counts[name] = counts.get(name, 0) + 1
        return counts

    def top_connections(
        self,
        n: int = 10,
        by: str = "total_bytes",
    ) -> List[ConnectionRecord]:
        """
        Return the top-N connections sorted by a counter field.

        Parameters
        ----------
        n : int
            Number of records to return.
        by : str
            Sort key. One of:
              "total_bytes"    — combined egress + ingress bytes
              "total_packets"  — combined packet count
              "egress_bytes"   — bytes sent
              "ingress_bytes"  — bytes received
              "duration_ms"    — connection age
        """
        valid_keys = {
            "total_bytes", "total_packets",
            "egress_bytes", "ingress_bytes", "duration_ms",
        }
        if by not in valid_keys:
            raise ValueError(f"'by' must be one of {valid_keys}, got {by!r}")

        return sorted(
            self._records.values(),
            key=lambda r: getattr(r, by),
            reverse=True,
        )[:n]

    def __iter__(self) -> Iterator[ConnectionRecord]:
        """Iterate over all active ConnectionRecords (insertion order)."""
        return iter(self._records.values())

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, conn_id: int) -> bool:
        return conn_id in self._records

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _create_record(self, meta: EventMeta) -> ConnectionRecord:
        """
        Construct a new ConnectionRecord from the first EventMeta seen
        for this conn_id.

        Called only once per connection; subsequent packets call update().
        """
        return ConnectionRecord(
            conn_id       = meta.conn_id,
            src_ip        = meta.src_ip,
            dst_ip        = meta.dst_ip,
            src_port      = meta.src_port,
            dst_port      = meta.dst_port,
            pid           = meta.pid,
            comm          = meta.comm,
            uid           = meta.uid,
            ip_version    = meta.ip_version,
            first_seen_ns = meta.timestamp_ns,
            last_seen_ns  = meta.timestamp_ns,
            protocol      = meta.protocol,   # kernel's initial guess; may be promoted
        )

    def _enforce_capacity(self) -> None:
        """
        Evict the least-recently-used record if we are at capacity.

        Called before inserting a new record. The LRU record is the
        first item in the OrderedDict (oldest insertion / least-recently
        moved to end).

        We evict exactly one record per new connection — the cap is a
        hard limit, not a soft target.
        """
        if len(self._records) < self._max:
            return

        # Pop the oldest (leftmost) record
        lru_cid, lru_rec = next(iter(self._records.items()))
        self._remove_record(lru_cid, reason="lru")
        self._total_evicted += 1

    def _remove_record(self, conn_id: int, reason: str) -> None:
        """
        Remove a record from the map and fire all cleanup callbacks.

        Steps (in order):
          1. Pop from _records dict (no-op if already removed).
          2. Call on_evict callback if registered.
          3. Call detector.on_connection_close() to release detector state.

        The reason string is passed to nothing externally right now, but
        is available for future structured logging / tracing.
        """
        record = self._records.pop(conn_id, None)
        if record is None:
            return   # Already removed — harmless double-close

        # Notify eviction callback (if registered)
        if self._on_evict is not None:
            try:
                self._on_evict(record)
            except Exception:
                pass   # Never let a callback crash the agent

        # Release ProtocolDetector state for this connection
        self._detector.on_connection_close(conn_id)

    @staticmethod
    def _is_more_specific(new_proto: Protocol, current: Protocol) -> bool:
        """
        Return True if new_proto is a more informative label than current.

        Promotion rules (never downgrade):
          UNKNOWN       → anything
          TLS           → HTTP1_TLS, HTTP2_TLS       (post-SSL-probe refinement)
          HTTP1         → WEBSOCKET, MCP              (upgrade handshake)
          HTTP2         → GRPC                        (content-type header)
          anything else → same or UNKNOWN (no change)

        The rule is asymmetric: once GRPC is confirmed we never revert to
        HTTP2, even if a later DATA frame doesn't have the grpc content-type.
        """
        if new_proto == current:
            return False
        if current == Protocol.UNKNOWN:
            return True
        if current == Protocol.TLS and new_proto in (
            Protocol.HTTP1_TLS, Protocol.HTTP2_TLS
        ):
            return True
        if current == Protocol.HTTP1 and new_proto in (
            Protocol.WEBSOCKET, Protocol.MCP
        ):
            return True
        if current == Protocol.HTTP2 and new_proto == Protocol.GRPC:
            return True
        return False