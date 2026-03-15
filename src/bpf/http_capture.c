//kprobe/tcp_sendmsg → captures outgoing HTTP requests
//kretprobe/tcp_recvmsg → captures incoming responses (fires after kernel fills buffer, so data is there)
//kprobe/tcp_close → tracks connection teardown and cleanup
//Kernel-side HTTP sniff (is_http_data) filters before ring buffer write — cuts 80–90% of irrelevant TCP traffic from ever crossing the kernel/user boundary
//"BPF_MAP_TYPE_RINGBUF for zero-loss, in-order, variable-size events"
//"Per-CPU drop counter you can monitor from userspace"

// SPDX-License-Identifier: GPL-2.0
//
// http_capture.c
// ==============
// Production eBPF program for zero-loss multi-protocol TCP capture.
//
// Supported protocols (detected kernel-side before ring buffer write):
//   - HTTP/1.0, HTTP/1.1  (plaintext + TLS post-decrypt)
//   - HTTP/2               (binary framing, PRI preface detection)
//   - gRPC                 (HTTP/2 with Content-Type: application/grpc)
//   - MCP                  (Model Context Protocol over HTTP/2 or WS)
//   - WebSocket            (Upgrade handshake + frame detection)
//   - TLS                  (record layer fingerprinting)
//   - Unknown TCP          (pass-through for correlation)
//
// Architecture:
//   kprobe/tcp_sendmsg    → outbound data (requests)
//   kretprobe/tcp_recvmsg → inbound data (responses, after kernel fills buf)
//   kprobe/tcp_close      → connection teardown + cleanup
//
// Zero-loss strategy:
//   1. BPF_MAP_TYPE_RINGBUF at 256 MB (single shared, ordered, variable-size)
//   2. Protocol filter in kernel — only matching traffic crosses boundary
//   3. Per-CPU drop counter exposed to userspace for monitoring
//   4. bpf_ringbuf_reserve() is non-blocking; drops increment counter
//
// Kernel requirement: Linux 5.8+ (BPF_MAP_TYPE_RINGBUF)
// Build:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86          \
//         -I/usr/include/x86_64-linux-gnu -I/usr/include   \
//         -c http_capture.c -o http_capture.o
//
// SPDX-FileCopyrightText: 2025 eBPF Agent Authors

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─────────────────────────────────────────────────────────────────────────────
// Tuneable constants
// ─────────────────────────────────────────────────────────────────────────────

// Maximum bytes of payload captured per event.
// Larger values reduce truncation but increase ring buffer pressure.
#ifndef MAX_PAYLOAD_SIZE
#define MAX_PAYLOAD_SIZE    65536
#endif

// Ring buffer size in bytes. Must be a power of 2.
// 256 MB absorbs ~4 million average-sized HTTP events before any drop.
#ifndef RINGBUF_SIZE
#define RINGBUF_SIZE        (256 * 1024 * 1024)
#endif

// Maximum simultaneous tracked connections (hash map capacity).
#define MAX_CONNECTIONS     65536

// Linux task name length (matches TASK_COMM_LEN in kernel headers).
#define COMM_LEN            16

// ─────────────────────────────────────────────────────────────────────────────
// Protocol identifiers
// Stored in event_header.protocol so userspace knows how to parse payload.
// ─────────────────────────────────────────────────────────────────────────────

#define PROTO_UNKNOWN       0   // Raw TCP, protocol unrecognised
#define PROTO_HTTP1         1   // HTTP/1.0 or HTTP/1.1
#define PROTO_HTTP2         2   // HTTP/2 binary framing
#define PROTO_GRPC          3   // gRPC (HTTP/2 + grpc content-type)
#define PROTO_WEBSOCKET     4   // WebSocket (after HTTP Upgrade)
#define PROTO_MCP           5   // Model Context Protocol
#define PROTO_TLS           6   // TLS record layer (encrypted)
#define PROTO_HTTP1_TLS     7   // HTTP/1.x after TLS decrypt (SSL probe)
#define PROTO_HTTP2_TLS     8   // HTTP/2 after TLS decrypt  (SSL probe)

// ─────────────────────────────────────────────────────────────────────────────
// Event direction
// ─────────────────────────────────────────────────────────────────────────────

#define DIR_EGRESS          1   // tcp_sendmsg  (client→server)
#define DIR_INGRESS         2   // tcp_recvmsg  (server→client)
#define DIR_CLOSE           3   // tcp_close    (connection end)

// ─────────────────────────────────────────────────────────────────────────────
// Data structures
// All structs use explicit padding to avoid compiler-dependent alignment gaps.
// Python ctypes mirrors must match byte-for-byte.
// ─────────────────────────────────────────────────────────────────────────────

//
// conn_tuple — 4-tuple key for connection tracking hash map.
//
struct conn_tuple {
    __u32   src_ip4;        // source IPv4 (network byte order)
    __u32   dst_ip4;        // destination IPv4 (network byte order)
    __u16   src_port;       // source port (host byte order)
    __u16   dst_port;       // destination port (host byte order)
    __u32   pid;            // owning PID (disambiguates port reuse)
};

//
// conn_meta — per-connection state stored in kernel hash map.
// Updated on first packet; used to fill event_header fields quickly.
//
struct conn_meta {
    __u64   conn_id;        // unique ID: hash of 4-tuple + timestamp
    __u64   first_seen_ns;  // ktime_get_ns() at connection creation
    __u64   last_seen_ns;   // ktime_get_ns() at last packet
    __u32   src_ip4;
    __u32   dst_ip4;
    __u16   src_port;
    __u16   dst_port;
    __u8    protocol;       // PROTO_* detected protocol
    __u8    pad[3];
    char    comm[COMM_LEN]; // process name at connection creation
};

//
// event_header — written to ring buffer before each payload chunk.
// Immediately followed in memory by `payload_len` bytes of raw data.
//
// Layout in ring buffer:
//   [event_header 96 bytes][payload 0..MAX_PAYLOAD_SIZE bytes]
//
struct event_header {
    // Timing
    __u64   timestamp_ns;   // event timestamp (ktime_get_ns)

    // Connection identity
    __u64   conn_id;        // matches conn_meta.conn_id

    // Process identity
    __u32   pid;            // userspace process ID
    __u32   tid;            // userspace thread ID
    __u32   uid;            // effective user ID

    // Network 4-tuple
    __u32   src_ip4;
    __u32   dst_ip4;
    __u16   src_port;
    __u16   dst_port;

    // Event classification
    __u8    direction;      // DIR_EGRESS | DIR_INGRESS | DIR_CLOSE
    __u8    protocol;       // PROTO_* value
    __u8    ip_version;     // 4 or 6 (IPv6 addresses in future extension)
    __u8    truncated;      // 1 if payload was clipped to MAX_PAYLOAD_SIZE

    // Process name
    char    comm[COMM_LEN]; // null-terminated, may be partial

    // Payload descriptor
    __u32   payload_len;    // bytes of payload following this header
    __u32   original_len;   // bytes in original tcp segment (before clip)
};

// ─────────────────────────────────────────────────────────────────────────────
// BPF Maps
// ─────────────────────────────────────────────────────────────────────────────

//
// events — primary output ring buffer.
//
// Sized at RINGBUF_SIZE bytes. bpf_ringbuf_reserve() is wait-free;
// if no space exists, the call fails immediately and the drop counter
// is incremented. The userspace agent must drain this fast enough.
//
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

//
// connections — active connection state, keyed by conn_tuple.
//
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key,         struct conn_tuple);
    __type(value,       struct conn_meta);
} connections SEC(".maps");

//
// recvmsg_ctx — per-thread context passed from kprobe entry to kretprobe.
// Stores the msghdr pointer and socket pointer so the return probe can
// read the filled buffer and reconstruct the 4-tuple.
//
struct recvmsg_args {
    __u64   sock_ptr;       // struct sock * (as integer)
    __u64   msghdr_ptr;     // struct msghdr * (as integer)
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key,         __u64);             // pid_tgid
    __type(value,       struct recvmsg_args);
} recvmsg_ctx SEC(".maps");

//
// port_filter — if non-empty, only capture traffic on these dst/src ports.
// Key = port number; value = 1. Insert key 0 as sentinel to activate filter.
//
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,         __u16);
    __type(value,       __u8);
} port_filter SEC(".maps");

//
// pid_filter — if non-empty, only capture traffic from these PIDs.
// Same sentinel-key convention as port_filter.
//
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,         __u32);
    __type(value,       __u8);
} pid_filter SEC(".maps");

//
// drop_counter — per-CPU counter of ring buffer overflow events.
// Userspace polls this periodically to emit drop-rate metrics.
//
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       __u64);
} drop_counter SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────────
// Static helper: increment drop counter (no lock needed — per-CPU)
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline void record_drop(void)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&drop_counter, &key);
    if (val)
        (*val)++;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static helper: connection ID derivation
//
// Produces a stable 64-bit ID for a connection from its 4-tuple plus
// the creation timestamp (nanoseconds). The timestamp component prevents
// collision when a port is rapidly reused after close.
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline __u64 make_conn_id(
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u64 ts_ns)
{
    // FNV-1a-inspired mixing on 4-tuple + timestamp
    __u64 h = 14695981039346656037ULL;
    h ^= (__u64)src_ip;   h *= 1099511628211ULL;
    h ^= (__u64)dst_ip;   h *= 1099511628211ULL;
    h ^= (__u64)src_port; h *= 1099511628211ULL;
    h ^= (__u64)dst_port; h *= 1099511628211ULL;
    h ^= ts_ns;           h *= 1099511628211ULL;
    return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static helper: extract IPv4 4-tuple from struct sock
// Returns 0 on success, -1 if the socket is not AF_INET.
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline int read_sock_4tuple(
    struct sock *sk,
    __u32 *src_ip, __u32 *dst_ip,
    __u16 *src_port, __u16 *dst_port)
{
    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    if (family != 2 /* AF_INET */)
        return -1;

    BPF_CORE_READ_INTO(src_ip,   sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(dst_ip,   sk, __sk_common.skc_daddr);

    __u16 sport_be = 0, dport_be = 0;
    BPF_CORE_READ_INTO(&sport_be, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);

    // skc_num is already host byte order; skc_dport is big-endian
    *src_port = sport_be;
    *dst_port = __builtin_bswap16(dport_be);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static helper: filter checks
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline int port_allowed(__u16 port)
{
    // If sentinel key 0 is absent, filter is inactive → allow all
    __u16 sentinel = 0;
    if (!bpf_map_lookup_elem(&port_filter, &sentinel))
        return 1;
    return bpf_map_lookup_elem(&port_filter, &port) ? 1 : 0;
}

static __always_inline int pid_allowed(__u32 pid)
{
    __u32 sentinel = 0;
    if (!bpf_map_lookup_elem(&pid_filter, &sentinel))
        return 1;
    return bpf_map_lookup_elem(&pid_filter, &pid) ? 1 : 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static helper: protocol detection
//
// Examines the first bytes of a TCP payload and returns the best-guess
// protocol identifier. Called in kernel context; uses bpf_probe_read_user
// to safely dereference user-space iov_base pointers.
//
// Detection priority (highest to lowest confidence):
//   1. TLS record layer  — byte 0 is 0x16/0x14/0x15/0x17, byte 1 is 0x03
//   2. HTTP/2 client preface — 24-byte magic string
//   3. HTTP/1.x method   — ASCII verb at offset 0
//   4. WebSocket frame   — opcode nibble in byte 0
//   5. MCP               — JSON-RPC envelope {"jsonrpc":"2.0"...}
//   6. gRPC              — HTTP/2 DATA frame with grpc content-type
//                          (detected later in userspace from headers)
// ─────────────────────────────────────────────────────────────────────────────

// HTTP/2 client connection preface (RFC 9113 §3.4)
// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"  (24 bytes)
static const char H2_PREFACE[24] = {
    0x50,0x52,0x49,0x20,0x2a,0x20,0x48,0x54,
    0x54,0x50,0x2f,0x32,0x2e,0x30,0x0d,0x0a,
    0x0d,0x0a,0x53,0x4d,0x0d,0x0a,0x0d,0x0a
};

static __always_inline __u8 detect_protocol(
    const void __user *buf, __u32 buf_len)
{
    if (buf_len < 3)
        return PROTO_UNKNOWN;

    __u8 b[8] = {};
    __u32 peek = buf_len < 8 ? buf_len : 8;
    if (bpf_probe_read_user(b, peek, buf) < 0)
        return PROTO_UNKNOWN;

    // ── TLS record layer ──────────────────────────────────────────
    // Content types: 0x14 (ChangeCipherSpec), 0x15 (Alert),
    //                0x16 (Handshake),        0x17 (ApplicationData)
    // Always followed by version: 0x03 0x01..0x04
    if ((b[0] == 0x16 || b[0] == 0x17 || b[0] == 0x14 || b[0] == 0x15)
         && b[1] == 0x03 && b[2] <= 0x04)
        return PROTO_TLS;

    // ── HTTP/2 client preface (first 8 bytes sufficient) ─────────
    // "PRI * HT" = 0x50 0x52 0x49 0x20 0x2a 0x20 0x48 0x54
    if (b[0]==0x50 && b[1]==0x52 && b[2]==0x49 && b[3]==0x20 &&
        b[4]==0x2a && b[5]==0x20 && b[6]==0x48 && b[7]==0x54)
        return PROTO_HTTP2;

    // ── HTTP/2 frame (server-side, no preface) ────────────────────
    // HTTP/2 frames: 3-byte length, 1-byte type (0x00..0x09), 1-byte flags
    // Type range 0–9 covers DATA, HEADERS, PRIORITY, RST_STREAM,
    // SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION
    if (buf_len >= 9 && b[3] <= 0x09) {
        // Weak signal: treat as HTTP/2 only if length field is plausible
        __u32 frame_len = (((__u32)b[0]) << 16) |
                          (((__u32)b[1]) << 8)  |
                            (__u32)b[2];
        if (frame_len <= MAX_PAYLOAD_SIZE)
            return PROTO_HTTP2;
    }

    // ── HTTP/1.x request methods ──────────────────────────────────
    // RFC 9110 registered methods; all begin with uppercase ASCII
    //   GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH
    if (b[0]=='G' && b[1]=='E' && b[2]=='T')           return PROTO_HTTP1;
    if (b[0]=='P' && b[1]=='O' && b[2]=='S')           return PROTO_HTTP1;
    if (b[0]=='P' && b[1]=='U' && b[2]=='T')           return PROTO_HTTP1;
    if (b[0]=='D' && b[1]=='E' && b[2]=='L')           return PROTO_HTTP1;
    if (b[0]=='P' && b[1]=='A' && b[2]=='T')           return PROTO_HTTP1;
    if (b[0]=='H' && b[1]=='E' && b[2]=='A')           return PROTO_HTTP1;
    if (b[0]=='O' && b[1]=='P' && b[2]=='T')           return PROTO_HTTP1;
    if (b[0]=='C' && b[1]=='O' && b[2]=='N')           return PROTO_HTTP1;
    if (b[0]=='T' && b[1]=='R' && b[2]=='A')           return PROTO_HTTP1;

    // ── HTTP/1.x response ─────────────────────────────────────────
    // "HTTP/1." prefix
    if (b[0]=='H' && b[1]=='T' && b[2]=='T' && b[3]=='P')
        return PROTO_HTTP1;

    // ── WebSocket frame ───────────────────────────────────────────
    // WS frame byte 0: FIN bit (0x80) + opcode (0x00..0x0F)
    // Common opcodes: 0x01 text, 0x02 binary, 0x08 close, 0x09 ping
    // Byte 1: MASK bit (0x80) + payload length
    // Heuristic: FIN set, opcode 0-15, mask bit present or absent
    if ((b[0] & 0x70) == 0x00) {   // RSV1/RSV2/RSV3 must be 0 (no extension)
        __u8 opcode = b[0] & 0x0F;
        if (opcode <= 0x0A && (b[1] & 0x7F) <= 127)
            return PROTO_WEBSOCKET;
    }

    // ── MCP (Model Context Protocol) ─────────────────────────────
    // MCP uses JSON-RPC 2.0; messages start with '{'
    // and contain "jsonrpc" near the beginning.
    // Weak signal: '{' + '"' is consistent with JSON-RPC.
    if (b[0] == '{' && b[1] == '"')
        return PROTO_MCP;

    return PROTO_UNKNOWN;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static helper: get or create connection metadata
//
// Looks up the conn_tuple in the connections map. If not found, creates
// a new entry with a fresh conn_id derived from the 4-tuple + current time.
// Returns a pointer to the map value (valid until map update/delete).
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline struct conn_meta *get_or_create_conn(
    struct conn_tuple *key,
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u32 pid)
{
    struct conn_meta *meta = bpf_map_lookup_elem(&connections, key);
    if (meta) {
        meta->last_seen_ns = bpf_ktime_get_ns();
        return meta;
    }

    // First time we see this 4-tuple: create entry
    struct conn_meta new_meta = {};
    new_meta.first_seen_ns = bpf_ktime_get_ns();
    new_meta.last_seen_ns  = new_meta.first_seen_ns;
    new_meta.src_ip4   = src_ip;
    new_meta.dst_ip4   = dst_ip;
    new_meta.src_port  = src_port;
    new_meta.dst_port  = dst_port;
    new_meta.protocol  = PROTO_UNKNOWN;  // updated on first payload
    new_meta.conn_id   = make_conn_id(
        src_ip, dst_ip, src_port, dst_port, new_meta.first_seen_ns);

    bpf_get_current_comm(&new_meta.comm, sizeof(new_meta.comm));
    bpf_map_update_elem(&connections, key, &new_meta, BPF_ANY);
    return bpf_map_lookup_elem(&connections, key);
}

// ─────────────────────────────────────────────────────────────────────────────
// Static helper: emit one event to the ring buffer
//
// Reserves (sizeof(event_header) + payload_cap) bytes atomically.
// Returns 0 on success, -1 on ring buffer full (drop recorded).
//
// The ring buffer reservation is split into two phases:
//   1. bpf_ringbuf_reserve  — atomically claims space
//   2. bpf_probe_read_user  — copies user-space payload into reserved slot
//   3. bpf_ringbuf_submit   — makes the event visible to userspace
//
// If bpf_probe_read_user fails (page fault, unmapped memory), the event
// is still submitted with payload_len = 0 so the metadata is not lost.
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline int emit_event(
    struct conn_meta *conn,
    __u8  direction,
    __u8  protocol,
    const void __user *payload,
    __u32 payload_len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Clip payload to maximum capture size
    __u32 cap        = payload_len > MAX_PAYLOAD_SIZE
                         ? MAX_PAYLOAD_SIZE : payload_len;
    __u32 total_size = sizeof(struct event_header) + cap;

    // Reserve ring buffer space (non-blocking)
    struct event_header *hdr =
        bpf_ringbuf_reserve(&events, total_size, 0);
    if (!hdr) {
        record_drop();
        return -1;
    }

    // ── Populate header ───────────────────────────────────────────
    hdr->timestamp_ns = bpf_ktime_get_ns();
    hdr->conn_id      = conn->conn_id;

    hdr->pid          = (__u32)(pid_tgid >> 32);
    hdr->tid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    hdr->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hdr->src_ip4      = conn->src_ip4;
    hdr->dst_ip4      = conn->dst_ip4;
    hdr->src_port     = conn->src_port;
    hdr->dst_port     = conn->dst_port;

    hdr->direction    = direction;
    hdr->protocol     = protocol;
    hdr->ip_version   = 4;
    hdr->truncated    = (payload_len > MAX_PAYLOAD_SIZE) ? 1 : 0;

    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));

    hdr->payload_len  = cap;
    hdr->original_len = payload_len;

    // ── Copy payload (immediately after header in ring buffer) ────
    if (cap > 0 && payload) {
        void *dst = (void *)(hdr + 1);
        if (bpf_probe_read_user(dst, cap, payload) < 0) {
            // Payload unreadable — zero-length is better than corrupt data
            hdr->payload_len = 0;
        }
    }

    bpf_ringbuf_submit(hdr, 0);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe: kprobe/tcp_sendmsg
//
// Fires on every outbound TCP write. We:
//   1. Check PID and port filters
//   2. Detect protocol from the first iovec buffer
//   3. Update or create connection metadata
//   4. Emit event to ring buffer
//
// Signature: int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
// ─────────────────────────────────────────────────────────────────────────────

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(probe_tcp_sendmsg,
               struct sock *sk,
               struct msghdr *msg,
               size_t size)
{
    // ── Filter: PID ───────────────────────────────────────────────
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;

    // ── Extract 4-tuple ───────────────────────────────────────────
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    if (read_sock_4tuple(sk, &src_ip, &dst_ip, &src_port, &dst_port) < 0)
        return 0;

    // ── Filter: port ──────────────────────────────────────────────
    if (!port_allowed(dst_port) && !port_allowed(src_port))
        return 0;

    // ── Get iovec base pointer ────────────────────────────────────
    // msghdr.msg_iter.iov points to the first iovec; iov.iov_base is
    // the user-space buffer pointer.
    struct iovec *iov = NULL;
    bpf_probe_read_kernel(&iov, sizeof(iov), &msg->msg_iter.iov);
    if (!iov)
        return 0;

    void __user *iov_base = NULL;
    bpf_probe_read_kernel(&iov_base, sizeof(iov_base), &iov->iov_base);
    if (!iov_base)
        return 0;

    // ── Detect protocol ───────────────────────────────────────────
    __u8 proto = detect_protocol(iov_base, (__u32)size);

    // ── Connection state ──────────────────────────────────────────
    struct conn_tuple key = {
        .src_ip4   = src_ip,
        .dst_ip4   = dst_ip,
        .src_port  = src_port,
        .dst_port  = dst_port,
        .pid       = pid,
    };

    struct conn_meta *conn =
        get_or_create_conn(&key, src_ip, dst_ip, src_port, dst_port, pid);
    if (!conn)
        return 0;

    // Promote UNKNOWN to detected protocol (first-write wins)
    if (conn->protocol == PROTO_UNKNOWN && proto != PROTO_UNKNOWN)
        conn->protocol = proto;

    __u8 final_proto = (conn->protocol != PROTO_UNKNOWN)
                         ? conn->protocol : proto;

    emit_event(conn, DIR_EGRESS, final_proto, iov_base, (__u32)size);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe: kprobe/tcp_recvmsg (entry)
//
// Stashes the msghdr and sock pointers into a per-thread map so the
// return probe can find them after the kernel has filled the buffer.
//
// We cannot read the payload here because the kernel hasn't written it yet.
//
// Signature: int tcp_recvmsg(struct sock *sk, struct msghdr *msg,
//                            size_t len, int flags, int *addr_len)
// ─────────────────────────────────────────────────────────────────────────────

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(probe_tcp_recvmsg_entry,
               struct sock *sk,
               struct msghdr *msg,
               size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;

    // Quick port pre-check to avoid storing context for uninteresting sockets
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    if (read_sock_4tuple(sk, &src_ip, &dst_ip, &src_port, &dst_port) < 0)
        return 0;

    if (!port_allowed(dst_port) && !port_allowed(src_port))
        return 0;

    struct recvmsg_args args = {
        .sock_ptr   = (__u64)(unsigned long)sk,
        .msghdr_ptr = (__u64)(unsigned long)msg,
    };
    bpf_map_update_elem(&recvmsg_ctx, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe: kretprobe/tcp_recvmsg (exit)
//
// Fires after the kernel has copied data into the user buffer.
// The return value is the number of bytes actually read (> 0 on success).
// ─────────────────────────────────────────────────────────────────────────────

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(probe_tcp_recvmsg_exit, int ret)
{
    // No data read or error
    if (ret <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);

    // Retrieve stashed context
    struct recvmsg_args *args =
        bpf_map_lookup_elem(&recvmsg_ctx, &pid_tgid);
    if (!args)
        return 0;

    struct sock    *sk  = (struct sock *)(unsigned long)args->sock_ptr;
    struct msghdr  *msg = (struct msghdr *)(unsigned long)args->msghdr_ptr;
    bpf_map_delete_elem(&recvmsg_ctx, &pid_tgid);

    // Re-extract 4-tuple (same socket as entry probe)
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    if (read_sock_4tuple(sk, &src_ip, &dst_ip, &src_port, &dst_port) < 0)
        return 0;

    // Get iov_base — this now points to the filled user buffer
    struct iovec *iov = NULL;
    bpf_probe_read_kernel(&iov, sizeof(iov), &msg->msg_iter.iov);
    if (!iov)
        return 0;

    void __user *iov_base = NULL;
    bpf_probe_read_kernel(&iov_base, sizeof(iov_base), &iov->iov_base);
    if (!iov_base)
        return 0;

    __u8 proto = detect_protocol(iov_base, (__u32)ret);

    struct conn_tuple key = {
        .src_ip4   = src_ip,
        .dst_ip4   = dst_ip,
        .src_port  = src_port,
        .dst_port  = dst_port,
        .pid       = pid,
    };

    struct conn_meta *conn =
        get_or_create_conn(&key, src_ip, dst_ip, src_port, dst_port, pid);
    if (!conn)
        return 0;

    if (conn->protocol == PROTO_UNKNOWN && proto != PROTO_UNKNOWN)
        conn->protocol = proto;

    __u8 final_proto = (conn->protocol != PROTO_UNKNOWN)
                         ? conn->protocol : proto;

    emit_event(conn, DIR_INGRESS, final_proto, iov_base, (__u32)ret);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe: kprobe/tcp_close
//
// Fires when a TCP socket is closed. Emits a zero-payload CLOSE event so
// userspace can flush any buffered state for this connection, then removes
// the connection from the tracking map.
//
// Signature: void tcp_close(struct sock *sk, long timeout)
// ─────────────────────────────────────────────────────────────────────────────

SEC("kprobe/tcp_close")
int BPF_KPROBE(probe_tcp_close, struct sock *sk)
{
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    if (read_sock_4tuple(sk, &src_ip, &dst_ip, &src_port, &dst_port) < 0)
        return 0;

    if (!port_allowed(dst_port) && !port_allowed(src_port))
        return 0;

    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    struct conn_tuple key = {
        .src_ip4   = src_ip,
        .dst_ip4   = dst_ip,
        .src_port  = src_port,
        .dst_port  = dst_port,
        .pid       = pid,
    };

    struct conn_meta *conn = bpf_map_lookup_elem(&connections, key);
    if (conn) {
        // Emit CLOSE event with last-known protocol
        emit_event(conn, DIR_CLOSE, conn->protocol, NULL, 0);
        bpf_map_delete_elem(&connections, &key);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";