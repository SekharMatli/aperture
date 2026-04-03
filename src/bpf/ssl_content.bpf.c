// SPDX-License-Identifier: GPL-2.0
//
// ssl_content.bpf.c
// =================
// Captures decrypted SSL/TLS plaintext via uprobes on SSL_read / SSL_write.
//
// Probe strategy
// --------------
// SSL_write entry  : buf is plaintext the application is SENDING.
//                    Read buf before the TLS library encrypts it.
// SSL_read  entry  : stash (tid -> buf ptr) so we know where data lands.
// SSL_read  return : buf now contains decrypted RECEIVED data; copy it.
//
// BoringSSL (Claude Code / Bun)
// -----------------------------
// Symbols are stripped so we cannot attach by name. The Python side locates
// the functions via byte-pattern scanning and passes offsets; the loader
// calls attach_uprobe with the explicit offset instead of a symbol name.
//
// Content field sizes
// -------------------
// SSL_CONTENT_MAX  : Maximum bytes captured per event. Large enough to hold
//                    one full LLM API request or response JSON body.
//                    Default 65536 (64 KB); configurable at load time via
//                    the ssl_config_map.
//
// ring buffer sizing
// ------------------
// Each event is up to SSL_CONTENT_MAX + fixed header bytes.
// Ring buffer is 256 MB to absorb bursts of large LLM responses.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define SSL_CONTENT_MAX     65536   // 64 KB per captured event
#define COMM_LEN            16
#define AF_INET             2
#define AF_INET6            10

// Event direction
#define SSL_DIR_WRITE       1   // agent → LLM (request/prompt)
#define SSL_DIR_READ        2   // LLM → agent (response)

// ─── Event structure ──────────────────────────────────────────────────────────
//
// Written to the ring buffer. Fixed header + variable data.
// Consumer reads up to data_len bytes from the data field.

struct ssl_event_t {
    // Envelope (fixed, 64 bytes)
    __u64  timestamp_ns;
    __u64  root_pid;          // top-level agent process (for correlation)
    __u32  pid;               // actual pid writing/reading SSL
    __u32  tid;
    __u32  uid;
    __u8   direction;         // SSL_DIR_WRITE | SSL_DIR_READ
    __u8   is_tls;            // always 1 for events from this program
    __u8   truncated;         // 1 if data was clipped at SSL_CONTENT_MAX
    __u8   pad;
    __u32  data_len;          // actual captured bytes (≤ SSL_CONTENT_MAX)
    __u32  seq;               // per-(pid,dir) monotonic counter for ordering
    char   comm[COMM_LEN];    // process name

    // Variable content (up to SSL_CONTENT_MAX bytes)
    char   data[SSL_CONTENT_MAX];
} __attribute__((packed));

// ─── Maps ────────────────────────────────────────────────────────────────────

// Ring buffer — 256 MB, zero copy, variable-size records
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024);
} ssl_events SEC(".maps");

// SSL_read entry: stash (tid -> user buf ptr) so the return probe can copy
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);       // tid (u64 for alignment)
    __type(value, __u64);       // user-space buf pointer
} ssl_read_args SEC(".maps");

// Per-pid/dir sequence counter for ordering reassembly
struct seq_key_t {
    __u32 pid;
    __u8  dir;
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct seq_key_t);
    __type(value, __u32);
} ssl_seq SEC(".maps");

// Config: max bytes to capture per event
struct ssl_config_t {
    __u32 max_capture_bytes;    // capped at SSL_CONTENT_MAX
    __u8  filter_by_comm;       // 1 = only capture comm matching target_comm
    __u8  pad[3];
    char  target_comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct ssl_config_t);
} ssl_config_map SEC(".maps");

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline struct ssl_config_t *_get_ssl_cfg(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&ssl_config_map, &key);
}

static __always_inline bool _comm_matches(struct ssl_config_t *cfg) {
    if (!cfg || !cfg->filter_by_comm)
        return true;
    char comm[COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    for (int i = 0; i < COMM_LEN; i++) {
        if (comm[i] != cfg->target_comm[i])
            return false;
        if (comm[i] == '\0')
            break;
    }
    return true;
}

static __always_inline __u32 _next_seq(__u32 pid, __u8 dir) {
    struct seq_key_t k = { .pid = pid, .dir = dir };
    __u32 *seq = bpf_map_lookup_elem(&ssl_seq, &k);
    __u32 n = seq ? (*seq + 1) : 0;
    bpf_map_update_elem(&ssl_seq, &k, &n, BPF_ANY);
    return n;
}

// ─── SSL_write uprobe — captures outbound plaintext (prompts) ─────────────────
//
// Signature: int SSL_write(SSL *ssl, const void *buf, int num);
// Called BEFORE encryption — buf is plaintext.

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    // arg1 = ssl (ignored), arg2 = buf, arg3 = num
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int         num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0)
        return 0;

    struct ssl_config_t *cfg = _get_ssl_cfg();
    if (!_comm_matches(cfg))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 tid      = (__u32)pid_tgid;

    __u32 cap = (cfg && cfg->max_capture_bytes && cfg->max_capture_bytes < SSL_CONTENT_MAX)
                    ? cfg->max_capture_bytes : SSL_CONTENT_MAX;
    __u32 copy_len = (__u32)num < cap ? (__u32)num : cap;

    struct ssl_event_t *ev = bpf_ringbuf_reserve(&ssl_events,
                                                   sizeof(struct ssl_event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid;
    ev->tid          = tid;
    ev->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->root_pid     = (__u64)pid;   // Python side will resolve to session root
    ev->direction    = SSL_DIR_WRITE;
    ev->is_tls       = 1;
    ev->truncated    = ((__u32)num > cap) ? 1 : 0;
    ev->data_len     = copy_len;
    ev->seq          = _next_seq(pid, SSL_DIR_WRITE);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    // Bounded read for BPF verifier — must use a compile-time constant mask
    bpf_probe_read_user(ev->data, copy_len & (SSL_CONTENT_MAX - 1), buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ─── SSL_write_ex uprobe — BoringSSL / OpenSSL 3.x variant ───────────────────
//
// Signature: int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written);

SEC("uprobe/SSL_write_ex")
int uprobe_ssl_write_ex(struct pt_regs *ctx)
{
    const void *buf  = (const void *)PT_REGS_PARM2(ctx);
    size_t      num  = (size_t)PT_REGS_PARM3(ctx);

    if (!num)
        return 0;

    struct ssl_config_t *cfg = _get_ssl_cfg();
    if (!_comm_matches(cfg))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 tid      = (__u32)pid_tgid;

    __u32 cap      = (cfg && cfg->max_capture_bytes && cfg->max_capture_bytes < SSL_CONTENT_MAX)
                         ? cfg->max_capture_bytes : SSL_CONTENT_MAX;
    __u32 copy_len = ((__u32)num < cap) ? (__u32)num : cap;

    struct ssl_event_t *ev = bpf_ringbuf_reserve(&ssl_events,
                                                   sizeof(struct ssl_event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid;
    ev->tid          = tid;
    ev->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->root_pid     = (__u64)pid;
    ev->direction    = SSL_DIR_WRITE;
    ev->is_tls       = 1;
    ev->truncated    = ((__u32)num > cap) ? 1 : 0;
    ev->data_len     = copy_len;
    ev->seq          = _next_seq(pid, SSL_DIR_WRITE);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    bpf_probe_read_user(ev->data, copy_len & (SSL_CONTENT_MAX - 1), buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ─── SSL_read entry — stash buf ptr ──────────────────────────────────────────
//
// Signature: int SSL_read(SSL *ssl, void *buf, int num);
// On entry buf is not yet filled. Stash the pointer so the return probe
// can read from it after the library has written decrypted data.

SEC("uprobe/SSL_read")
int uprobe_ssl_read_entry(struct pt_regs *ctx)
{
    struct ssl_config_t *cfg = _get_ssl_cfg();
    if (!_comm_matches(cfg))
        return 0;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    if (!buf)
        return 0;

    __u64 tid64 = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    __u64 ptr   = (__u64)(uintptr_t)buf;
    bpf_map_update_elem(&ssl_read_args, &tid64, &ptr, BPF_ANY);
    return 0;
}

// ─── SSL_read return — copy decrypted data ───────────────────────────────────
//
// Return value is the number of bytes read into buf (>0 on success).

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u64 tid64    = pid_tgid & 0xFFFFFFFF;

    __u64 *buf_ptr = bpf_map_lookup_elem(&ssl_read_args, &tid64);
    if (!buf_ptr)
        return 0;

    __u64 buf = *buf_ptr;
    bpf_map_delete_elem(&ssl_read_args, &tid64);

    struct ssl_config_t *cfg = _get_ssl_cfg();
    __u32 cap      = (cfg && cfg->max_capture_bytes && cfg->max_capture_bytes < SSL_CONTENT_MAX)
                         ? cfg->max_capture_bytes : SSL_CONTENT_MAX;
    __u32 copy_len = ((__u32)ret < cap) ? (__u32)ret : cap;

    struct ssl_event_t *ev = bpf_ringbuf_reserve(&ssl_events,
                                                   sizeof(struct ssl_event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid;
    ev->tid          = (__u32)tid64;
    ev->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->root_pid     = (__u64)pid;
    ev->direction    = SSL_DIR_READ;
    ev->is_tls       = 1;
    ev->truncated    = ((__u32)ret > cap) ? 1 : 0;
    ev->data_len     = copy_len;
    ev->seq          = _next_seq(pid, SSL_DIR_READ);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    bpf_probe_read_user(ev->data, copy_len & (SSL_CONTENT_MAX - 1), (void *)(uintptr_t)buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// SSL_read_ex entry
SEC("uprobe/SSL_read_ex")
int uprobe_ssl_read_ex_entry(struct pt_regs *ctx)
{
    struct ssl_config_t *cfg = _get_ssl_cfg();
    if (!_comm_matches(cfg))
        return 0;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    if (!buf)
        return 0;

    __u64 tid64 = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    __u64 ptr   = (__u64)(uintptr_t)buf;
    bpf_map_update_elem(&ssl_read_args, &tid64, &ptr, BPF_ANY);
    return 0;
}

// SSL_read_ex return — size is in *readbytes (arg4), not retval
// retval is 1/0 success indicator; actual bytes in arg4 ptr
SEC("uretprobe/SSL_read_ex")
int uretprobe_ssl_read_ex(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret != 1)   // 1 = success in SSL_read_ex
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u64 tid64    = pid_tgid & 0xFFFFFFFF;

    __u64 *buf_ptr = bpf_map_lookup_elem(&ssl_read_args, &tid64);
    if (!buf_ptr)
        return 0;

    __u64 buf = *buf_ptr;
    bpf_map_delete_elem(&ssl_read_args, &tid64);

    // For SSL_read_ex we don't know exact byte count at this point.
    // Capture SSL_CONTENT_MAX and let Python trim to actual content.
    struct ssl_config_t *cfg = _get_ssl_cfg();
    __u32 cap = (cfg && cfg->max_capture_bytes && cfg->max_capture_bytes < SSL_CONTENT_MAX)
                    ? cfg->max_capture_bytes : SSL_CONTENT_MAX;

    struct ssl_event_t *ev = bpf_ringbuf_reserve(&ssl_events,
                                                   sizeof(struct ssl_event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid;
    ev->tid          = (__u32)tid64;
    ev->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->root_pid     = (__u64)pid;
    ev->direction    = SSL_DIR_READ;
    ev->is_tls       = 1;
    ev->truncated    = 0;   // unknown
    ev->data_len     = cap;
    ev->seq          = _next_seq(pid, SSL_DIR_READ);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    bpf_probe_read_user(ev->data, cap, (void *)(uintptr_t)buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";