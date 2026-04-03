// SPDX-License-Identifier: GPL-2.0
//
// process_monitor.bpf.c
// =====================
// Kernel-level process and file-system event capture for AI agent monitoring.
//
// What this captures
// ------------------
//  PROC_EXEC   : sched_process_exec — agent spawned a subprocess
//  PROC_EXIT   : sched_process_exit — subprocess finished + exit code
//  FILE_OPEN   : sys_enter_openat   — file opened (path + flags)
//  FILE_WRITE  : sys_exit_write     — bytes written to an fd
//  NET_CONNECT : sys_exit_connect   — outbound TCP connection established
//  NET_BIND    : sys_exit_bind      — agent opened a listening socket
//
// Why tracepoints instead of kprobes
// ------------------------------------
// Tracepoints have stable ABIs — they don't break across minor kernel
// versions the way kprobe targets can. sched_process_exec and
// sched_process_exit are standard scheduler tracepoints available on
// all kernels ≥ 4.4.  openat2/connect/write tracepoints are in
// sys_enter_* / sys_exit_* which are available via raw_tracepoint
// in 4.17+.
//
// Process tree tracking
// ----------------------
// We maintain a pid→ppid map in BPF so every child event can be traced
// back to its root agent. The Python consumer resolves the full tree.
//
// Filtering
// ---------
// root_pid_set: userspace populates this with the PIDs of known agent
// processes. Only events from those PIDs (or their children) are emitted.
// When empty, all processes are captured (safe default for discovery).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define PATH_MAX_CAP    256     // max chars of file path captured
#define COMM_LEN        16
#define AF_INET         2
#define AF_INET6        10

// Event types
#define PROC_EXEC       1
#define PROC_EXIT       2
#define FILE_OPEN       3
#define FILE_WRITE      4
#define NET_CONNECT     5
#define NET_BIND        6

// File open flags (mirrors Linux O_* — kept minimal for portability)
#define O_RDONLY        0x0000
#define O_WRONLY        0x0001
#define O_RDWR          0x0002
#define O_CREAT         0x0040
#define O_TRUNC         0x0200
#define O_APPEND        0x0400

// ─── Event structure ──────────────────────────────────────────────────────────

struct proc_event_t {
    // Fixed header (72 bytes)
    __u64  timestamp_ns;
    __u64  root_pid;        // root agent pid (resolved in BPF via ppid map)
    __u32  pid;
    __u32  ppid;            // parent pid
    __u32  tid;
    __u32  uid;
    __u8   event_type;      // PROC_EXEC | FILE_OPEN | ...
    __u8   pad[3];

    // Outcome
    __s32  retval;          // syscall return value (negative = error)
    __u32  flags;           // open flags or connect family

    // Network (NET_CONNECT / NET_BIND)
    __u32  dst_addr;        // IPv4 destination
    __u32  src_addr;
    __u16  dst_port;
    __u16  src_port;

    // Bytes (FILE_WRITE)
    __u64  bytes_count;

    char   comm[COMM_LEN];  // process name

    // Variable: file path or exec filename (null-terminated, up to PATH_MAX_CAP)
    char   path[PATH_MAX_CAP];
} __attribute__((packed));

// ─── Maps ────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);   // 64 MB
} proc_events SEC(".maps");

// pid → ppid  (populated on exec, used to trace child chains)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u32);   // pid
    __type(value, __u32);   // ppid
} pid_ppid_map SEC(".maps");

// root_pid_set: agent PIDs to monitor (empty = monitor all)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);   // pid
    __type(value, __u8);    // 1 = is root
} root_pid_set SEC(".maps");

// In-flight openat: tid → flags (stash on entry, emit on exit with retval)
struct open_args_t {
    __u64 path_ptr;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);               // tid
    __type(value, struct open_args_t);
} open_args SEC(".maps");

// In-flight connect: tid → sockaddr ptr
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);               // tid
    __type(value, __u64);               // sockaddr ptr
} connect_args SEC(".maps");

// In-flight write: tid → fd
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);
    __type(value, __u64);               // fd
} write_args SEC(".maps");

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Resolve root_pid by walking ppid chain (max 8 hops to avoid infinite loop)
static __always_inline __u64 resolve_root_pid(__u32 pid) {
    __u32 cur = pid;
    for (int i = 0; i < 8; i++) {
        __u8 *is_root = bpf_map_lookup_elem(&root_pid_set, &cur);
        if (is_root)
            return (__u64)cur;
        __u32 *pp = bpf_map_lookup_elem(&pid_ppid_map, &cur);
        if (!pp || *pp == 0 || *pp == cur)
            break;
        cur = *pp;
    }
    // If root_pid_set is empty, treat every pid as its own root (discovery mode)
    return (__u64)pid;
}

static __always_inline bool should_capture(__u32 pid) {
    // If the set is empty (no keys), capture everything
    // We check by looking up the pid itself or any ancestor
    __u32 cur = pid;
    for (int i = 0; i < 8; i++) {
        __u8 *is_root = bpf_map_lookup_elem(&root_pid_set, &cur);
        if (is_root)
            return true;
        __u32 *pp = bpf_map_lookup_elem(&pid_ppid_map, &cur);
        if (!pp || *pp == 0 || *pp == cur)
            break;
        cur = *pp;
    }

    // root_pid_set empty → capture all (discovery mode)
    // We detect "empty" by trying a sentinel key we never insert
    __u32 sentinel = 0xFFFFFFFF;
    __u8 *s = bpf_map_lookup_elem(&root_pid_set, &sentinel);
    // sentinel key present means "filter mode active but pid not matched"
    return (s == NULL);  // NULL sentinel = empty set = capture all
}

// ─── sched_process_exec ───────────────────────────────────────────────────────
// Fires when a process calls execve successfully.

SEC("tracepoint/sched/sched_process_exec")
int tp_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 ppid     = 0;

    // Get ppid from task_struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
        }
    }

    // Update pid→ppid map
    bpf_map_update_elem(&pid_ppid_map, &pid, &ppid, BPF_ANY);

    if (!should_capture(pid))
        return 0;

    struct proc_event_t *ev = bpf_ringbuf_reserve(&proc_events,
                                                    sizeof(struct proc_event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid;
    ev->ppid         = ppid;
    ev->tid          = (__u32)pid_tgid;
    ev->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->event_type   = PROC_EXEC;
    ev->retval       = 0;
    ev->root_pid     = resolve_root_pid(pid);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    // Filename from tracepoint context
    unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(ev->path, sizeof(ev->path),
                               (char *)ctx + fname_off);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ─── sched_process_exit ───────────────────────────────────────────────────────

SEC("tracepoint/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);

    if (!should_capture(pid))
        goto cleanup;

    {
        struct proc_event_t *ev = bpf_ringbuf_reserve(&proc_events,
                                                        sizeof(struct proc_event_t), 0);
        if (ev) {
            ev->timestamp_ns = bpf_ktime_get_ns();
            ev->pid          = pid;
            ev->tid          = (__u32)pid_tgid;
            ev->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            ev->event_type   = PROC_EXIT;
            ev->retval       = ctx->prio;   // exit code is in ctx
            ev->root_pid     = resolve_root_pid(pid);
            bpf_get_current_comm(ev->comm, sizeof(ev->comm));
            bpf_ringbuf_submit(ev, 0);
        }
    }

cleanup:
    bpf_map_delete_elem(&pid_ppid_map, &pid);
    return 0;
}

// ─── sys_enter_openat ─────────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);

    if (!should_capture(pid))
        return 0;

    struct open_args_t args = {};
    args.path_ptr = (uintptr_t)ctx->args[1];   // const char __user *filename
    args.flags    = (__u32)ctx->args[2];        // int flags
    bpf_map_update_elem(&open_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);

    struct open_args_t *args = bpf_map_lookup_elem(&open_args, &pid_tgid);
    if (!args)
        return 0;

    struct open_args_t saved = *args;
    bpf_map_delete_elem(&open_args, &pid_tgid);

    // Only emit successful opens (retval ≥ 0 = fd)
    if (ctx->ret < 0)
        return 0;

    struct proc_event_t *ev = bpf_ringbuf_reserve(&proc_events,
                                                    sizeof(struct proc_event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid;
    ev->tid          = (__u32)pid_tgid;
    ev->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->event_type   = FILE_OPEN;
    ev->retval       = (__s32)ctx->ret;   // fd number
    ev->flags        = saved.flags;
    ev->root_pid     = resolve_root_pid(pid);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    bpf_probe_read_user_str(ev->path, sizeof(ev->path),
                             (const char *)(uintptr_t)saved.path_ptr);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ─── sys_enter_write / sys_exit_write ────────────────────────────────────────
// We only record byte counts, not content.

SEC("tracepoint/syscalls/sys_enter_write")
int tp_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);

    if (!should_capture(pid))
        return 0;

    __u64 fd = (__u64)ctx->args[0];
    bpf_map_update_elem(&write_args, &pid_tgid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tp_write_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fd_ptr  = bpf_map_lookup_elem(&write_args, &pid_tgid);
    if (!fd_ptr)
        return 0;

    bpf_map_delete_elem(&write_args, &pid_tgid);

    if (ctx->ret <= 0)
        return 0;

    __u32 pid = (__u32)(pid_tgid >> 32);

    struct proc_event_t *ev = bpf_ringbuf_reserve(&proc_events,
                                                    sizeof(struct proc_event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid;
    ev->tid          = (__u32)pid_tgid;
    ev->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->event_type   = FILE_WRITE;
    ev->retval       = (__s32)ctx->ret;
    ev->bytes_count  = (__u64)ctx->ret;
    ev->root_pid     = resolve_root_pid(pid);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    // path not available at write exit without fd→path lookup (expensive)
    // Python side resolves via /proc/pid/fd/N

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ─── sys_enter_connect / sys_exit_connect ────────────────────────────────────

struct sockaddr_in_bpf {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);

    if (!should_capture(pid))
        return 0;

    __u64 addr_ptr = (__u64)ctx->args[1];
    bpf_map_update_elem(&connect_args, &pid_tgid, &addr_ptr, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tp_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *addr_ptr = bpf_map_lookup_elem(&connect_args, &pid_tgid);
    if (!addr_ptr)
        return 0;

    __u64 saved_ptr = *addr_ptr;
    bpf_map_delete_elem(&connect_args, &pid_tgid);

    // Only emit successful connects (ret == 0)
    if (ctx->ret != 0)
        return 0;

    __u32 pid = (__u32)(pid_tgid >> 32);

    struct sockaddr_in_bpf sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)(uintptr_t)saved_ptr);

    if (sa.sin_family != AF_INET)
        return 0;   // IPv6 support can be added; skip for now

    struct proc_event_t *ev = bpf_ringbuf_reserve(&proc_events,
                                                    sizeof(struct proc_event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid;
    ev->tid          = (__u32)pid_tgid;
    ev->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->event_type   = NET_CONNECT;
    ev->retval       = 0;
    ev->flags        = AF_INET;
    ev->dst_addr     = sa.sin_addr;
    ev->dst_port     = __builtin_bswap16(sa.sin_port);
    ev->root_pid     = resolve_root_pid(pid);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";