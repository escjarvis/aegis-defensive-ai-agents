/*
 * outbound_connection_tracer.bpf.c
 *
 * Sample eBPF program stub for the Inline Protective Agent
 * (FortiGate Sentry 900G context)
 *
 * Purpose:
 *   Trace outbound network connections to detect potential data exfiltration
 *   from browser-assembled malicious inference models.
 *
 * This is a lightweight stub designed to illustrate integration points.
 * In a real deployment it would feed events to the Python InlineProtectiveAgent
 * via ring buffer or perf events.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Event structure sent to userspace */
struct connection_event {
    __u32 pid;
    __u32 tgid;
    __u32 daddr;      /* Destination IPv4 */
    __u16 dport;      /* Destination port */
    __u16 lport;      /* Local port */
    __u64 timestamp;
    char comm[16];    /* Process name */
};

/* Ring buffer for sending events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Tracepoint for connect syscall (IPv4) */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in *addr;
    struct connection_event *e;
    struct task_struct *task;

    /* Only trace IPv4 for simplicity in this stub */
    addr = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
    if (addr->sin_family != AF_INET)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->daddr = BPF_CORE_READ(addr, sin_addr.s_addr);
    e->dport = bpf_ntohs(BPF_CORE_READ(addr, sin_port));
    e->lport = 0; /* Can be filled from socket if needed */
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
