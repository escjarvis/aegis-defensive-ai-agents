/*
 * outbound_connection_tracer.bpf.c
 *
 * Sample eBPF program for the Inline Protective Agent
 * (FortiGate Sentry 900G context)
 *
 * Traces outbound connections (IPv4 + IPv6) to help detect data exfiltration
 * from browser-assembled malicious inference models.
 *
 * Enhanced version with IPv6 support and connection start timestamp.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct connection_event {
    __u32 pid;
    __u32 tgid;
    __u8 family;        /* AF_INET or AF_INET6 */
    __u32 daddr_v4;     /* IPv4 destination */
    __u8 daddr_v6[16];  /* IPv6 destination */
    __u16 dport;
    __u64 timestamp;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* IPv4 connect */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_v4(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
    if (addr->sin_family != AF_INET)
        return 0;

    struct connection_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->family = AF_INET;
    e->daddr_v4 = BPF_CORE_READ(addr, sin_addr.s_addr);
    e->dport = bpf_ntohs(BPF_CORE_READ(addr, sin_port));
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* IPv6 connect */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_v6(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)BPF_CORE_READ(ctx, args[1]);
    if (addr->sin6_family != AF_INET6)
        return 0;

    struct connection_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->family = AF_INET6;
    BPF_CORE_READ_INTO(&e->daddr_v6, addr, sin6_addr);
    e->dport = bpf_ntohs(BPF_CORE_READ(addr, sin6_port));
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
