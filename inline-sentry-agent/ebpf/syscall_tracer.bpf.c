/*
 * syscall_tracer.bpf.c
 *
 * Sample eBPF stub for kernel-level visibility into suspicious process behavior.
 * Useful for enhancing the SandboxModule (especially when analyzing payloads
 * that may spawn processes or perform dangerous operations).
 *
 * Traces selected dangerous syscalls (execve, openat, connect) with basic filtering.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct syscall_event {
    __u32 pid;
    __u32 tgid;
    __u64 timestamp;
    __u32 syscall_id;
    char comm[16];
    /* For execve/openat we can add more fields later */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} rb SEC(".maps");

/* Trace execve */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->syscall_id = 59; /* __NR_execve */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Trace openat (file access) */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->syscall_id = 257; /* __NR_openat */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
