/*
 * xdp_early_inspector.bpf.c
 *
 * More complete XDP program stub for the Inline Protective Agent
 * (FortiGate Sentry 900G context)
 *
 * Capabilities:
 *   - Early packet inspection at the driver level
 *   - Detects unusually large packets (strong signal for model artifact transfer/exfiltration)
 *   - Extracts basic metadata (IP version, ports, packet size)
 *   - Sends events via ring buffer for consumption by userspace/Python agent
 *
 * This is designed to be compilable with modern libbpf + clang.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Event sent to userspace */
struct xdp_event {
    __u32 ifindex;
    __u32 pkt_len;
    __u8  ip_version;     /* 4 or 6 */
    __u32 src_ip;         /* IPv4 only for simplicity */
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u64 timestamp;
};

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_early_inspect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    /* Only handle IPv4 for this stub (IPv6 can be added similarly) */
    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 pkt_len = ctx->data_end - ctx->data;

    /* Example policy: Drop very large packets (potential model transfer) */
    if (pkt_len > 9000) {   /* Adjust threshold as needed */
        /* In production we might log via ring buffer first */
        return XDP_DROP;
    }

    /* Prepare event for userspace */
    struct xdp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return XDP_PASS;

    e->ifindex   = ctx->ingress_ifindex;
    e->pkt_len   = pkt_len;
    e->ip_version = 4;
    e->src_ip    = ip->saddr;
    e->dst_ip    = ip->daddr;
    e->src_port  = 0; /* TCP/UDP ports would require further parsing */
    e->dst_port  = 0;
    e->timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
