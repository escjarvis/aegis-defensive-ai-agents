/*
 * browser_inference_xdp.bpf.c
 *
 * XDP program for browser inference model detection with its own shared map.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct inference_event {
    __u32 ifindex;
    __u32 pkt_len;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  is_large_transfer;
    __u8  is_suspicious_resource;
    __u64 timestamp;
};

/* Shared map for browser inference flows */
struct browser_flow_stats {
    __u64 large_transfer_count;
    __u8  suspicious;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct browser_flow_stats);
} browser_flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} rb SEC(".maps");

SEC("xdp")
int xdp_browser_inference_detect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 pkt_len = ctx->data_end - ctx->data;
    __u32 dst = ip->daddr;

    struct browser_flow_stats *stats = bpf_map_lookup_elem(&browser_flow_map, &dst);
    if (!stats) {
        struct browser_flow_stats new_stats = {0};
        bpf_map_update_elem(&browser_flow_map, &dst, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&browser_flow_map, &dst);
    }

    if (stats && pkt_len > 2000) {
        __sync_fetch_and_add(&stats->large_transfer_count, 1);
        if (stats->large_transfer_count > 2) {
            stats->suspicious = 1;
        }
    }

    struct inference_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->ifindex = ctx->ingress_ifindex;
        e->pkt_len = pkt_len;
        e->dst_ip = dst;
        e->timestamp = bpf_ktime_get_ns();
        e->is_large_transfer = (pkt_len > 8000) ? 1 : 0;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
            if ((void *)(tcp + 1) > data_end) {
                bpf_ringbuf_discard(e, 0);
                return XDP_PASS;
            }
            e->dst_port = bpf_ntohs(tcp->dest);
            if (e->dst_port == 443 || e->dst_port == 80) {
                e->is_suspicious_resource = 1;
            }
        }

        bpf_ringbuf_submit(e, 0);
    }

    if (stats && stats->suspicious) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
