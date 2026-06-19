/*
 * xdp_early_inspector.bpf.c
 *
 * Enhanced XDP program with shared map for tighter coupling
 * with the Python InlineProtectiveAgent.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct xdp_event {
    __u32 ifindex;
    __u32 pkt_len;
    __u8  ip_version;
    __u32 src_ip;
    __u32 dst_ip;
    __u8  src_ip_v6[16];
    __u8  dst_ip_v6[16];
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u64 timestamp;
};

/* Shared map: key = destination IPv4, value = stats */
struct flow_stats {
    __u64 large_packet_count;
    __u64 total_bytes;
    __u8  suspicious;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);           /* dst_ip (IPv4) */
    __type(value, struct flow_stats);
} flow_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline int parse_ports(void *data, void *data_end, __u8 protocol,
                                       __u16 *src_port, __u16 *dst_port)
{
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)data;
        if ((void *)(tcp + 1) > data_end) return 0;
        *src_port = bpf_ntohs(tcp->source);
        *dst_port = bpf_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)data;
        if ((void *)(udp + 1) > data_end) return 0;
        *src_port = bpf_ntohs(udp->source);
        *dst_port = bpf_ntohs(udp->dest);
    }
    return 1;
}

SEC("xdp")
int xdp_early_inspect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 pkt_len = ctx->data_end - ctx->data;
    __u32 dst = ip->daddr;

    /* Update shared map */
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats_map, &dst);
    if (!stats) {
        struct flow_stats new_stats = {0};
        bpf_map_update_elem(&flow_stats_map, &dst, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&flow_stats_map, &dst);
    }

    if (stats) {
        __sync_fetch_and_add(&stats->total_bytes, pkt_len);
        if (pkt_len > 8000) {
            __sync_fetch_and_add(&stats->large_packet_count, 1);
            if (stats->large_packet_count > 3) {
                stats->suspicious = 1;
            }
        }
    }

    /* Send event via ring buffer */
    struct xdp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->ifindex = ctx->ingress_ifindex;
        e->pkt_len = pkt_len;
        e->ip_version = 4;
        e->src_ip = ip->saddr;
        e->dst_ip = dst;
        e->protocol = ip->protocol;
        e->timestamp = bpf_ktime_get_ns();

        void *l4 = (void *)ip + (ip->ihl * 4);
        parse_ports(l4, data_end, ip->protocol, &e->src_port, &e->dst_port);

        bpf_ringbuf_submit(e, 0);
    }

    /* Early drop for very large or suspicious flows */
    if (pkt_len > 9000 || (stats && stats->suspicious)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
