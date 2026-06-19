/*
 * xdp_early_inspector.bpf.c
 *
 * Enhanced XDP program for the Inline Protective Agent
 * (FortiGate Sentry 900G context)
 *
 * Features:
 *   - Early packet inspection (Ethernet + IP + TCP/UDP)
 *   - IPv4 and basic IPv6 support
 *   - Large packet detection (model artifact / exfiltration signal)
 *   - Extracts ports and basic metadata
 *   - Sends events via ring buffer
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
    __u8  protocol;     /* IPPROTO_TCP / UDP */
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline int parse_ports(void *data, void *data_end, __u8 protocol,
                                       __u16 *src_port, __u16 *dst_port)
{
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)data;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        *src_port = bpf_ntohs(tcp->source);
        *dst_port = bpf_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)data;
        if ((void *)(udp + 1) > data_end)
            return 0;
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
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    struct xdp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return XDP_PASS;

    e->ifindex = ctx->ingress_ifindex;
    e->pkt_len = ctx->data_end - ctx->data;
    e->timestamp = bpf_ktime_get_ns();

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }

        e->ip_version = 4;
        e->src_ip = ip->saddr;
        e->dst_ip = ip->daddr;
        e->protocol = ip->protocol;

        void *l4 = (void *)ip + (ip->ihl * 4);
        parse_ports(l4, data_end, ip->protocol, &e->src_port, &e->dst_port);

    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }

        e->ip_version = 6;
        __builtin_memcpy(e->src_ip_v6, &ip6->saddr, 16);
        __builtin_memcpy(e->dst_ip_v6, &ip6->daddr, 16);
        e->protocol = ip6->nexthdr;

        void *l4 = (void *)ip6 + 40; /* IPv6 header is fixed 40 bytes */
        parse_ports(l4, data_end, ip6->nexthdr, &e->src_port, &e->dst_port);
    } else {
        bpf_ringbuf_discard(e, 0);
        return XDP_PASS;
    }

    /* Early drop for very large packets (model transfer / exfiltration) */
    if (e->pkt_len > 9000) {
        bpf_ringbuf_submit(e, 0);
        return XDP_DROP;
    }

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
