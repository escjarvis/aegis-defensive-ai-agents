/*
 * xdp_early_inspector.bpf.c
 *
 * Expanded XDP program with support for:
 *   - QUIC (UDP 443)
 *   - DNS (UDP/TCP 53)
 *   - Common AI Model / Agent API ports
 *   - Enhanced shared map with protocol and port tracking
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Event structure */
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
    __u8  protocol;           /* IPPROTO_TCP, UDP, etc. */
    __u8  app_protocol;       /* 0=Unknown, 1=HTTP/HTTPS, 2=QUIC, 3=DNS */
    __u64 timestamp;
};

/* Shared flow stats map */
struct flow_stats {
    __u64 large_packet_count;
    __u64 total_bytes;
    __u32 protocol;
    __u16 dst_port;
    __u8  app_protocol;
    __u8  suspicious;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct flow_stats);
} flow_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Common AI / Agent API ports (for heuristic marking) */
#define AI_PORT_OPENAI      443
#define AI_PORT_ANTHROPIC   443
#define AI_PORT_OLLAMA      11434
#define AI_PORT_LMSTUDIO    1234
#define AI_PORT_DEFAULT     8000

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

/* Simple QUIC detection heuristic (UDP + port 443 + long header) */
static __always_inline int is_quic(void *data, void *data_end, __u16 dst_port)
{
    if (dst_port != 443) return 0;

    /* QUIC long header starts with 0b1100xxxx */
    __u8 first_byte = *(__u8 *)data;
    if ((first_byte & 0xC0) == 0xC0)
        return 1;

    return 0;
}

SEC("xdp")
int xdp_early_inspect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 eth_proto = eth->h_proto;

    struct xdp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return XDP_PASS;

    e->ifindex   = ctx->ingress_ifindex;
    e->pkt_len   = ctx->data_end - ctx->data;
    e->timestamp = bpf_ktime_get_ns();
    e->app_protocol = 0;

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }

        e->ip_version = 4;
        e->src_ip     = ip->saddr;
        e->dst_ip     = ip->daddr;
        e->protocol   = ip->protocol;

        __u16 src_p = 0, dst_p = 0;
        void *l4 = (void *)ip + (ip->ihl * 4);

        if (parse_ports(l4, data_end, ip->protocol, &src_p, &dst_p)) {
            e->src_port = src_p;
            e->dst_port = dst_p;
        }

        /* Protocol identification */
        if (ip->protocol == IPPROTO_UDP && dst_p == 53) {
            e->app_protocol = 3; /* DNS */
        } else if (ip->protocol == IPPROTO_UDP && dst_p == 443) {
            if (is_quic(l4, data_end, dst_p))
                e->app_protocol = 2; /* QUIC */
            else
                e->app_protocol = 1; /* Likely HTTPS fallback */
        } else if (ip->protocol == IPPROTO_TCP && (dst_p == 80 || dst_p == 443)) {
            e->app_protocol = 1; /* HTTP/HTTPS */
        } else if (dst_p == AI_PORT_OLLAMA || dst_p == AI_PORT_LMSTUDIO || dst_p == AI_PORT_DEFAULT) {
            e->app_protocol = 4; /* AI / Agent API */
        }

    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        /* Basic IPv6 handling */
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }
        e->ip_version = 6;
        e->protocol = ip6->nexthdr;
        /* Simplified - full port parsing can be added */
    } else {
        bpf_ringbuf_discard(e, 0);
        return XDP_PASS;
    }

    /* Update shared map */
    __u32 dst_key = e->dst_ip;
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats_map, &dst_key);
    if (!stats) {
        struct flow_stats new_stats = {0};
        bpf_map_update_elem(&flow_stats_map, &dst_key, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&flow_stats_map, &dst_key);
    }

    if (stats) {
        __sync_fetch_and_add(&stats->total_bytes, e->pkt_len);
        stats->protocol = e->protocol;
        stats->dst_port = e->dst_port;
        stats->app_protocol = e->app_protocol;

        if (e->pkt_len > 8000) {
            __sync_fetch_and_add(&stats->large_packet_count, 1);
            if (stats->large_packet_count > 3) {
                stats->suspicious = 1;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

    /* Early drop policy */
    if (e->pkt_len > 9000 || (stats && stats->suspicious)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
