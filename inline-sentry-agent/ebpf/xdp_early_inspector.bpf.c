/*
 * xdp_early_inspector.bpf.c
 *
 * Enhanced with:
 * - Improved QUIC detection
 * - Basic TLS fingerprinting (JA3-style)
 * - SNI extraction for domain-based filtering
 * - Better app_protocol classification
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
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  app_protocol;     /* 1=HTTPS, 2=QUIC, 3=DNS, 4=AI_API */
    __u32 ja3_hash;         /* Simplified JA3 hash */
    char  sni[64];          /* Server Name Indication (truncated) */
    __u64 timestamp;
};

struct flow_stats {
    __u64 large_packet_count;
    __u64 total_bytes;
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

/* QUIC detection - improved heuristic */
static __always_inline int detect_quic(void *data, void *data_end)
{
    if (data + 1 > data_end) return 0;
    __u8 first = *(__u8 *)data;
    /* QUIC long header: 0b1100xxxx or short header patterns */
    if ((first & 0xC0) == 0xC0 || (first & 0x80) == 0x00)
        return 1;
    return 0;
}

/* Very simplified JA3-style fingerprinting (real JA3 needs full extension parsing) */
static __always_inline __u32 calculate_ja3(struct tcphdr *tcp, void *data_end)
{
    /* Placeholder - real implementation would hash TLS version + ciphers + extensions */
    return (__u32)((__u64)tcp->source << 16) | tcp->dest;
}

/* Extract SNI from TLS ClientHello (simplified) */
static __always_inline int extract_sni(void *data, void *data_end, char *sni, int max_len)
{
    /* This is a stub - full SNI parsing is complex in XDP */
    /* In practice we would walk TLS extensions */
    if (data + 10 > data_end) return 0;
    /* Placeholder: copy first few bytes as demo */
    __builtin_memcpy(sni, data, 8);
    sni[8] = 0;
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
    __u8 protocol = ip->protocol;

    struct xdp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return XDP_PASS;

    e->ifindex = ctx->ingress_ifindex;
    e->pkt_len = pkt_len;
    e->ip_version = 4;
    e->src_ip = ip->saddr;
    e->dst_ip = ip->daddr;
    e->protocol = protocol;
    e->timestamp = bpf_ktime_get_ns();
    e->ja3_hash = 0;
    e->app_protocol = 0;

    __u16 src_p = 0, dst_p = 0;
    void *l4 = (void *)ip + (ip->ihl * 4);

    if (parse_ports(l4, data_end, protocol, &src_p, &dst_p)) {
        e->src_port = src_p;
        e->dst_port = dst_p;
    }

    /* Protocol classification */
    if (protocol == IPPROTO_UDP && dst_p == 53) {
        e->app_protocol = 3; /* DNS */
    } else if (protocol == IPPROTO_UDP && dst_p == 443) {
        if (detect_quic(l4, data_end))
            e->app_protocol = 2; /* QUIC */
    } else if (protocol == IPPROTO_TCP && dst_p == 443) {
        e->app_protocol = 1; /* HTTPS */
        struct tcphdr *tcp = (struct tcphdr *)l4;
        if ((void *)(tcp + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }
        e->ja3_hash = calculate_ja3(tcp, data_end);
        extract_sni((void *)tcp + (tcp->doff * 4), data_end, e->sni, sizeof(e->sni));
    } else if (dst_p == 11434 || dst_p == 1234 || dst_p == 8000) {
        e->app_protocol = 4; /* AI/Agent API */
    }

    /* Update shared map */
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats_map, &e->dst_ip);
    if (!stats) {
        struct flow_stats new_stats = {0};
        bpf_map_update_elem(&flow_stats_map, &e->dst_ip, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&flow_stats_map, &e->dst_ip);
    }

    if (stats) {
        __sync_fetch_and_add(&stats->total_bytes, pkt_len);
        stats->app_protocol = e->app_protocol;
        if (pkt_len > 8000) {
            __sync_fetch_and_add(&stats->large_packet_count, 1);
            if (stats->large_packet_count > 3) stats->suspicious = 1;
        }
    }

    bpf_ringbuf_submit(e, 0);

    if (pkt_len > 9000 || (stats && stats->suspicious)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
