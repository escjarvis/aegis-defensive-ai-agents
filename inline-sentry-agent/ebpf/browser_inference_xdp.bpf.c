/*
 * browser_inference_xdp.bpf.c
 *
 * XDP program focused on early detection of browser cache inference model attacks.
 *
 * Looks for patterns associated with malicious websites assembling inference models
 * in the victim's browser (frequent resource loading, large model artifacts,
 * suspicious outbound patterns).
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
    __u8  is_suspicious_resource;  /* .js, .wasm, worker, etc. */
    __u64 timestamp;
};

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
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 pkt_len = ctx->data_end - ctx->data;

    struct inference_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return XDP_PASS;

    e->ifindex = ctx->ingress_ifindex;
    e->pkt_len = pkt_len;
    e->dst_ip = ip->daddr;
    e->timestamp = bpf_ktime_get_ns();
    e->is_large_transfer = (pkt_len > 8000) ? 1 : 0;
    e->is_suspicious_resource = 0;

    /* Simple heuristic: large transfer or common model-related ports */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS;
        }
        e->dst_port = bpf_ntohs(tcp->dest);

        /* Heuristic for web/worker traffic */
        if (e->dst_port == 443 || e->dst_port == 80) {
            if (pkt_len > 2000 || e->is_large_transfer)
                e->is_suspicious_resource = 1;
        }
    }

    bpf_ringbuf_submit(e, 0);

    /* Early drop for very large suspicious transfers */
    if (e->is_large_transfer && e->is_suspicious_resource)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
