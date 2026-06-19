# XDP Packet Inspection Exploration

**Context:** Inline Protective Agent for FortiGate Sentry 900G  
**Focus:** Early, high-performance packet inspection using XDP (eXpress Data Path)

## What is XDP?

XDP is a Linux kernel feature that allows eBPF programs to process packets at the **earliest possible point** in the network stack — right after the network driver receives the packet, before it enters the kernel's networking stack.

This makes XDP extremely attractive for inline security agents because it offers:
- Extremely low latency (can drop or redirect packets in nanoseconds)
- High throughput
- Ability to make decisions before expensive kernel processing occurs

## Relevance to the Inline Protective Agent

The current agent focuses on protecting AI models by inspecting HTTPS traffic for attack vectors (prompt injection, browser cache inference models, data exfiltration, morphing payloads, etc.).

XDP can provide **early filtering and metadata extraction** that feeds or accelerates the Python-based `InlineProtectiveAgent`.

### High-Value Use Cases

#### 1. Early Size-Based Filtering
- Large outbound or inbound transfers can be a strong signal of model artifact exfiltration or model delivery.
- XDP can drop or mark packets exceeding certain size thresholds very early.

#### 2. Basic Protocol & Header Inspection
- Extract Ethernet, IP, TCP/UDP, and basic HTTP/2 information at the earliest stage.
- Identify TLS handshake patterns or SNI (Server Name Indication) for domain reputation checks.

#### 3. Metadata Enrichment for Python Agent
- XDP programs can attach metadata (via packet metadata or shared maps) that the Python agent can consume.
- This reduces the amount of work the higher-layer Python code needs to do.

#### 4. Fast Path Blocking
- For clearly malicious patterns (known bad domains, anomalous request sizes, or known attack signatures), XDP can block traffic **before** it reaches the Python decision engine.

#### 5. Complement to Existing Modules
- Works together with:
  - `MorphDetectionModule` (early detection of suspicious resource loading)
  - `BehaviorModelDetection` (network behavior signals)
  - `SandboxModule` (context about what was transferred)

## Proposed Architecture

```
[ NIC ]
   |
   v
[XDP Program]  --> Early decision / metadata attachment
   |
   +--> Drop (malicious)
   +--> Pass + metadata --> Kernel Stack --> Python InlineProtectiveAgent
```

## Sample XDP Program Concept (Simplified)

```c
// Basic XDP stub concept (illustrative)
SEC("xdp")
int xdp_inspect(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Example: Drop very large packets (potential model transfer)
    if (bpf_ntohs(ip->tot_len) > 10000) {
        // Could log or increment a map counter here
        return XDP_DROP;
    }

    return XDP_PASS;
}
```

## Integration with Python Agent

- XDP can write to shared eBPF maps that the Python loader reads.
- Events can be sent via ring buffer (similar to the syscall and connection tracers).
- The Python agent can use XDP-derived metadata to make faster or more accurate decisions.

## Practical Considerations for FortiGate Sentry 900G

- Direct XDP programming on FortiGate hardware is likely restricted.
- More realistic paths:
  - Run supporting eBPF/XDP logic on Linux hosts in front of or behind FortiGate.
  - Use FortiGate features that internally leverage similar acceleration.
  - Develop hybrid solutions where XDP runs on adjacent infrastructure.

## Recommended Next Steps

1. Create a more complete XDP program stub (with ring buffer events).
2. Define what metadata XDP should extract for the protective agent.
3. Prototype a combined XDP + Python decision pipeline.
4. Evaluate performance impact on realistic traffic mixes (including LLM API traffic).

## Conclusion

XDP represents one of the most powerful tools available for achieving true **inline, low-latency** protection. While direct integration on FortiGate may be limited, the architectural concepts are highly relevant for evolving the agent toward production-grade performance.

**JARVIS Recommendation:** Strong area for continued investment if we want the agent to operate at the highest performance levels.