# eBPF Integration Exploration

**Agent:** Inline Protective Agent (FortiGate Sentry 900G)  
**Branch:** `feature/inline-protective-agent-sentry-900g`  
**Date:** 2026-06-19

## Overview

eBPF (extended Berkeley Packet Filter) is a powerful Linux kernel technology that allows safe, efficient, and programmable packet processing, tracing, and security enforcement directly in the kernel with very low overhead.

While FortiGate is a proprietary appliance, exploring eBPF integration is valuable because:
- FortiGate runs on a hardened Linux base.
- eBPF can complement the Python-based inline agent with kernel-level visibility and enforcement.
- It aligns perfectly with the goals of low-latency inline protection, behavior analysis, and advanced sandboxing.

## Relevant Use Cases for This Agent

### 1. High-Performance Traffic Inspection & Context Extraction
- Use eBPF to perform early packet classification and metadata extraction at the kernel level before traffic reaches the Python agent.
- Extract key HTTPS context (SNI, HTTP method, path, content-type, request size) with minimal latency.
- Feed enriched context into the `InlineProtectiveAgent` for faster decision making.
- Particularly useful for detecting large model artifact transfers or inference traffic patterns.

**Benefit:** Reduces load on the Python layer and enables earlier blocking of suspicious flows.

### 2. Advanced Behavior & Morph Detection
- eBPF can trace network outbound connections, DNS queries, and connection patterns in real time.
- Detect anomalous outbound traffic that may indicate data exfiltration from browser-assembled inference models.
- Monitor for morphing behavior at the network level (sudden changes in connection patterns, new domains, unusual ports).
- Combine with the existing `MorphDetectionModule` and `BehaviorModelDetection` for multi-layer detection.

**Example signals eBPF can provide:**
- Unexpected outbound connections after loading a suspicious script/worker
- High-frequency small requests (potential model probing)
- Connections to known malicious infrastructure

### 3. Kernel-Level Sandboxing & Runtime Security
- Use eBPF + seccomp or Landlock to create lightweight kernel-enforced sandboxes for suspicious payloads.
- Trace syscalls made by processes spawned from analyzed content (e.g., if a payload attempts to execute code).
- Restrict file system access, network access, or specific syscalls for high-risk flows.
- This complements the existing `SandboxModule` (BrowserSandbox, GeneralPayloadSandbox, HybridStaticBehavioral).

**Advantage over userspace sandboxing:** Much lower overhead and stronger security guarantees.

### 4. Observability & Telemetry for the Protective Agent
- eBPF can provide rich, low-overhead telemetry on:
  - Process behavior
  - Network flows
  - File and memory access patterns
- This data can be used to train or tune the lightweight behavior models in `BehaviorModelDetection`.
- Export metrics to FortiAnalyzer or external SIEM for correlation with model attack events.

### 5. Traffic Steering & Policy Enforcement
- eBPF programs (via XDP or TC hooks) can redirect or drop traffic at the earliest possible point based on decisions from the Python agent.
- Useful for implementing dynamic blocking of malicious inference model traffic without relying solely on higher-layer proxies.

## Proposed Integration Architecture

```
[Network Traffic]
       |
       v
[eBPF XDP/TC Hook]  --> Early classification + metadata extraction
       |
       v
[FortiGate Inline Path] --> Python InlineProtectiveAgent
       |                           |
       |                           v
       |                    [SandboxModule + Sub-modules]
       |                    [MorphDetection]
       |                    [BehaviorModelDetection]
       |
       v
[eBPF Enforcement] <-- Decision feedback (allow/block/alert)
```

## Practical Considerations for FortiGate Sentry 900G

- **Direct eBPF on FortiGate**: Limited public APIs. Custom development would likely require Fortinet engineering involvement or use of supported FortiOS features that leverage eBPF internally.
- **Host-side eBPF**: More feasible if deploying the agent logic on a Linux host in front of or alongside FortiGate (e.g., using traffic mirroring or as a transparent proxy).
- **Hybrid approach**: Use eBPF on supporting Linux infrastructure to provide additional signals that feed the FortiGate-based agent.

## Recommended Next Steps

1. **Design a lightweight eBPF program** for extracting HTTPS metadata and basic behavioral signals (outbound connections, request patterns).
2. **Prototype syscall tracing** for the sandbox use case using eBPF.
3. **Define a data exchange format** between eBPF programs and the Python `InlineProtectiveAgent`.
4. **Evaluate performance impact** of eBPF hooks on inline traffic.

## Conclusion

eBPF offers significant potential to strengthen the inline protective agent, especially for:
- Ultra-low-latency detection
- Kernel-enforced sandboxing
- Rich behavioral telemetry for morphing inference model attacks

While direct integration on FortiGate hardware may be constrained, the concepts are highly relevant for future evolution of the agent or for hybrid deployments.

**JARVIS Recommendation:** This is a high-value area for deeper exploration if we want to push the performance and security boundaries of the inline agent.