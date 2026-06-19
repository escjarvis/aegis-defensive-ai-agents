# eBPF Programs for Inline Protective Agent

This directory contains sample eBPF programs that can complement the Python-based
`InlineProtectiveAgent` running on or alongside FortiGate Sentry 900G hardware.

## Current Samples

### `outbound_connection_tracer.bpf.c`

**Purpose:** Trace outbound `connect()` syscalls to detect potential data exfiltration
originating from browser-assembled malicious inference models.

**Key Features:**
- Captures destination IP, port, process name, PID/TGID, and timestamp
- Uses ring buffer for efficient event delivery to userspace
- Lightweight and focused on network exfiltration signals

**Integration Ideas:**
- The userspace loader (in C or Python using `bcc` or `libbpf`) can forward events
to the Python `InlineProtectiveAgent` via gRPC, shared memory, or a simple socket.
- Events can be correlated with the `MorphDetectionModule` and `BehaviorModelDetection`
  to raise the overall risk score when suspicious outbound connections appear after
  loading suspicious scripts or model artifacts.

**Limitations (Stub):**
- Currently only handles IPv4 `connect()`
- Does not yet include connection duration or data volume
- Needs a userspace component to consume the ring buffer

## Future Samples (Potential)

- Packet metadata extractor (XDP/TC) for early HTTPS context
- Syscall filtering / sandbox enforcement (for the SandboxModule)
- DNS query tracing for domain reputation checks
- File access tracing for sandboxed payload analysis

## Compilation Notes

This stub uses modern CO-RE (Compile Once - Run Everywhere) style with `vmlinux.h`.
It can be compiled with `clang` + `libbpf` or using `bpftrace` for rapid prototyping.

Example compilation (simplified):
```bash
gcc -o loader loader.c -lbpf
```

## Recommended Next Steps

1. Implement a simple userspace loader that prints or forwards events.
2. Add IPv6 and UDP support.
3. Correlate eBPF events with specific HTTP contexts in the Python agent.
4. Explore XDP for even earlier traffic decisions.