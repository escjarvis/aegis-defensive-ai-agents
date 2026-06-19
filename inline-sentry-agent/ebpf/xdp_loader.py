#!/usr/bin/env python3
"""
Enhanced XDP loader with basic integration hook for InlineProtectiveAgent.

This version demonstrates how XDP events can be consumed and forwarded
(or used to influence) the Python InlineProtectiveAgent.
"""

from bcc import BPF
import ctypes
import sys
import time

if len(sys.argv) != 2:
    print("Usage: python3 xdp_loader.py <interface>")
    sys.exit(1)

interface = sys.argv[1]

b = BPF(src_file="xdp_early_inspector.bpf.c")
fn = b.load_func("xdp_early_inspect", BPF.XDP)
b.attach_xdp(interface, fn, 0)

print(f"XDP early inspector attached to {interface}")

class XdpEvent(ctypes.Structure):
    _fields_ = [
        ("ifindex", ctypes.c_uint32),
        ("pkt_len", ctypes.c_uint32),
        ("ip_version", ctypes.c_uint8),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_ip_v6", ctypes.c_ubyte * 16),
        ("dst_ip_v6", ctypes.c_ubyte * 16),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("timestamp", ctypes.c_uint64),
    ]

def forward_to_agent(event):
    """
    Example integration point.
    In a real system this would call into InlineProtectiveAgent
    or update shared state / maps.
    """
    # Placeholder: could update a shared eBPF map or send via socket/gRPC
    if event.pkt_len > 5000:
        print(f"  -> Large packet detected ({event.pkt_len} bytes) - potential model transfer")

b["rb"].open_ring_buffer(lambda ctx, data, size: forward_to_agent(
    ctypes.cast(data, ctypes.POINTER(XdpEvent)).contents))

try:
    while True:
        b.ring_buffer_poll()
        time.sleep(0.05)
except KeyboardInterrupt:
    print("\nDetaching XDP...")
    b.remove_xdp(interface)
    b.cleanup()