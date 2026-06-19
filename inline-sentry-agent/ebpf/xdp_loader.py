#!/usr/bin/env python3
"""
XDP loader with shared map access for tighter coupling with InlineProtectiveAgent.

Demonstrates reading/writing the shared flow_stats_map from userspace.
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

print(f"XDP program attached to {interface}")

# Access the shared map from Python
flow_stats_map = b.get_table("flow_stats_map")

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

def handle_event(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(XdpEvent)).contents
    dst_ip = event.dst_ip

    # Read from shared map
    try:
        stats = flow_stats_map[dst_ip]
        if stats.suspicious:
            print(f"  [!] Suspicious flow detected for dst_ip={dst_ip} (large packets: {stats.large_packet_count})")
    except KeyError:
        pass

    print(f"[XDP] len={event.pkt_len} dst={dst_ip}")

b["rb"].open_ring_buffer(handle_event)

try:
    while True:
        b.ring_buffer_poll()
        time.sleep(0.05)
except KeyboardInterrupt:
    print("\nDetaching XDP...")
    b.remove_xdp(interface)
    b.cleanup()