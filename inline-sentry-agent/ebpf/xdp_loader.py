#!/usr/bin/env python3
"""
Simple XDP loader using BCC for xdp_early_inspector.bpf.c

Attaches the XDP program to an interface and prints events from the ring buffer.

Usage example:
    python3 xdp_loader.py eth0

Requires: pip install bcc
"""

from bcc import BPF
import ctypes
import sys
import time

if len(sys.argv) != 2:
    print("Usage: python3 xdp_loader.py <interface>")
    sys.exit(1)

interface = sys.argv[1]

# Load the XDP program
b = BPF(src_file="xdp_early_inspector.bpf.c")

fn = b.load_func("xdp_early_inspect", BPF.XDP)

# Attach to interface
b.attach_xdp(interface, fn, 0)

print(f"XDP program attached to {interface}. Press Ctrl+C to exit...")

class XdpEvent(ctypes.Structure):
    _fields_ = [
        ("ifindex", ctypes.c_uint32),
        ("pkt_len", ctypes.c_uint32),
        ("ip_version", ctypes.c_uint8),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("timestamp", ctypes.c_uint64),
    ]

def handle_event(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(XdpEvent)).contents
    import socket
    src_ip = socket.inet_ntoa(ctypes.c_uint32(event.src_ip).value.to_bytes(4, 'big'))
    dst_ip = socket.inet_ntoa(ctypes.c_uint32(event.dst_ip).value.to_bytes(4, 'big'))
    print(f"[XDP] if={event.ifindex} len={event.pkt_len} {src_ip} -> {dst_ip}")

b["rb"].open_ring_buffer(handle_event)

try:
    while True:
        b.ring_buffer_poll()
        time.sleep(0.05)
except KeyboardInterrupt:
    print("\nDetaching XDP program...")
    b.remove_xdp(interface)
    b.cleanup()