#!/usr/bin/env python3
"""
Simple Python userspace loader using BCC for the outbound_connection_tracer.bpf.c

This loader attaches the eBPF program and prints connection events.
In a real system this would forward events to the InlineProtectiveAgent.

Requires: pip install bcc
"""

from bcc import BPF
import ctypes
import time

# Load the eBPF program
b = BPF(src_file="outbound_connection_tracer.bpf.c")

# Define the event structure matching the eBPF program
class ConnectionEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("family", ctypes.c_uint8),
        ("daddr_v4", ctypes.c_uint32),
        ("daddr_v6", ctypes.c_ubyte * 16),
        ("dport", ctypes.c_uint16),
        ("timestamp", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
    ]

# Callback for ring buffer events
def handle_event(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(ConnectionEvent)).contents
    comm = event.comm.decode('utf-8', errors='replace').strip('\x00')

    if event.family == 2:  # AF_INET
        import socket
        ip = socket.inet_ntoa(ctypes.c_uint32(event.daddr_v4).value.to_bytes(4, 'big'))
        print(f"[{comm}] PID={event.pid} IPv4 connect -> {ip}:{event.dport}")
    elif event.family == 10:  # AF_INET6
        # Simple IPv6 print (full formatting can be improved)
        print(f"[{comm}] PID={event.pid} IPv6 connect -> port {event.dport}")
    else:
        print(f"[{comm}] PID={event.pid} Unknown family connect")

# Open the ring buffer
b["rb"].open_ring_buffer(handle_event)

print("eBPF outbound connection tracer loaded. Press Ctrl+C to exit...")

# Poll for events
try:
    while True:
        b.ring_buffer_poll()
        time.sleep(0.1)
except KeyboardInterrupt:
    print("\nExiting...")
    b.cleanup()