#!/usr/bin/env python3
"""
Combined XDP Loader

Loads multiple XDP programs (early inspector + browser inference detector)
and exposes their shared maps for use by InlineProtectiveAgent.

This provides tighter coupling between XDP and the Python agent.
"""

from bcc import BPF
import ctypes
import sys
import time

if len(sys.argv) != 2:
    print("Usage: python3 combined_xdp_loader.py <interface>")
    sys.exit(1)

interface = sys.argv[1]

# Load both XDP programs
b = BPF(src_file="xdp_early_inspector.bpf.c")

fn1 = b.load_func("xdp_early_inspect", BPF.XDP)
b.attach_xdp(interface, fn1, 0)

# Load second program (browser inference focused)
b2 = BPF(src_file="browser_inference_xdp.bpf.c")
fn2 = b2.load_func("xdp_browser_inference_detect", BPF.XDP)
b2.attach_xdp(interface, fn2, 0)

print(f"Attached both XDP programs to {interface}")

# Expose maps
flow_stats_map = b.get_table("flow_stats_map")
browser_flow_map = b2.get_table("browser_flow_map")

print("Shared maps exposed:")
print("  - flow_stats_map")
print("  - browser_flow_map")

# Example: Pass maps to InlineProtectiveAgent
# from inline_protective_agent import InlineProtectiveAgent
# agent = InlineProtectiveAgent(xdp_maps={
#     "flow_stats_map": flow_stats_map,
#     "browser_flow_map": browser_flow_map
# })

print("\nPress Ctrl+C to exit...")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nDetaching XDP programs...")
    b.remove_xdp(interface)
    b2.remove_xdp(interface)
    b.cleanup()
    b2.cleanup()