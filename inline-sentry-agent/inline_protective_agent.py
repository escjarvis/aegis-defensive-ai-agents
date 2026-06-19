#!/usr/bin/env python3
"""
Inline Protective Agent with improved XDP integration
"""

from typing import Dict, Any, Optional

class InlineProtectiveAgent:
    def __init__(self, xdp_maps: Optional[Dict] = None):
        self.xdp_maps = xdp_maps or {}

    def query_xdp_flow_stats(self, dst_ip: int) -> Dict[str, Any]:
        flow_map = self.xdp_maps.get("flow_stats_map")
        if not flow_map:
            return {"large_packet_count": 0, "suspicious": False, "app_protocol": 0}
        try:
            stats = flow_map[dst_ip]
            return {
                "large_packet_count": getattr(stats, "large_packet_count", 0),
                "suspicious": bool(getattr(stats, "suspicious", 0)),
                "app_protocol": getattr(stats, "app_protocol", 0),
            }
        except KeyError:
            return {"large_packet_count": 0, "suspicious": False, "app_protocol": 0}

    def process_https_context(self, http_context: Dict[str, Any]) -> Dict[str, Any]:
        dst_ip = http_context.get("dst_ip", 0)
        xdp_stats = self.query_xdp_flow_stats(dst_ip)

        app_proto = xdp_stats.get("app_protocol", 0)
        decision = "allow"

        # React differently based on protocol
        if app_proto == 2:  # QUIC
            print("  [XDP] QUIC traffic detected")
        elif app_proto == 3:  # DNS
            print("  [XDP] DNS query detected")
        elif app_proto == 4:  # AI/Agent API
            print("  [XDP] AI/Agent API traffic")

        if xdp_stats.get("suspicious"):
            decision = "alert"

        return {
            "decision": decision,
            "xdp_stats": xdp_stats,
            "app_protocol": app_proto
        }


if __name__ == "__main__":
    class FakeStats:
        large_packet_count = 4
        suspicious = 1
        app_protocol = 2  # QUIC

    fake_map = {0xC0A80101: FakeStats()}
    agent = InlineProtectiveAgent(xdp_maps={"flow_stats_map": fake_map})

    result = agent.process_https_context({"dst_ip": 0xC0A80101})
    print("Decision:", result["decision"])
    print("App Protocol:", result["app_protocol"])