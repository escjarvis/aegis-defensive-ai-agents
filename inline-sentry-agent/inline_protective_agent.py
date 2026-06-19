#!/usr/bin/env python3
"""
Inline Protective Agent Stub — FortiGate Sentry 900G

Now includes real integration pattern for querying shared eBPF maps
populated by XDP programs.
"""

from typing import Dict, Any, List, Optional
import json
import math
from collections import deque, defaultdict

# ... (other classes remain the same)

class InlineProtectiveAgent:
    def __init__(self, xdp_maps: Optional[Dict] = None):
        self.analysis = InlineAnalysisEngine()
        self.assembly = AssemblyModule()
        self.sandbox = SandboxModule()
        self.morph = MorphDetectionModule()
        self.evasion = EvasionDetectionModule()
        self.behavior = BehaviorModelDetection()

        # Real integration point: XDP maps passed from loader
        self.xdp_maps = xdp_maps or {}

    def query_xdp_flow_stats(self, dst_ip: int) -> Dict[str, Any]:
        """
        Query the shared eBPF flow_stats_map populated by XDP.

        In production, this is called with the actual BCC map object.
        """
        flow_map = self.xdp_maps.get("flow_stats_map")
        if not flow_map:
            return {"large_packet_count": 0, "suspicious": False, "total_bytes": 0}

        try:
            stats = flow_map[dst_ip]
            return {
                "large_packet_count": getattr(stats, "large_packet_count", 0),
                "suspicious": bool(getattr(stats, "suspicious", 0)),
                "total_bytes": getattr(stats, "total_bytes", 0),
                "protocol": getattr(stats, "protocol", 0),
                "dst_port": getattr(stats, "dst_port", 0),
            }
        except KeyError:
            return {"large_packet_count": 0, "suspicious": False, "total_bytes": 0}

    def process_https_context(self, http_context: Dict[str, Any]) -> Dict[str, Any]:
        print("\n[InlineProtectiveAgent] Processing new HTTPS context...")

        assembled = self.assembly.reassemble(http_context.get("fragments", []))
        req_analysis = self.analysis.analyze_request(http_context)
        resp_analysis = self.analysis.analyze_response(http_context)

        morph_result = self.morph.detect_morph(http_context)
        behavior_result = self.behavior.analyze_behavior(http_context)

        # Query XDP shared map for additional context
        dst_ip = http_context.get("dst_ip", 0)
        xdp_stats = self.query_xdp_flow_stats(dst_ip)

        if xdp_stats.get("suspicious"):
            print(f"  [XDP] Flow marked suspicious by XDP (large packets: {xdp_stats.get('large_packet_count')})")

        if morph_result.get("total_risk", 0) > 0.5 or behavior_result.get("anomaly_score", 0) > 0.5:
            sandbox_result = self.sandbox.execute_safely(
                assembled.decode(errors="ignore"), 
                context=http_context
            )
        else:
            sandbox_result = {"executed": False, "decision": "skipped"}

        overall_risk = max(
            req_analysis.get("risk_score", 0),
            resp_analysis.get("risk_score", 0),
            morph_result.get("total_risk", 0),
            behavior_result.get("anomaly_score", 0),
            sandbox_result.get("risk_score", 0) if sandbox_result.get("executed") else 0
        )

        decision = "allow"
        if overall_risk > 0.8 or morph_result.get("morph_detected"):
            decision = "block"
        elif overall_risk > 0.5 or sandbox_result.get("decision") == "block":
            decision = "alert"

        return {
            "decision": decision,
            "overall_risk": round(overall_risk, 3),
            "sandbox": sandbox_result,
            "morph": morph_result,
            "behavior": behavior_result,
            "xdp_stats": xdp_stats
        }


# Demo with simulated map (in real use the map comes from BCC)
if __name__ == "__main__":
    # Simulate map data that would come from XDP
    class FakeStats:
        def __init__(self):
            self.large_packet_count = 5
            self.suspicious = 1
            self.total_bytes = 45000
            self.protocol = 6
            self.dst_port = 443

    fake_map = {0xC0A80101: FakeStats()}  # 192.168.1.1

    agent = InlineProtectiveAgent(xdp_maps={"flow_stats_map": fake_map})

    print("=== Normal traffic ===")
    normal = {"path": "/api/chat", "body": "hello"}
    result = agent.process_https_context(normal)
    print("Decision:", result["decision"])

    print("\n=== Traffic from XDP-suspicious flow ===")
    suspicious = {"path": "/worker.js", "body": "large model payload", "dst_ip": 0xC0A80101}
    result2 = agent.process_https_context(suspicious)
    print("Decision:", result2["decision"])
    print("XDP stats:", result2["xdp_stats"])