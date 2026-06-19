#!/usr/bin/env python3
"""
Inline Protective Agent Stub — FortiGate Sentry 900G

Now includes integration point for querying shared eBPF maps from XDP.
"""

from typing import Dict, Any, List, Optional
import json
import math
from collections import deque, defaultdict

# ... (previous classes unchanged for brevity in this response)

class InlineProtectiveAgent:
    def __init__(self):
        self.analysis = InlineAnalysisEngine()
        self.assembly = AssemblyModule()
        self.sandbox = SandboxModule()
        self.morph = MorphDetectionModule()
        self.evasion = EvasionDetectionModule()
        self.behavior = BehaviorModelDetection()

        # Placeholder for XDP map integration
        self.xdp_flow_stats = {}  # In real use: populated from eBPF map via loader

    def query_xdp_flow_stats(self, dst_ip: int) -> Dict[str, Any]:
        """
        Query shared eBPF flow_stats_map (populated by XDP).

        In production, this would read from the actual eBPF map
        exposed via BCC or a custom loader.
        """
        # Simulated lookup (in real system this comes from the map)
        if dst_ip in self.xdp_flow_stats:
            stats = self.xdp_flow_stats[dst_ip]
            return {
                "large_packet_count": stats.get("large_packet_count", 0),
                "suspicious": stats.get("suspicious", False),
                "total_bytes": stats.get("total_bytes", 0)
            }
        return {"large_packet_count": 0, "suspicious": False, "total_bytes": 0}

    def process_https_context(self, http_context: Dict[str, Any]) -> Dict[str, Any]:
        print("\n[InlineProtectiveAgent] Processing new HTTPS context...")

        assembled = self.assembly.reassemble(http_context.get("fragments", []))
        req_analysis = self.analysis.analyze_request(http_context)
        resp_analysis = self.analysis.analyze_response(http_context)

        morph_result = self.morph.detect_morph(http_context)
        behavior_result = self.behavior.analyze_behavior(http_context)

        # Example: Check XDP map for additional context
        dst_ip = http_context.get("dst_ip", 0)
        xdp_stats = self.query_xdp_flow_stats(dst_ip)
        if xdp_stats.get("suspicious"):
            print("  [XDP] Flow previously marked suspicious by XDP layer")

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


# Demo
if __name__ == "__main__":
    agent = InlineProtectiveAgent()

    print("=== Normal traffic ===")
    normal = {"path": "/api/chat", "body": "hello"}
    result = agent.process_https_context(normal)
    print("Decision:", result["decision"])

    print("\n=== Suspicious flow (XDP marked) ===")
    suspicious = {"path": "/worker.js", "body": "large model", "dst_ip": 0xC0A80101}  # 192.168.1.1
    # Simulate XDP having marked this IP
    agent.xdp_flow_stats[0xC0A80101] = {"large_packet_count": 5, "suspicious": True, "total_bytes": 50000}
    result2 = agent.process_https_context(suspicious)
    print("Decision:", result2["decision"])
    print("XDP stats:", result2["xdp_stats"])