#!/usr/bin/env python3
"""
Defensive AI Agent Template — Aegis Initiative
Inspired by CAI (aliasrobotics/CAI) ReACT + guardrails philosophy.

This is a minimal, dependency-light starting point.
When CAI is available, replace/extend the core loop with CAI agents, tools, and guardrails.

Mission: Demonstrate intake → reasoning → protective action for defensive scenarios
          (malicious activity, ransomware indicators, anomalous agent behaviour).

Run: python defensive-agent-template.py
"""

import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

# ============================================================
# CONFIG — Tune for your defensive posture
# ============================================================
AGENT_NAME = "Aegis-Defender-v0.1"
GUARDRAIL_ENABLED = True          # Simulate CAI-style guardrails
HITL_REQUIRED = True              # Human-in-the-loop for high-severity actions
MAX_ITERATIONS = 5

# Simple rule-based "threat intelligence" (expand with real YARA, ML, or CAI tools)
THREAT_RULES = {
    "ransomware": ["encrypt", "ransom", ".locked", "readme.txt", "bitcoin", "payment"],
    "malicious_agent": ["prompt injection", "tool abuse", "secret exfil", "infinite loop"],
    "offensive_activity": ["port scan", "privilege escalation", "lateral movement", "c2 beacon"]
}

def apply_guardrails(input_text: str) -> bool:
    """Simulate CAI guardrails. In real CAI this is native + configurable."""
    if not GUARDRAIL_ENABLED:
        return True
    blocked_keywords = ["rm -rf", "format", "delete all", "sudo rm"]
    for kw in blocked_keywords:
        if kw.lower() in input_text.lower():
            print(f"[GUARDRAIL] Blocked dangerous action pattern: {kw}")
            return False
    return True

def detect_threat(indicators: List[str]) -> Dict[str, Any]:
    """Core defensive reasoning — classify threat type and severity."""
    threat_type = "benign"
    severity = "low"
    matched = []

    text = " ".join(indicators).lower()

    for ttype, keywords in THREAT_RULES.items():
        for kw in keywords:
            if kw in text:
                matched.append(kw)
                threat_type = ttype
                if ttype == "ransomware":
                    severity = "critical"
                elif ttype in ["malicious_agent", "offensive_activity"]:
                    severity = "high"
                break

    return {
        "threat_type": threat_type,
        "severity": severity,
        "matched_indicators": matched,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

def protective_action(threat: Dict[str, Any]) -> Dict[str, Any]:
    """Execute or recommend defensive response. In production: integrate safe tools + approval."""
    action_plan = {
        "recommended_actions": [],
        "requires_approval": False,
        "status": "analysed"
    }

    if threat["severity"] == "critical":
        action_plan["recommended_actions"] = [
            "Isolate affected host/network segment",
            "Kill suspicious processes matching ransomware patterns",
            "Create forensic snapshot / memory dump",
            "Generate incident report for SOC"
        ]
        action_plan["requires_approval"] = True
        action_plan["status"] = "containment_recommended"

    elif threat["severity"] == "high":
        action_plan["recommended_actions"] = [
            "Increase monitoring / enable EDR rules for matched TTPs",
            "Block associated indicators (IPs, domains, hashes)",
            "Alert on-call analyst"
        ]
        action_plan["requires_approval"] = HITL_REQUIRED

    else:
        action_plan["recommended_actions"] = ["Log for review", "Continue baseline monitoring"]

    return action_plan

def defensive_agent_loop(threat_input: str) -> Dict[str, Any]:
    """Main ReACT-style defensive loop (simplified)."""
    print(f"\n[{AGENT_NAME}] Defensive cycle started at {datetime.now().isoformat()}")
    print(f"Input received: {threat_input[:120]}{'...' if len(threat_input) > 120 else ''}")

    if not apply_guardrails(threat_input):
        return {"status": "blocked_by_guardrail", "reason": "Dangerous pattern detected"}

    # Perception / Intake
    indicators = threat_input.split()  # In real: parse logs, alerts, agent traces, etc.

    # Reasoning
    threat_assessment = detect_threat(indicators)
    print(f"Threat Assessment: {json.dumps(threat_assessment, indent=2)}")

    # Action (protective)
    response = protective_action(threat_assessment)
    print(f"Protective Response Plan: {json.dumps(response, indent=2)}")

    # In full CAI: this would call tools, delegate to sub-agents, apply real guardrails, trace with Phoenix/OpenTelemetry
    full_output = {
        "agent": AGENT_NAME,
        "input_summary": threat_input[:200],
        "assessment": threat_assessment,
        "response_plan": response,
        "guardrails_applied": GUARDRAIL_ENABLED,
        "hitl_enforced": response.get("requires_approval", False)
    }

    print(f"\n[{AGENT_NAME}] Cycle complete. Output ready for review or automated execution (with approval).")
    return full_output

# ============================================================
# DEMO / TEST CASES
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("AEGIS DEFENSIVE AGENT TEMPLATE — DEMO RUN")
    print("=" * 60)

    # Test case 1: Ransomware-like indicators
    test_ransom = "Detected unusual file encryption activity on host-42. readme.txt created with bitcoin payment instructions. Multiple .locked files."
    result1 = defensive_agent_loop(test_ransom)
    print("\n--- RESULT 1 (Ransomware) ---")
    print(json.dumps(result1, indent=2))

    time.sleep(1)

    # Test case 2: Malicious agent behaviour
    test_agent = "AI coding agent attempted prompt injection to exfiltrate secrets via tool call and entered suspected infinite loop."
    result2 = defensive_agent_loop(test_agent)
    print("\n--- RESULT 2 (Malicious Agent) ---")
    print(json.dumps(result2, indent=2))

    print("\n" + "=" * 60)
    print("Template run complete. Extend this with real CAI agents, YARA integration,")
    print("or connection to malware analysis tools from 03-ransomware-intel/.")
    print("Add your own defensive playbooks in protective_action().")
    print("=" * 60)