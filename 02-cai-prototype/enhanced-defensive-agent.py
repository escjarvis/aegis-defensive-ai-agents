#!/usr/bin/env python3
"""
Enhanced Defensive AI Agent — Aegis v0.2
Builds on the original template with:
- Stronger ransomware detection (YARA-ready + behavioural patterns)
- Clear integration points for real CAI (aliasrobotics/CAI)
- Better structure for guardrails, tools, and multi-agent handoff
- Comments for LangChain/LiteLLM or direct CAI ReACT agents

Run: python enhanced-defensive-agent.py

Next evolution: Replace detect_threat + protective_action with CAI agents + real tools.
"""

import json
import time
from datetime import datetime
from typing import Dict, Any, List

# ============================================================
# CONFIG
# ============================================================
AGENT_NAME = "Aegis-Defender-v0.2-Enhanced"
GUARDRAIL_ENABLED = True
HITL_REQUIRED = True

# Expanded ransomware + malicious indicators (easy to extend with real YARA)
RANSOMWARE_INDICATORS = [
    "encrypt", "ransom", ".locked", "readme.txt", "bitcoin", "payment", 
    "your files", "decryption", "cryptolocker", "wannacry", "ryuk"
]

MALICIOUS_AGENT_INDICATORS = [
    "prompt injection", "tool abuse", "secret exfil", "infinite loop", 
    "jailbreak", "override instructions", "ignore previous"
]

def apply_guardrails(input_text: str) -> bool:
    """CAI-style guardrails. Extend with real CAI guardrail system when integrated."""
    if not GUARDRAIL_ENABLED:
        return True
    blocked = ["rm -rf /", "format c:", "delete everything", "sudo rm -rf"]
    for pattern in blocked:
        if pattern.lower() in input_text.lower():
            print(f"[GUARDRAIL BLOCK] Dangerous pattern detected: {pattern}")
            return False
    return True

def detect_threat_advanced(indicators: List[str]) -> Dict[str, Any]:
    """
    Enhanced threat detection.
    Ready for: YARA rule matching + behavioural ML + CAI reasoning.
    """
    text = " ".join(indicators).lower()
    matched = []
    threat_type = "benign"
    severity = "low"
    confidence = 0.6

    # Ransomware detection
    ransom_matches = [kw for kw in RANSOMWARE_INDICATORS if kw in text]
    if ransom_matches:
        matched.extend(ransom_matches)
        threat_type = "ransomware"
        severity = "critical"
        confidence = 0.85

    # Malicious AI agent detection
    agent_matches = [kw for kw in MALICIOUS_AGENT_INDICATORS if kw in text]
    if agent_matches and threat_type == "benign":
        matched.extend(agent_matches)
        threat_type = "malicious_agent"
        severity = "high"
        confidence = 0.75

    return {
        "threat_type": threat_type,
        "severity": severity,
        "matched_indicators": matched,
        "confidence": confidence,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "recommendation": "YARA scan recommended" if threat_type == "ransomware" else "Standard triage"
    }

def protective_action_enhanced(threat: Dict[str, Any]) -> Dict[str, Any]:
    """Protective response with clear playbooks. Ready for CAI tool calling."""
    plan = {
        "recommended_actions": [],
        "requires_approval": False,
        "status": "analysed",
        "playbook": None
    }

    if threat["severity"] == "critical":
        plan["recommended_actions"] = [
            "1. Isolate affected endpoint immediately (network segmentation)",
            "2. Kill processes matching ransomware behavioural patterns",
            "3. Create memory + disk snapshot for forensics",
            "4. Block associated hashes/domains via EDR/SIEM",
            "5. Generate full incident report + notify SOC"
        ]
        plan["requires_approval"] = True
        plan["status"] = "containment_recommended"
        plan["playbook"] = "RANSOMWARE_CRITICAL_v1"

    elif threat["severity"] == "high":
        plan["recommended_actions"] = [
            "Increase EDR monitoring on host",
            "Block observed indicators of compromise",
            "Alert on-call security analyst with context"
        ]
        plan["requires_approval"] = HITL_REQUIRED
        plan["playbook"] = "MALICIOUS_AGENT_HIGH_v1"

    else:
        plan["recommended_actions"] = ["Log event", "Continue baseline monitoring"]

    return plan

def defensive_agent_enhanced(threat_input: str) -> Dict[str, Any]:
    """Main enhanced defensive loop — designed for easy CAI upgrade."""
    print(f"\n[{AGENT_NAME}] Enhanced defensive cycle started")
    print(f"Input: {threat_input[:150]}{'...' if len(threat_input) > 150 else ''}")

    if not apply_guardrails(threat_input):
        return {"status": "blocked_by_guardrail"}

    indicators = threat_input.split()  # TODO: Replace with real log parser / CAI tool output

    assessment = detect_threat_advanced(indicators)
    print(f"Assessment: {json.dumps(assessment, indent=2)}")

    response = protective_action_enhanced(assessment)
    print(f"Response Plan: {json.dumps(response, indent=2)}")

    # === CAI INTEGRATION NOTES (for next evolution) ===
    # When using real CAI:
    # 1. Replace this function with a CAI Agent instance
    # 2. Give it tools: YARA scanner, process killer (sandboxed), report generator
    # 3. Use CAI's native guardrails + HITL
    # 4. Add ReACT reasoning + handoff to sub-agents (e.g., MalwareAnalystAgent)
    # Example future call:
    #   agent = CAIAgent(tools=[yara_tool, containment_tool], guardrails=...)
    #   result = agent.run(f"Analyze and respond to: {threat_input}")

    output = {
        "agent": AGENT_NAME,
        "assessment": assessment,
        "response_plan": response,
        "guardrails": GUARDRAIL_ENABLED,
        "hitl_required": response["requires_approval"],
        "next_step": "Integrate with CAI + real YARA engine for production"
    }
    return output

# ============================================================
# DEMO
# ============================================================
if __name__ == "__main__":
    print("=" * 65)
    print("AEGIS ENHANCED DEFENSIVE AGENT v0.2 — DEMO")
    print("=" * 65)

    # Ransomware test
    ransom_input = "Critical alert: Multiple files encrypted on srv-finance-07. New readme.txt with bitcoin wallet and 'pay to decrypt' instructions detected."
    result = defensive_agent_enhanced(ransom_input)
    print("\n--- RANSOMWARE TEST RESULT ---")
    print(json.dumps(result, indent=2))

    time.sleep(0.8)

    # Malicious agent test
    agent_input = "Security event: Autonomous coding agent attempted prompt injection to bypass restrictions and exfiltrate API keys via unauthorized tool call."
    result2 = defensive_agent_enhanced(agent_input)
    print("\n--- MALICIOUS AGENT TEST RESULT ---")
    print(json.dumps(result2, indent=2))

    print("\n" + "=" * 65)
    print("v0.2 complete. Ready for CAI integration or YARA rule loading.")
    print("See comments in code for exact upgrade path.")
    print("=" * 65)