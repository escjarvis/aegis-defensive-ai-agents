#!/usr/bin/env python3
"""
Enhanced Defensive AI Agent — Aegis v0.3 (YARA Integrated)
- Strong ransomware detection with optional real YARA scanning
- Graceful fallback if yara-python not installed
- Clear CAI integration roadmap
- Ready for production defensive pipelines

Run: python enhanced-defensive-agent.py
Install YARA support: pip install yara-python
"""

import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

# ============================================================
# OPTIONAL YARA INTEGRATION
# ============================================================
YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# Embedded sample ransomware YARA rule (expand with real rules from ties2/malware-ai-agent or external)
RANSOMWARE_YARA_RULES = """
rule Ransomware_Generic_Behaviour {
    meta:
        description = "Detects common ransomware patterns (file encryption + ransom note)"
        author = "Aegis Defensive AI"
        date = "2026-06-19"
    strings:
        $encrypt = "encrypt" ascii wide
        $ransom = "ransom" ascii wide
        $locked = ".locked" ascii wide
        $readme = "readme.txt" ascii wide
        $bitcoin = "bitcoin" ascii wide
        $pay = "pay to decrypt" ascii wide nocase
    condition:
        3 of them
}
"""

def load_yara_rules() -> Optional[Any]:
    """Load YARA rules. Returns compiled rules or None."""
    if not YARA_AVAILABLE:
        return None
    try:
        rules = yara.compile(source=RANSOMWARE_YARA_RULES)
        return rules
    except Exception as e:
        print(f"[YARA] Failed to compile rules: {e}")
        return None

def scan_with_yara(data: str, rules: Any) -> List[str]:
    """Scan input with YARA. Returns list of matched rule names."""
    if not rules:
        return []
    try:
        matches = rules.match(data=data)
        return [match.rule for match in matches]
    except Exception as e:
        print(f"[YARA] Scan error: {e}")
        return []

# ============================================================
# CONFIG
# ============================================================
AGENT_NAME = "Aegis-Defender-v0.3-YARA"
GUARDRAIL_ENABLED = True
HITL_REQUIRED = True

RANSOMWARE_INDICATORS = [
    "encrypt", "ransom", ".locked", "readme.txt", "bitcoin", "payment", 
    "your files", "decryption", "cryptolocker", "wannacry", "ryuk"
]

MALICIOUS_AGENT_INDICATORS = [
    "prompt injection", "tool abuse", "secret exfil", "infinite loop", 
    "jailbreak", "override instructions", "ignore previous"
]

yara_rules = load_yara_rules()

def apply_guardrails(input_text: str) -> bool:
    if not GUARDRAIL_ENABLED:
        return True
    blocked = ["rm -rf /", "format c:", "delete everything", "sudo rm -rf"]
    for pattern in blocked:
        if pattern.lower() in input_text.lower():
            print(f"[GUARDRAIL BLOCK] Dangerous pattern: {pattern}")
            return False
    return True

def detect_threat_advanced(indicators: List[str], raw_input: str = "") -> Dict[str, Any]:
    """
    Enhanced detection with YARA boost for ransomware.
    """
    text = " ".join(indicators).lower()
    matched = []
    threat_type = "benign"
    severity = "low"
    confidence = 0.6
    yara_matches = []

    # YARA scan (if available)
    if YARA_AVAILABLE and yara_rules and raw_input:
        yara_matches = scan_with_yara(raw_input, yara_rules)
        if yara_matches:
            matched.extend(yara_matches)
            threat_type = "ransomware"
            severity = "critical"
            confidence = 0.95
            print(f"[YARA] Matched rules: {yara_matches}")

    # Keyword fallback / enrichment
    ransom_matches = [kw for kw in RANSOMWARE_INDICATORS if kw in text]
    if ransom_matches and threat_type != "ransomware":
        matched.extend(ransom_matches)
        threat_type = "ransomware"
        severity = "critical"
        confidence = max(confidence, 0.85)

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
        "yara_matches": yara_matches,
        "confidence": round(confidence, 2),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "yara_available": YARA_AVAILABLE,
        "recommendation": "YARA confirmed ransomware" if yara_matches else "YARA scan recommended" if threat_type == "ransomware" else "Standard triage"
    }

def protective_action_enhanced(threat: Dict[str, Any]) -> Dict[str, Any]:
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
    print(f"\n[{AGENT_NAME}] Enhanced defensive cycle started (YARA: {'enabled' if YARA_AVAILABLE else 'not installed - using keyword fallback'})")
    print(f"Input: {threat_input[:140]}{'...' if len(threat_input) > 140 else ''}")

    if not apply_guardrails(threat_input):
        return {"status": "blocked_by_guardrail"}

    indicators = threat_input.split()
    assessment = detect_threat_advanced(indicators, raw_input=threat_input)
    print(f"Assessment: {json.dumps(assessment, indent=2)}")

    response = protective_action_enhanced(assessment)
    print(f"Response Plan: {json.dumps(response, indent=2)}")

    # === CAI INTEGRATION ROADMAP ===
    # 1. Replace core logic with real CAI Agent
    # 2. Register YARA scan as a tool
    # 3. Add containment tools (sandboxed)
    # 4. Use CAI guardrails + Phoenix tracing
    # 5. Enable multi-agent handoff (see ransomware_response_swarm.py)

    output = {
        "agent": AGENT_NAME,
        "assessment": assessment,
        "response_plan": response,
        "guardrails": GUARDRAIL_ENABLED,
        "hitl_required": response["requires_approval"],
        "yara_status": "active" if YARA_AVAILABLE else "fallback (install yara-python)",
        "next_step": "Integrate with real CAI + full YARA ruleset + multi-agent swarm"
    }
    return output

# ============================================================
# DEMO
# ============================================================
if __name__ == "__main__":
    print("=" * 70)
    print("AEGIS ENHANCED DEFENSIVE AGENT v0.3 — YARA INTEGRATED DEMO")
    print("=" * 70)

    ransom_input = "Critical alert: Multiple files encrypted on srv-finance-07. New readme.txt with bitcoin wallet and 'pay to decrypt' instructions detected."
    result = defensive_agent_enhanced(ransom_input)
    print("\n--- RANSOMWARE + YARA TEST ---")
    print(json.dumps(result, indent=2))

    time.sleep(0.7)

    agent_input = "Security event: Autonomous coding agent attempted prompt injection to bypass restrictions and exfiltrate API keys via unauthorized tool call."
    result2 = defensive_agent_enhanced(agent_input)
    print("\n--- MALICIOUS AGENT TEST ---")
    print(json.dumps(result2, indent=2))

    print("\n" + "=" * 70)
    print("v0.3 complete. YARA integration active (or graceful fallback).")
    print("Install 'yara-python' for full rule-based ransomware confirmation.")
    print("=" * 70)