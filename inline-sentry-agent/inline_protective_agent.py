#!/usr/bin/env python3
"""
Inline Protective Agent Stub — FortiGate Sentry 900G

Focus: Detection of sophisticated browser-based malicious inference model attacks.
Attackers use compromised/malicious websites to assemble inference models in the victim's browser cache.
These models morph over time to evade detection.

Detection relies on:
- Behavior analysis of browser traffic patterns
- Analysis of model-related outbound network traffic
- Detection of morphing (adaptive structural changes)

Lightweight design for inline hardware deployment.
"""

from typing import Dict, Any, List, Optional
import json
import math
from collections import deque, defaultdict

# ============================================================
# ENHANCED MORPH DETECTION MODULE
# Focus: Browser Cache Inference Model Attacks + Morphing Evasion
# ============================================================

class MorphDetectionModule:
    """
    Advanced morph detection for browser-assembled malicious inference models.

    Detects:
    - Browser cache-based model assembly (resource-heavy, patterned requests)
    - Morphing behavior: structural/encoding changes over time to evade detection
    - Anomalous outbound traffic patterns indicative of inference model usage
    - Cache manipulation and timing-based side-channel signals
    """

    def __init__(self, history_window: int = 8):
        self.history_window = history_window
        self.domain_history = defaultdict(lambda: deque(maxlen=history_window))
        self.global_morph_signals = deque(maxlen=20)

    def _extract_browser_features(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features relevant to browser cache inference model attacks."""
        headers = context.get("headers", {})
        body = context.get("body", "")
        path = context.get("path", "")
        method = context.get("method", "GET")

        features = {
            "is_cache_related": False,
            "resource_type": "unknown",
            "request_size": len(body),
            "has_cache_headers": False,
            "timing_anomaly": False,
            "structural_hash": hash(body[:200] if body else path),  # Simple structural signature
        }

        # Detect cache-related headers (common in model assembly / cache probing)
        cache_headers = ["if-none-match", "if-modified-since", "cache-control", "pragma"]
        if any(h.lower() in headers for h in cache_headers):
            features["has_cache_headers"] = True
            features["is_cache_related"] = True

        # Resource type inference (scripts, workers, fonts, images often used in browser ML)
        if ".js" in path or "worker" in path.lower():
            features["resource_type"] = "script_or_worker"
        elif any(ext in path for ext in [".wasm", ".onnx", ".bin", ".model"]):
            features["resource_type"] = "model_artifact"
        elif path.endswith((".png", ".jpg", ".webp", ".svg")):
            features["resource_type"] = "image"

        # Detect large or repetitive outbound patterns (model inference traffic)
        if method == "POST" and features["request_size"] > 500:
            features["potential_inference_traffic"] = True
        else:
            features["potential_inference_traffic"] = False

        return features

    def _detect_morphing(self, domain: str, current_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect if the request structure is morphing compared to previous requests to the same domain.
        This is a key signal for adaptive evasion in browser-assembled models.
        """
        history = self.domain_history[domain]
        if len(history) < 2:
            history.append(current_features)
            return {"morph_detected": False, "morph_score": 0.0, "changes": []}

        previous = history[-1]
        changes = []
        morph_score = 0.0

        # Structural morphing (different body/path signature)
        if current_features.get("structural_hash") != previous.get("structural_hash"):
            changes.append("structural_signature_changed")
            morph_score += 0.35

        # Resource type switching (common in morphing attacks)
        if current_features.get("resource_type") != previous.get("resource_type"):
            changes.append("resource_type_switch")
            morph_score += 0.25

        # Cache header behavior change
        if current_features.get("has_cache_headers") != previous.get("has_cache_headers"):
            changes.append("cache_header_behavior_changed")
            morph_score += 0.2

        # Sudden size or method change (potential model inference activation)
        if abs(current_features.get("request_size", 0) - previous.get("request_size", 0)) > 300:
            changes.append("significant_size_change")
            morph_score += 0.3

        history.append(current_features)

        morph_detected = morph_score > 0.4
        if morph_detected:
            self.global_morph_signals.append({
                "domain": domain,
                "score": morph_score,
                "changes": changes
            })

        return {
            "morph_detected": morph_detected,
            "morph_score": round(morph_score, 3),
            "changes": changes
        }

    def detect_morph(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for enhanced morph detection.

        Focuses on browser cache inference model attacks and morphing evasion.
        """
        domain = context.get("host", context.get("path", "unknown"))
        features = self._extract_browser_features(context)
        morph_result = self._detect_morphing(domain, features)

        # Additional behavioral signals for browser inference models
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

        # Aggregate morph + inference risk
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


# ============================================================
# BEHAVIOR MODEL DETECTION (kept from previous enhancement)
# ============================================================

class BehaviorModelDetection:
    def __init__(self, window_size: int = 10, z_threshold: float = 2.5):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self.history = deque(maxlen=window_size)
        self.feature_history = deque(maxlen=window_size)
        self.baseline = {
            "prompt_len_mean": 0.0,
            "prompt_len_std": 1.0,
            "response_len_mean": 0.0,
            "response_len_std": 1.0,
            "special_char_ratio_mean": 0.0,
            "special_char_ratio_std": 0.1,
        }

    def _extract_features(self, context: Dict[str, Any]) -> Dict[str, float]:
        prompt = context.get("prompt", "") or context.get("body", "")
        response = context.get("response", "")
        prompt_len = len(prompt)
        response_len = len(response)

        if prompt_len > 0:
            special_chars = sum(1 for c in prompt if not c.isalnum() and not c.isspace())
            special_char_ratio = special_chars / prompt_len
        else:
            special_char_ratio = 0.0

        entropy = self._approx_entropy(prompt) if prompt else 0.0

        jailbreak_keywords = ["ignore previous", "ignore all", "you are now", "act as", "roleplay", "jailbreak"]
        exfil_keywords = ["exfiltrate", "dump", "show all", "list all", "output everything", "reveal"]

        jailbreak_score = sum(1 for kw in jailbreak_keywords if kw.lower() in prompt.lower())
        exfil_score = sum(1 for kw in exfil_keywords if kw.lower() in (prompt + response).lower())

        return {
            "prompt_len": float(prompt_len),
            "response_len": float(response_len),
            "special_char_ratio": special_char_ratio,
            "entropy": entropy,
            "jailbreak_score": float(jailbreak_score),
            "exfil_score": float(exfil_score),
        }

    def _approx_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _update_baseline(self, features: Dict[str, float]):
        alpha = 0.1
        for key in ["prompt_len", "response_len", "special_char_ratio"]:
            if key in features:
                mean_key = f"{key}_mean"
                std_key = f"{key}_std"
                old_mean = self.baseline[mean_key]
                new_mean = old_mean * (1 - alpha) + features[key] * alpha
                self.baseline[mean_key] = new_mean
                variance = (features[key] - old_mean) ** 2
                old_std = self.baseline[std_key]
                self.baseline[std_key] = old_std * (1 - alpha) + math.sqrt(variance) * alpha

    def _z_score(self, value: float, mean: float, std: float) -> float:
        if std < 0.001:
            return 0.0
        return abs(value - mean) / std

    def analyze_behavior(self, context: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_features(context)
        self._update_baseline(features)
        self.feature_history.append(features)

        anomaly_signals = []
        total_anomaly_score = 0.0

        z_prompt = self._z_score(features["prompt_len"], self.baseline["prompt_len_mean"], self.baseline["prompt_len_std"])
        z_response = self._z_score(features["response_len"], self.baseline["response_len_mean"], self.baseline["response_len_std"])
        z_special = self._z_score(features["special_char_ratio"], self.baseline["special_char_ratio_mean"], self.baseline["special_char_ratio_std"])

        if z_prompt > self.z_threshold:
            anomaly_signals.append(f"Unusual prompt length (z={z_prompt:.1f})")
            total_anomaly_score += min(z_prompt / 3, 1.0)
        if z_response > self.z_threshold * 1.2:
            anomaly_signals.append(f"Unusual response length (z={z_response:.1f})")
            total_anomaly_score += min(z_response / 4, 1.0)
        if z_special > self.z_threshold:
            anomaly_signals.append(f"High special character ratio (possible obfuscation) (z={z_special:.1f})")
            total_anomaly_score += min(z_special / 2.5, 1.0)

        if features["jailbreak_score"] >= 2:
            anomaly_signals.append("Multiple jailbreak keywords detected")
            total_anomaly_score += 0.6
        if features["exfil_score"] >= 1:
            anomaly_signals.append("Data exfiltration indicators in prompt or response")
            total_anomaly_score += 0.7
        if features["entropy"] > 4.5 and features["prompt_len"] > 50:
            anomaly_signals.append("High entropy prompt (possible encoded/obfuscated attack)")
            total_anomaly_score += 0.4

        if len(self.feature_history) >= 3:
            recent_prompts = [f["prompt_len"] for f in list(self.feature_history)[-3:]]
            if max(recent_prompts) > 3 * min(recent_prompts) and min(recent_prompts) > 10:
                anomaly_signals.append("Rapid escalation in prompt complexity (possible iterative jailbreak)")
                total_anomaly_score += 0.5

        final_score = min(total_anomaly_score, 1.0)
        is_anomalous = final_score > 0.45 or len(anomaly_signals) >= 2

        recommendation = "allow"
        if is_anomalous:
            if final_score > 0.75 or any("exfil" in s.lower() for s in anomaly_signals):
                recommendation = "block"
            else:
                recommendation = "alert"

        return {
            "anomaly_score": round(final_score, 3),
            "is_anomalous": is_anomalous,
            "signals": anomaly_signals,
            "features": features,
            "recommendation": recommendation,
            "baseline": {k: round(v, 2) for k, v in self.baseline.items()}
        }


# ============================================================
# REMAINING MODULES (lightweight stubs)
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

class SandboxModule:
    def execute_safely(self, payload: str, language: str = "python") -> Dict[str, Any]:
        print(f"[Sandbox] Executing payload in isolated environment ({language})...")
        return {"executed": True, "output": "sandbox_result", "risk": "low"}

class EvasionDetectionModule:
    def detect_evasion(self, context: Dict[str, Any]) -> Dict[str, Any]:
        print("[Evasion] Scanning for evasion patterns...")
        return {"evasion_detected": False, "confidence": 0.0}

class InlineProtectiveAgent:
    def __init__(self):
        self.analysis = InlineAnalysisEngine()
        self.assembly = AssemblyModule()
        self.sandbox = SandboxModule()
        self.morph = MorphDetectionModule()          # Enhanced for browser inference attacks
        self.evasion = EvasionDetectionModule()
        self.behavior = BehaviorModelDetection()

    def process_https_context(self, http_context: Dict[str, Any]) -> Dict[str, Any]:
        print("\n[InlineProtectiveAgent] Processing new HTTPS context...")

        assembled = self.assembly.reassemble(http_context.get("fragments", []))
        req_analysis = self.analysis.analyze_request(http_context)
        resp_analysis = self.analysis.analyze_response(http_context)

        morph_result = self.morph.detect_morph(http_context)   # Now much stronger
        evasion_result = self.evasion.detect_evasion(http_context)
        behavior_result = self.behavior.analyze_behavior(http_context)

        if req_analysis.get("risk_score", 0) > 0.7:
            sandbox_result = self.sandbox.execute_safely(assembled.decode(errors="ignore"))
        else:
            sandbox_result = {"executed": False}

        overall_risk = max(
            req_analysis.get("risk_score", 0),
            resp_analysis.get("risk_score", 0),
            morph_result.get("total_risk", 0),
            behavior_result.get("anomaly_score", 0)
        )

        decision = "allow"
        if overall_risk > 0.8 or morph_result.get("morph_detected"):
            decision = "block"
        elif overall_risk > 0.5 or behavior_result.get("is_anomalous"):
            decision = "alert"

        return {
            "decision": decision,
            "overall_risk": round(overall_risk, 3),
            "analysis": req_analysis,
            "morph": morph_result,
            "evasion": evasion_result,
            "behavior": behavior_result,
            "sandbox": sandbox_result
        }


# ============================================================
# DEMO
# ============================================================
if __name__ == "__main__":
    agent = InlineProtectiveAgent()

    print("=== Normal browsing ===")
    normal = {
        "host": "news.example.com",
        "path": "/article",
        "method": "GET",
        "headers": {"cache-control": "max-age=3600"},
        "body": ""
    }
    result_normal = agent.process_https_context(normal)
    print("Decision:", result_normal["decision"])
    print("Morph risk:", result_normal["morph"]["total_risk"])

    print("\n=== Suspicious browser inference model assembly (morphing) ===")
    suspicious = {
        "host": "malicious-tracker.example",
        "path": "/worker.js",
        "method": "POST",
        "headers": {"if-none-match": "W/\"abc123\""},
        "body": "large_model_payload_here",
        "request_size": 1200
    }
    result_suspicious = agent.process_https_context(suspicious)
    print("Decision:", result_suspicious["decision"])
    print("Morph detected:", result_suspicious["morph"]["morph_detected"])
    print("Morph score:", result_suspicious["morph"]["morph_score"])
    print("Inference signals:", result_suspicious["morph"]["inference_signals"])