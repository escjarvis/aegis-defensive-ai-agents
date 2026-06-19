# Design Document — Inline Protective Agent for FortiGate Sentry 900G

## 1. System Overview
The Inline Protective Agent runs as a security service on FortiGate hardware equipped with the Sentry chip (900G). It acts as an intelligent HTTPS proxy/inspector specifically tuned for traffic to and from AI model endpoints (OpenAI, Azure OpenAI, local LLMs, etc.).

**Core Principle**: Everything happens in-line with minimal latency. The agent must decide "allow / block / sanitize / alert" within tight time budgets.

## 2. Data Flow
1. Client → FortiGate (HTTPS to AI endpoint)
2. Sentry chip / Inline Agent performs:
   - TLS termination / inspection (hardware accelerated)
   - Full request context assembly
   - Multi-layer detection (structural + behavioral)
3. Decision engine applies policy
4. (Optional) Sanitization or blocking
5. Forward to backend AI model (or return blocked response)

## 3. Module Breakdown

### 3.1 In-line Analysis Engine
- Real-time parsing of HTTP/2 or HTTP/1.1 over TLS
- Extraction of prompt, parameters, and context from JSON payloads
- Header and metadata analysis

### 3.2 Assembly Module
- Reassembly of chunked transfer encoding
- Handling of streaming responses (important for LLM token streaming)
- Context window reconstruction for long conversations

### 3.3 Sandboxing Module
- Lightweight sandbox for executing or emulating suspicious code/payloads
- Safe execution of JavaScript/Python snippets sometimes embedded in attacks
- Containerized or chip-level isolation where available

### 3.4 Morph Detection
- Detection of encoding transformations (base64, URL encoding, Unicode normalization attacks)
- Payload mutation tracking across requests
- Adversarial suffix/prefix detection

### 3.5 Evasion Detection
- Identification of known evasion techniques (prompt splitting, role-playing jailbreaks, encoding chains)
- Statistical anomaly in token distribution or structure
- Comparison against known evasion signatures

### 3.6 Behavior Model Detection
- Maintains a behavioral profile of "normal" interactions with each protected model
- Uses lightweight ML / statistical models or rule+ML hybrid
- Detects:
  - Unusual query volume or complexity
  - Data exfiltration patterns (long outputs, specific keywords in responses)
  - Drift in user/agent behavior
  - Coordinated multi-request attacks

## 4. Integration with FortiGate
- Security Profile extension or custom IPS/ WAF-like profile for AI traffic
- REST API for configuration and logging
- Logging to FortiAnalyzer / SIEM
- Hardware offload where possible via Sentry chip

## 5. Performance Requirements
- Sub-millisecond added latency for most traffic
- Hardware acceleration critical for TLS and deep inspection
- Scalable to high-throughput enterprise links

## 6. Future Enhancements
- On-chip ML inference for behavior models
- Tight integration with FortiAI / FortiGuard threat intelligence
- Automated playbook execution (containment, rate limiting, user challenge)

**JARVIS Note:** Keep the design ruthlessly focused on inline constraints. Every component must justify its latency cost.