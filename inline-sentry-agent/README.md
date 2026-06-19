# Inline Protective Agent — FortiGate Sentry 900G

**Branch:** `feature/inline-protective-agent-sentry-900g`  
**Focus:** In-line defensive AI agent running on Fortinet FortiGate Sentry chip hardware (900G series)

## Mission
Build a high-performance, hardware-accelerated in-line protective agent that proxies and inspects HTTPS traffic to detect and mitigate **model attack vectors** targeting AI/LLM systems.

The agent operates transparently in the data path on FortiGate hardware, performing real-time analysis without introducing significant latency.

## Key Capabilities (Current Focus)
- **In-line Analysis**: Deep packet/context inspection of HTTPS requests/responses to AI models
- **Assembly**: Reassembly of fragmented or chunked HTTPS payloads for complete context
- **Sandboxing**: Safe execution/analysis of suspicious payloads or code in isolated environments
- **Morph Detection**: Identification of payload mutation, obfuscation, or adversarial transformations
- **Evasion Detection**: Detection of techniques designed to bypass traditional security controls
- **Behavior Model Detection**: Anomaly and behavioral analysis of queries/responses against learned "normal" model interaction patterns

## Hardware Context
- **Platform**: Fortinet FortiGate with Sentry chip (900G series)
- **Capabilities leveraged**: Hardware-accelerated SSL/TLS inspection, deep packet inspection (DPI), custom security processing on Sentry chip
- **Integration points**: FortiOS REST API, CLI scripting, custom security profiles, or direct chip-level hooks where available

## Model Attack Vectors Addressed
- Prompt injection / jailbreaks in LLM API calls
- Data exfiltration via crafted model queries or responses
- Model poisoning or backdoor activation through API traffic
- Adversarial examples in multimodal or text inputs
- Evasion of content filters via encoding, morphing, or context manipulation

## Current Status
This branch contains the initial design and stub implementation. The agent is designed to be lightweight enough for inline deployment while powerful enough for sophisticated behavioral and structural analysis.

## Next Steps on This Branch
1. Flesh out the core detection modules
2. Define interfaces for FortiGate integration
3. Prototype sandbox and morph detection components
4. Integrate behavior model (anomaly detection) logic
5. Performance testing and latency benchmarks for inline operation

**JARVIS:** This is a specialized, hardware-constrained defensive capability. Ruthless focus on low-latency, high-accuracy inline protection.