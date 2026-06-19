# raphabot/awesome-cybersecurity-agentic-ai — Defensive Highlights

**Source:** https://github.com/raphabot/awesome-cybersecurity-agentic-ai  
**Why it matters:** Best single curated list for agentic AI in cyber. Heavy emphasis on defensive tools, scanners, guardrails, and threat response. Excellent for discovering production-ready or near-ready protective components.

## Top Defensive / Protective Projects Extracted

### AI Agent Security & Testing
- **AgentFence** (https://github.com/agentfence/agentfence)  
  Open-source platform for automatically testing AI agent security. Detects prompt injection, secret leakage, system instruction exposure. Core defensive testing tool.

- **Inkog** (https://github.com/inkog-io/inkog)  
  AI agent security scanner. Audits agent code, MCP servers, multi-agent delegation for prompt injection, infinite loops, missing oversight. Maps to OWASP LLM/Agentic Top 10 and EU AI Act. SARIF output for CI/CD.

- **ShellWard** (https://github.com/jnMetaCode/shellward)  
  AI agent security middleware with 8-layer defense-in-depth. 32 prompt injection rules + DLP-style data flow tracking + dangerous command blocking. Works as SDK or OpenClaw plugin. Zero dependencies.

### Full Security Suites for Agents
- **OpenClaw Security Suite** (https://github.com/AtlasPA/openclaw-security)  
  11-tool suite for securing AI agent workspaces: integrity verification, secret scanning, prompt injection defense, supply chain analysis, network DLP, permission auditing, credential lifecycle, compliance, audit trails, cryptographic signing, incident response. Pure Python, local.

- **Aguara** (https://github.com/garagon/aguara)  
  Static security scanner for AI agent skills and MCP servers. 173 detection rules, 4 analysis layers (pattern matching, NLP, taint tracking, rug-pull detection). Offline & deterministic.

### Autonomous Cyberdefense Agents
- **AICA Agent** (https://github.com/aica-iwg/aica-agent)  
  Autonomous intelligent cyberdefense agent for research and production. Advanced detection, response, and management capabilities. Direct match for protective agent needs.

### Supporting / Specialised
- **ExposureGuard** tools (haldir, exposureguard-mcp) — Guardian layer with scoped sessions, encrypted secrets, audit, policy enforcement, domain security scanning.
- MCP servers for threat intel: VirusTotal, Shodan, dnstwist, urlDNA (phishing/malware URL analysis) — easy to wire into defensive agents.
- **brood-box** — CLI for running AI coding agents in hardware-isolated microVMs (strong sandboxing for defensive execution environments).

## Research & Frameworks Mentioned
- CyberBattleSim (Microsoft) for attack/defense simulation
- Multi-Agent Systems for Cybersecurity survey
- MAESTRO (CSA) threat modeling for agentic AI
- ATFAA/SHIELD framework for securing generative/agentic AI

## JARVIS Takeaway
Start here for discovery. Shortlist 3-5 tools that match your stack (e.g., ShellWard or Inkog for immediate guardrails + AICA or CAI for the agent brain). Many are lightweight and local-first — ideal for defensive posture without heavy cloud dependency.

**Action:** Cross-reference with `04-agent-protection/` for Cisco equivalents. Many overlap in philosophy (scanning + runtime defense).