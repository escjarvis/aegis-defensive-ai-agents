# CAI Prototype — Fastest Path to Custom Defensive Agents

**Framework:** aliasrobotics/CAI (https://github.com/aliasrobotics/CAI)  
**Why recommended:** Lightweight, battle-tested in CTFs and real assessments. Explicit support for **defensive automation** (mitigation, detection, incident response, ransomware containment). Built-in guardrails, HITL, tracing, and ReACT agent model. 9k+ stars and active.

## Quick Start (When Online)
1. Clone into `external/` or your preferred location
2. Follow official setup (supports Ollama for local models — air-gapped friendly)
3. `pip install -e .` or use their CLI
4. Explore `examples/` and `benchmarks/`

**Key defensive strengths from reconnaissance:**
- Agent-based architecture for specialised defensive roles (monitor → detect → respond)
- Guardrails against prompt injection and dangerous commands (critical for protective agents)
- Human-in-the-loop via Ctrl+C or explicit approval
- Tools for reconnaissance, but easily extended or restricted to defensive toolsets only
- Proven in OT CTF and real vulnerability validation

## This Prototype Template
- `defensive-agent-template.py` — Minimal starting point you can run/extend immediately. Demonstrates a basic defensive loop (threat intake → reasoning → protective action). 
- Expand it by:
  - Wiring in CAI tools or custom defensive tools (YARA scan, process isolation playbooks, report generation)
  - Adding specific ransomware indicators (file encryption patterns, ransom notes, C2 beacons)
  - Layering guardrails and observability
  - Connecting to malware analysis agents (see `03-ransomware-intel/`)

## Defensive Use Cases to Prototype
1. **Threat Intake Agent** — Ingest logs/alerts → classify (malicious / ransomware / benign) → escalate or auto-contain
2. **Ransomware Response Agent** — Detect indicators → generate containment playbook (kill processes, isolate network, snapshot) → human approval gate
3. **Agent Guardian** — Monitor other AI agents for anomalous behaviour (using patterns from ATR or ShellWard rules)
4. **Mitigation Orchestrator** — Coordinate defensive actions across hosts (via safe, audited tools)

## Next
Edit `defensive-agent-template.py`, add your first defensive behaviour, then run it.  
Once it produces useful output on a test case, move to L2 success criteria.

**JARVIS:** This is the cleanest on-ramp. Do not over-engineer — get a working defensive loop first, then harden with the protection layer in `04-agent-protection/`.