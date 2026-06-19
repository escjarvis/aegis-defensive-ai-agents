# Success Criteria — Aegis Defensive AI Project

**JARVIS Gatekeeping Protocol:** No dispatch to production or scaling without meeting L1-L3 criteria. Fail loud if blocked.

## L1 — Foundation (Complete when)
- [ ] Workspace reviewed: All numbered sections (01-04) have been read
- [ ] Awesome lists notes digested — at least 5 defensive tools shortlisted for your use case
- [ ] CAI prototype template executed or forked (even a minimal run)
- [ ] `scripts/setup-repos.sh` run successfully (clones present in `external/`)
- [ ] First commit or checkpoint documented in this repo

**Measurable:** Project has a working local git history and at least one extended file in `02-cai-prototype/`

## L2 — Prototype Validation (Defensive Agent MVP)
- [ ] A defensive agent (built on CAI or equivalent) demonstrates at least one core capability:
  - Threat detection / anomaly flagging from logs or simulated input
  - Automated mitigation playbooks (e.g., isolate process, generate report)
  - Ransomware indicator detection (hash/YARA match or behavioural)
- [ ] Guardrails / human-in-the-loop tested (CAI native or added)
- [ ] Integration test: Agent calls or consumes output from at least one malware analysis tool (ties2 or mrphrazer)
- [ ] Basic observability (logs or tracing) in place
- [ ] Documented in `02-cai-prototype/` or `examples/`

**Measurable:** Agent produces a structured response (JSON or report) to a test threat scenario. Time-to-response < 30s on local hardware.

## L3 — Hardening & Protection Layer
- [ ] At least one Cisco AI Defense scanner (or equivalent from awesome lists: AgentFence, Inkog, ShellWard) evaluated or integrated for your agent
- [ ] Supply-chain / skill / MCP scanning considerations documented
- [ ] Adversarial testing performed (prompt injection or malicious input simulation)
- [ ] Architecture diagram or decision record added to `docs/architecture.md`
- [ ] Clear path to multi-agent coordination or swarm for defense-in-depth

**Measurable:** Documented "defensive posture score" or risk reduction (e.g., "blocks 80% of simulated prompt injection per ShellWard rules").

## L4 — Operational (Stretch)
- Simulation environment (CyberBattleSim or equivalent) used to train/evaluate the defensive agent
- End-to-end ransomware response workflow exercised (analysis → detection → containment playbook)
- Production deployment considerations (sandboxing, HITL, audit logging) recorded
- Metrics dashboard or simple telemetry implemented

## JARVIS Adversarial Review Gate
Before any escalation or major feature addition:
- Re-run L1-L3 checklist
- Update this file with evidence (screenshots, logs, commit hashes)
- Confirm alignment with original mission: **defense against human and AI offensive, malicious, and ransomware**

If criteria not met → **Fail loud.** Return to prototype loop with targeted fixes.

**Current Status (as of init):** L1 partially met by project creation. Your first task: Complete L1 review and mark items.

**Recommendation:** Approve this structure. Proceed to prototype in `02-cai-prototype/`. Report completion of L1 for next dispatch.