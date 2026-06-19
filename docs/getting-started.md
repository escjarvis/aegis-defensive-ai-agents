# Getting Started — Defensive AI Agents Project

## 1. Workspace Orientation
You are inside a self-contained local project. All external repositories are referenced via notes and will be cloned into `external/` when you run the setup script (requires internet).

## 2. Immediate Actions (No Internet Required)
- Read this file
- Review main `README.md`
- Browse `01-awesome-lists/` for curated defensive tools
- Open `02-cai-prototype/README.md` and the Python template — this is your quickest path to a working defensive agent
- Check `docs/success-criteria.md` for measurable goals

## 3. When Internet is Available
```bash
cd /home/workdir/artifacts/Defensive-AI-Agents-Project/scripts
bash setup-repos.sh
```
This will:
- Create `external/` directory
- Clone the two awesome lists + CAI + key defensive repos (malware-ai-agent, etc.)
- Optionally init submodules or create symlinks

After cloning, you can `cd external/aliasrobotics/CAI` and follow their official setup (they support Ollama/local models for air-gapped friendliness).

## 4. Recommended First Prototype Path
1. Start in `02-cai-prototype/`
2. Review the defensive agent template
3. Install CAI per their docs (or use the prepared requirements)
4. Extend the template with specific defensive behaviours (e.g., ransomware indicator detection + automated containment playbook)
5. Add guardrails early (CAI has them built-in)

## 5. Success Criteria (see docs/success-criteria.md)
- First defensive agent responds to simulated threat within defined SLA
- Integration test with at least one malware analysis tool
- Documented architecture for scaling to multi-agent defensive swarm

**JARVIS note:** Ruthlessly protect your time — this structure prevents rabbit holes. Dispatch only when criteria are clear.