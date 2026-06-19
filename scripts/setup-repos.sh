#!/bin/bash
# setup-repos.sh — JARVIS Automated First Actions
# Run this ONLY when you have internet access.
# It clones the key recommended repositories into external/ for local reference and extension.

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXTERNAL_DIR="$PROJECT_ROOT/external"

echo "=== JARVIS Defensive AI Agents — Repository Setup ==="
echo "Project root: $PROJECT_ROOT"
echo "Target external dir: $EXTERNAL_DIR"
echo ""

mkdir -p "$EXTERNAL_DIR"
cd "$EXTERNAL_DIR"

echo "Cloning awesome lists and core frameworks..."

# 1. Awesome lists (meta)
git clone --depth 1 https://github.com/raphabot/awesome-cybersecurity-agentic-ai.git || echo "Warning: raphabot clone failed or already exists"
git clone --depth 1 https://github.com/ProjectRecon/awesome-ai-agents-security.git || echo "Warning: ProjectRecon clone failed or already exists"

# 2. Core recommended framework
git clone --depth 1 https://github.com/aliasrobotics/CAI.git || echo "Warning: CAI clone failed or already exists"

# 3. Key defensive / malware tools
git clone --depth 1 https://github.com/ties2/malware-ai-agent.git || echo "Warning: malware-ai-agent clone failed"
git clone --depth 1 https://github.com/mrphrazer/agentic-malware-analysis.git || echo "Warning: agentic-malware-analysis clone failed"

# 4. Optional but high-value defensive
git clone --depth 1 https://github.com/mrwadams/honeyagents.git || echo "Warning: honeyagents clone failed"
git clone --depth 1 https://github.com/Agent-Threat-Rule/agent-threat-rules.git || echo "Warning: ATR clone failed"

# Cisco AI Defense (if you want the full suite — large org, selective clone recommended)
# git clone --depth 1 https://github.com/cisco-ai-defense/defenseclaw.git || true

echo ""
echo "=== Setup complete ==="
echo "Cloned repositories are in: $EXTERNAL_DIR"
echo ""
echo "Next:"
echo "  cd $EXTERNAL_DIR/aliasrobotics/CAI"
echo "  Follow their README for installation (supports local Ollama models)"
echo ""
echo "Then return to project root and continue with 02-cai-prototype/ work."
echo "JARVIS recommends marking L1 criteria complete after this step."