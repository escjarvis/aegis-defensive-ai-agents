# Cognitive System Architecture (System 1 / 2 / 3)

## Overview

This document outlines the multi-level cognitive defensive architecture for Aegis.

### System 1 – Reactive Layer (On-Box)
- Location: FortiGate (lightweight)
- Role: Fast observation and action using local models and knowledge vaults
- Examples: Inline Protective Agent, Enforcer Agent
- Characteristics: Low latency, limited compute, strong local knowledge

### System 2 – Reasoning & Intelligence Layer (Off-Box)
- Location: Off-box infrastructure
- Role: Deeper analysis, coordination, intelligence processing, and agent evolution
- Feeds System 1 with updated knowledge and directives
- Contains major parts of the AutoResearch and Agent Builder capabilities

### System 3 – Predictive & Strategic Swarm Layer
- Role: Long-horizon threat prediction, swarm coordination, and high-level strategy
- Generates directives for System 2
- Part of the broader intelligence and predictive analysis swarm

## Key Components

- **Enforcer Agent**: Separate safety agent responsible for pause, sandbox, and rollback of other agents.
- **Agent Builder**: Generates feature agents and modular sub-agents based on System 2/System 3 directives.
- **AutoResearch Agents**: Continuous research and testing agents (separate instances for inline agent, overall system, and attack surface).
- **External Intelligence Feed**: Dedicated agent (on separate branch) that ingests external threat intelligence.