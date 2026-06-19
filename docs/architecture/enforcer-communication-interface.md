# Enforcer Communication Interface (System 1 ↔ System 2)

## Overview

This document defines the communication interface between the **System 1 Enforcer** (on-box, fast-acting) and the **System 2 Enforcer** (off-box, policy & coordination layer).

The goal is to enable secure, reliable, and low-latency coordination while maintaining clear separation of responsibilities.

## Design Principles

- **Asymmetric Roles**: System 2 makes high-level decisions. System 1 executes fast, local actions.
- **Fail-Safe Default**: System 1 must be able to act autonomously when System 2 is unreachable.
- **Minimal Trust**: System 1 should validate commands from System 2.
- **Auditability**: All commands and actions must be logged.
- **Extensibility**: The interface should support future message types.

## Communication Patterns

### 1. Command (System 2 → System 1)
System 2 sends directives to System 1 for immediate or scheduled action.

### 2. Event / Report (System 1 → System 2)
System 1 reports observations, actions taken, and status back to System 2.

### 3. Policy Update (System 2 → System 1)
System 2 pushes updated local policies or rulesets.

## Message Types

### Commands (System 2 → System 1)

| Command              | Description                                      | Required Parameters                  | Response Expected |
|----------------------|--------------------------------------------------|--------------------------------------|-------------------|
| `PauseAgent`         | Immediately pause a specific agent               | `agent_id`, `reason`, `duration?`    | Yes               |
| `SandboxAgent`       | Place an agent into sandbox mode                 | `agent_id`, `reason`, `level`        | Yes               |
| `RollbackAgent`      | Roll back an agent to a previous known state     | `agent_id`, `version`                | Yes               |
| `BlockFlow`          | Block network flow associated with an agent      | `flow_id` or `dst_ip`, `duration?`   | Yes               |
| `UpdateLocalPolicy`  | Push updated policy/rules to System 1            | `policy_id`, `policy_content`        | Yes               |
| `QueryStatus`        | Request current status of an agent               | `agent_id`                           | Yes               |

### Events / Reports (System 1 → System 2)

| Event                     | Description                                           | Key Fields                              |
|---------------------------|-------------------------------------------------------|-----------------------------------------|
| `AgentAnomalyDetected`    | System 1 detected suspicious behavior in an agent     | `agent_id`, `anomaly_type`, `confidence`, `details` |
| `ActionTaken`             | System 1 executed a containment action                | `action_type`, `agent_id`, `success`, `reason`      |
| `PolicyViolation`         | Local policy violation observed                       | `policy_id`, `agent_id`, `details`                  |
| `StatusReport`            | Periodic or on-demand status update                   | `agent_id`, `state`, `metrics`                      |
| `ConnectivityLost`        | System 1 lost connection to System 2                  | `timestamp`, `last_known_state`                     |

## Message Format

All messages should use a consistent structure. Recommended format: **JSON** (for simplicity and debuggability) or **Protocol Buffers** for production performance.

Example JSON structure:

```json
{
  "message_id": "uuid",
  "timestamp": "2026-06-19T11:30:00Z",
  "message_type": "PauseAgent",
  "source_layer": "System2",
  "target_layer": "System1",
  "payload": {
    "agent_id": "inline-agent-01",
    "reason": "Behavioral anomaly detected",
    "duration_seconds": 300
  },
  "signature": "..."
}
```

## Security Requirements

- All messages **must be authenticated** (mutual TLS or signed tokens).
- Sensitive commands should be **encrypted** in transit.
- System 1 should validate command signatures and authorization before execution.
- Rate limiting and replay protection recommended.

## Reliability & Resilience

- System 1 must support **offline operation** with cached policies.
- Commands should support **acknowledgment** (ACK) and retry logic.
- Critical actions (e.g., Rollback) should have confirmation mechanisms.
- System 1 should buffer events when connectivity to System 2 is lost and sync later.

## Versioning

The interface should be versioned (e.g., `v1`, `v2`). Both sides must negotiate or declare supported versions during connection.

## Next Steps

- Define concrete message schemas (JSON Schema or Protobuf).
- Implement reference communication library in `core/communication/`.
- Define fallback behavior for System 1 when System 2 is unavailable.
- Design policy distribution mechanism from System 2 to System 1.