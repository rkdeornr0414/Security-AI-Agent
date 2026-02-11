# Security-Agent

# 🚨 Why This Project Exists

Running Clawdbot on a publicly exposed VPS introduces a realistic attack chain.
Default-bound services are continuously scanned and brute-forced by automated botnets. A single misconfiguration or weak credential path can lead to initial access, privilege escalation, and eventual data exposure.

This project was built to break that chain.

# 🎯 Threat Model (MITRE ATT&CK Mapping)

The typical attack flow in a misconfigured VPS environment maps to:

T1190 – Exploit Public-Facing Application \t
T1110 – Brute Force \t
T1078 – Valid Accounts \t
T1068 – Privilege Escalation \t
T1021 – Remote Services (Lateral Movement) \t
T1005 – Data from Local System \t
T1041 – Exfiltration Over C2 Channel

Rather than relying on model behavior alone, this project introduces architectural constraints, layered validation, and strict execution boundaries.

# The philosophy is simple:
Assume exposure. Minimize privilege. Contain damage.

# Diagram


<img width="563" height="389" alt="image" src="https://github.com/user-attachments/assets/b7294d14-49fb-4abe-b97c-b0b3178ab124" />

# Key Principle
No single layer is sufficient. Prompt injection is an unsolved problem in AI security — the LLM can always potentially be tricked. That's why the architectural layers (secrets the agent can never access, output filtering, network restrictions) are more important than trying to make the prompt "un-injectable."


# OS
Linux

# Design Philosophy
This is an advisory-only agent. It never executes commands, never writes to the filesystem, and never modifies system state. It observes, analyzes, and guides.
```text
┌─────────────────────────────────────────────────────────┐
│              DEFENSE-IN-DEPTH LAYERS                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Layer 1: ARCHITECTURAL                                 │
│  ├── No subprocess, os.system, or exec calls            │
│  ├── No shell access in codebase whatsoever             │
│  ├── Agent has zero system privileges                   │
│  └── Config.allow_command_execution enforced by assert  │
│                                                         │
│  Layer 2: LLM BEHAVIORAL (System Prompt)                │
│  ├── Explicit rules against script generation           │
│  ├── Mandatory explanation-before-command format        │
│  ├── Safe sequencing rules (allow before deny)          │
│  ├── Scope boundaries (Linux only, defensive only)      │
│  └── Required rollback instructions                     │
│                                                         │
│  Layer 3: OUTPUT VALIDATION (safety.py)                 │
│  ├── Blocked patterns (curl|bash, rm -rf /, etc.)       │
│  ├── Warning injection for dangerous commands           │
│  ├── Bulk-script detection                              │
│  └── Post-LLM filtering before user sees output         │
│                                                         │
│  Layer 4: INPUT VALIDATION                              │
│  ├── Prompt injection pattern detection                 │
│  ├── Logged but not blocked (system prompt is primary)  │
│  └── Topic scope enforcement                            │
│                                                         │
│  Layer 5: USER REMAINS EXECUTOR                         │
│  ├── User reads, understands, then runs each command    │
│  ├── User can verify/question any recommendation        │
│  ├── User maintains full audit trail                    │
│  └── User can stop at any point                         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```
