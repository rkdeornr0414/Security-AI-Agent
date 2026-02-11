# Security-Agent

# Diagram


<img width="563" height="389" alt="image" src="https://github.com/user-attachments/assets/b7294d14-49fb-4abe-b97c-b0b3178ab124" />

# Key Principle
No single layer is sufficient. Prompt injection is an unsolved problem in AI security — the LLM can always potentially be tricked. That's why the architectural layers (secrets the agent can never access, output filtering, network restrictions) are more important than trying to make the prompt "un-injectable."


# OS
Linux

# Design Philosophy
This is an advisory-only agent. It never executes commands, never writes to the filesystem, and never modifies system state. It observes, analyzes, and guides.
'''
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
'''
