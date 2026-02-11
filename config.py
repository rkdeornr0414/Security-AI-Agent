"""
Agent configuration - Safety-first defaults.
This agent NEVER executes commands. It only advises.
"""

from dataclasses import dataclass, field
from typing import List
from enum import Enum

class SecurityLevel(Enum):
    """How agressive the hardening recommendations should be."""
    MINIMAL = "minimal"
    MODERATE = "moderate"
    STRICT = "strict"

class OutputMode(Enum):
    """How commands should format its output."""
    EXPLAIN_FIRST = "explain_first"
    COMMAND_ANNOTATED = "annotated" # Comand with inline explanations
    STEP_BY_STEP = "step_by_step"

@dataclass
class AgentConfig:
    """Main agent configuration."""

    # --- Safety Boundaries ---
    # These are architectural constraints, not suggestions
    allow_command_execution: bool = False  # ALWAYS False. This is advisory-only.
    allow_script_generation: bool = False  # No runnable scripts. Individual commands only.
    require_explanation: bool = True       # Every command must have a "why"
    show_risk_warnings: bool = True        # Warn about destructive commands
    confirm_destructive: bool = True       # Extra warning for commands that lock you out

    # --- User Preferences ---
    security_level: SecurityLevel = SecurityLevel.MODERATE
    output_mode: OutputMode = OutputMode.STEP_BY_STEP
    verbose_explanations: bool = True
    show_rollback_steps: bool = True       # Always show how to undo

    # --- Supported Environments ---
    supported_distros: List[str] = field(default_factory=lambda: [
        "ubuntu", "debian", "fedora", "centos", "rhel",
        "rocky", "alma", "arch", "opensuse"
    ])

    # --- Commands that require extra warnings ---
    destructive_patterns: List[str] = field(default_factory=lambda: [
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "ufw default deny incoming",
        "systemctl disable",
        "systemctl stop sshd",
        "passwd -l",
        "chmod 000",
        "rm -rf",
        "dd if=",
        "> /dev/",
        "nft flush",
        "firewall-cmd --panic-on",
    ])

    # --- Topics this agent handles ---
    supported_topics: List[str] = field(default_factory=lambda: [
        "wireguard",
        "fail2ban",
        "ssh_hardening",
        "firewall",
        "kernel_hardening",
        "user_management",
        "file_permissions",
        "audit_logging",
        "automatic_updates",
        "service_minimization",
    ])


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: str = "openai"           # or "anthropic"
    model: str = "gpt-5.2"              # or "claude-opus-4-6"
    temperature: float = 0.1          # Low temperature for precise technical output
    max_tokens: int = 4096            # or any integer values
    api_key_env_var: str = "SECURITY_AGENT_API_KEY"