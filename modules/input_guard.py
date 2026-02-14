"""Layer 4: Input validation.

Detects prompt injection attempts, logs suspicious inputs,
and enforces topic scope boundaries.
"""

import re
import logging

logger = logging.getLogger("input_guard")

# Prompt injection patterns
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?above\s+instructions",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(all\s+)?previous",
    r"you\s+are\s+now\s+a",
    r"act\s+as\s+if\s+you",
    r"pretend\s+you\s+are",
    r"new\s+instructions?:",
    r"system\s*prompt:",
    r"<\s*system\s*>",
    r"\bDAN\b.*\bjailbreak\b",
    r"do\s+anything\s+now",
    r"developer\s+mode",
    r"override\s+(safety|security|restrictions)",
    r"bypass\s+(safety|security|restrictions|filter)",
    r"connect\s+to\s+(agent|openclaw|container)",
    r"send\s+(message|data|request)\s+to",
    r"communicate\s+with\s+(agent|openclaw|another)",
    r"forward\s+(this|message|data)\s+to",
    r"relay\s+to",
    r"call\s+(agent|openclaw|api|endpoint)",
    r"webhook",
    r"callback",
]

# Topics that are in scope
IN_SCOPE_KEYWORDS = [
    "wireguard", "vpn", "ssh", "sshd", "fail2ban",
    "ufw", "firewall", "iptables", "nftables",
    "hardening", "security", "linux", "ubuntu", "debian",
    "centos", "fedora", "arch", "rhel", "sysctl",
    "audit", "auditd", "permissions", "chmod", "chown",
    "password", "authentication", "key", "certificate",
    "tls", "ssl", "encryption", "port", "network",
    "service", "systemctl", "daemon", "update", "upgrade",
    "unattended", "backup", "logging", "log", "journal",
    "user", "root", "sudo", "privilege", "kernel",
    "ban", "block", "allow", "deny", "rule",
    "config", "configure", "setup", "install",
]


class InputGuardResult:
    """Result of input validation."""

    def __init__(self, safe: bool, message: str = "", flagged: bool = False):
        self.safe = safe
        self.message = message
        self.flagged = flagged


def validate_input(text: str) -> InputGuardResult:
    """Validate user input for injection attempts and scope.

    Returns InputGuardResult with safe=True if input is acceptable.
    """
    text_lower = text.lower().strip()

    # Check for prompt injection
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            logger.warning(f"Prompt injection detected: {text[:100]}")
            return InputGuardResult(
                safe=False,
                message="I detected what looks like a prompt injection attempt. "
                        "I can only help with Linux security topics.",
                flagged=True,
            )

    # Scope check: only warn, don't block (user may be asking tangentially)
    if len(text_lower) > 20:
        has_scope_keyword = any(kw in text_lower for kw in IN_SCOPE_KEYWORDS)
        if not has_scope_keyword:
            logger.info(f"Possibly off-topic input: {text[:100]}")
            return InputGuardResult(
                safe=True,
                message="",
                flagged=True,
            )

    return InputGuardResult(safe=True)
