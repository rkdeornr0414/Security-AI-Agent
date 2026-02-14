"""Layer 3: Output validation.

Blocks dangerous command patterns, injects warnings for risky output,
detects bulk script generation, and filters model output before presentation.
"""

import re
import logging

logger = logging.getLogger("safety")

# Patterns that should NEVER appear in advisor output
BLOCKED_PATTERNS = [
    (r"curl\s+[^\|]*\|\s*(?:ba)?sh", "Piping curl to shell is extremely dangerous"),
    (r"wget\s+[^\|]*\|\s*(?:ba)?sh", "Piping wget to shell is extremely dangerous"),
    (r"rm\s+-rf\s+/(?:\s|$|\*)", "Recursive deletion of root filesystem"),
    (r"mkfs\.", "Filesystem formatting detected"),
    (r"dd\s+if=.*of=/dev/[sh]d", "Raw disk write detected"),
    (r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;", "Fork bomb detected"),
    (r"chmod\s+-R\s+777\s+/", "World-writable root filesystem"),
    (r">\s*/dev/[sh]d", "Direct write to block device"),
    (r"echo\s+.*>\s*/etc/shadow", "Direct shadow file manipulation"),
]

# Patterns that trigger a warning prefix
WARNING_PATTERNS = [
    (r"rm\s+-rf\b", "WARNING: Destructive delete command. Verify the path carefully before running."),
    (r"chmod\s+-R\b", "WARNING: Recursive permission change. Double-check the target path."),
    (r"chown\s+-R\b", "WARNING: Recursive ownership change. Double-check the target path."),
    (r"iptables\s+-F\b", "WARNING: Flushing all firewall rules. You may lose remote access."),
    (r"ufw\s+disable\b", "WARNING: Disabling firewall entirely. Ensure you understand the risks."),
    (r"ufw\s+reset\b", "WARNING: Resetting all firewall rules. You may lose remote access."),
    (r"systemctl\s+stop\s+sshd", "WARNING: Stopping SSH. You may lose remote access."),
    (r"systemctl\s+disable\s+sshd", "WARNING: Disabling SSH. You will lose remote access on reboot."),
    (r"passwd\s+-l\s+root", "WARNING: Locking root account. Ensure sudo access works first."),
]

# Max number of code blocks before flagging as bulk script generation
MAX_CODE_BLOCKS = 10


def validate_output(text: str) -> str:
    """Validate and filter model output. Returns filtered text.

    Raises ValueError if output contains blocked patterns.
    """
    # Check blocked patterns
    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning(f"Blocked output pattern: {reason}")
            raise ValueError(
                f"Output blocked: {reason}. "
                f"The advisor will not provide this type of guidance."
            )

    # Inject warnings for risky patterns
    warnings = []
    for pattern, warning_msg in WARNING_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            warnings.append(warning_msg)

    # Detect bulk script generation
    code_blocks = re.findall(r"```", text)
    block_count = len(code_blocks) // 2
    if block_count > MAX_CODE_BLOCKS:
        warnings.append(
            f"NOTE: This response contains {block_count} code blocks. "
            f"Review each one carefully before executing."
        )

    if warnings:
        warning_header = "\n".join(f"[!] {w}" for w in warnings)
        text = f"{warning_header}\n\n{text}"

    return text
