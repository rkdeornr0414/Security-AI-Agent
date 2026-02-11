"""
Output safety validation — Defense-in-depth layer.

This module ensures the agent NEVER produces output that could
be blindly piped to a shell or cause unintended damage.

The safety validator runs on ALL agent output AFTER the LLM generates it
but BEFORE the user sees it.
"""

import re
import logging
from typing import List, Tuple, Optional
from dataclasses import dataclass, field
from config import AgentConfig

logger = logging.getLogger("secguide.safety")


@dataclass
class SafetyCheckResult:
    """Result of a safety validation check."""
    is_safe: bool
    warnings: List[str] = field(default_factory=list)
    blocked_content: List[str] = field(default_factory=list)
    modified_output: str = ""
    injection_detected: bool = False


class OutputSafetyValidator:
    """
    Validates all agent output before presenting to user.
    
    This is a POST-PROCESSING safety net. The system prompt is the
    primary behavioral control. This catches anything that slips through.
    """

    def __init__(self, config: AgentConfig):
        self.config = config

        # ──────────────────────────────────────────────────────
        # BLOCKED PATTERNS — Content that must never appear
        # ──────────────────────────────────────────────────────
        self.blocked_patterns: List[Tuple[str, str]] = [
            # Pipe-to-shell patterns
            (r'curl\s+[^\|]*\|\s*(sudo\s+)?(ba)?sh',
             "curl-pipe-to-shell is unsafe. Download first, inspect, then run."),
            (r'wget\s+[^\|]*\|\s*(sudo\s+)?(ba)?sh',
             "wget-pipe-to-shell is unsafe. Download first, inspect, then run."),
            (r'curl\s+[^\|]*\|\s*(sudo\s+)?python',
             "curl-pipe-to-python is unsafe."),

            # Encoded/obfuscated command execution
            (r'base64\s+(-d|--decode)\s*\|.*?(ba)?sh',
             "Obfuscated command execution via base64."),
            (r'eval\s*\$\(\s*echo',
             "Obfuscated eval execution."),
            (r'echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh',
             "Encoded payload execution."),

            # Catastrophic file operations
            (r'rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?/\s*$',
             "Recursive delete of root filesystem."),
            (r'rm\s+-rf\s+/($|\s|;|&&|\|\|)',
             "Recursive delete of root filesystem."),
            (r'rm\s+-rf\s+/(etc|usr|var|boot|bin|sbin|lib|home|root)\s',
             "Recursive delete of critical system directory."),

            # Disk wiping
            (r'dd\s+if=/dev/(zero|urandom)\s+of=/dev/[shv]d[a-z]\b',
             "Disk wipe command — would destroy all data."),
            (r'mkfs\.\w+\s+/dev/[shv]d[a-z][0-9]?\b(?!.*#)',
             "Filesystem format of what may be an active partition."),

            # Fork bombs and resource exhaustion
            (r':\(\)\s*\{\s*:\|:&\s*\}',
             "Fork bomb detected."),
            (r'>\s*/dev/(sda|hda|vda|nvme)',
             "Direct write to block device."),
        ]

        # ──────────────────────────────────────────────────────
        # WARNING PATTERNS — Commands that need prominent warnings
        # ──────────────────────────────────────────────────────
        self.warning_patterns: List[Tuple[str, str]] = [
            (r'iptables\s+-P\s+(INPUT|FORWARD)\s+DROP',
             "LOCKOUT WARNING: This sets the default firewall policy to DROP. "
             "If you haven't added ALLOW rules for SSH first, you WILL lose remote access. "
             "Make sure you have: (1) An allow rule for your SSH port, (2) Console access as backup."),

            (r'ufw\s+default\s+deny\s+incoming',
             "LOCKOUT WARNING: This denies all incoming connections by default. "
             "Run 'sudo ufw allow ssh' (or your custom SSH port) BEFORE enabling UFW."),

            (r'ufw\s+enable',
             "IMPORTANT: Before enabling UFW, verify your SSH allow rule is in place "
             "with 'sudo ufw status'. If SSH isn't allowed, you'll be locked out."),

            (r'systemctl\s+(stop|disable)\s+ssh(d)?',
             "LOCKOUT WARNING: This will stop/disable the SSH daemon. "
             "You will lose remote access immediately. Only do this if you have "
             "another access method (console, WireGuard) already working and tested."),

            (r'PermitRootLogin\s+no',
             "IMPORTANT: Before applying this, verify:\n"
             "  1. You have a non-root user with sudo privileges\n"
             "  2. You can successfully log in as that user\n"
             "  3. sudo works for that user\n"
             "  Test in a SEPARATE terminal before restarting SSH."),

            (r'PasswordAuthentication\s+no',
             "LOCKOUT WARNING: Before disabling password authentication:\n"
             "  1. Verify your SSH key-based login works\n"
             "  2. Test in a SEPARATE terminal: ssh -i /path/to/key user@server\n"
             "  3. Keep your current session open until confirmed\n"
             "  If keys don't work and you disable passwords, you're locked out."),

            (r'passwd\s+-l\s+root',
             "IMPORTANT: Locking the root account password. Ensure:\n"
             "  1. You have a working sudo-capable user\n"
             "  2. Sudo is properly configured and tested\n"
             "  3. You have another way to get root if needed (e.g., single-user mode)"),

            (r'nft\s+flush\s+ruleset',
             "LOCKOUT WARNING: This flushes ALL nftables rules immediately. "
             "If your default policy is 'drop', you'll be locked out the instant this runs."),

            (r'firewall-cmd\s+--permanent.*--remove',
             "CAUTION: Removing a permanent firewall rule. If this is for SSH or "
             "your management port, you may lose access after firewall reload."),

            (r'visudo',
             "IMPORTANT: visudo edits the sudoers file. A syntax error here can "
             "break sudo entirely. visudo has built-in syntax checking — if it reports "
             "an error, do NOT save the file."),

            (r'chmod\s+[0-7]*0[0-7]\s+/etc/ssh',
             "CAUTION: Changing SSH config file permissions. Incorrect permissions "
             "on SSH files can prevent SSH from starting."),
        ]

    def validate_output(self, agent_output: str) -> SafetyCheckResult:
        """
        Validate agent output before showing to user.
        
        This is the main entry point. Every agent response passes through here.
        
        Args:
            agent_output: Raw text from the LLM.
            
        Returns:
            SafetyCheckResult with validated/modified output.
        """
        warnings: List[str] = []
        blocked: List[str] = []
        modified = agent_output

        # ── Check for blocked patterns ──
        for pattern, reason in self.blocked_patterns:
            matches = re.finditer(pattern, modified, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                blocked.append(reason)
                logger.warning(f"BLOCKED content: {reason} | Match: {match.group()}")
                # Replace with visible warning
                replacement = (
                    f"\n\n🚫 **BLOCKED — UNSAFE COMMAND REMOVED**\n"
                    f"> {reason}\n"
                    f"> This type of command was filtered for your safety.\n\n"
                )
                modified = modified[:match.start()] + replacement + modified[match.end():]

        # ── Check for warning patterns ──
        for pattern, warning_msg in self.warning_patterns:
            if re.search(pattern, modified, re.IGNORECASE | re.MULTILINE):
                if warning_msg not in warnings:
                    warnings.append(warning_msg)

        # ── Inject warnings near relevant commands ──
        if warnings and self.config.show_risk_warnings:
            modified = self._inject_warnings_into_output(modified, warnings)

        # ── Check for excessive commands without explanation ──
        if self.config.require_explanation:
            modified = self._check_explanation_density(modified)

        # ── Check for multi-line scripts disguised as single blocks ──
        modified = self._check_script_blocks(modified)

        is_safe = len(blocked) == 0

        return SafetyCheckResult(
            is_safe=is_safe,
            warnings=warnings,
            blocked_content=blocked,
            modified_output=modified,
            injection_detected=False,
        )

    def _inject_warnings_into_output(
        self, output: str, warnings: List[str]
    ) -> str:
        """
        Insert warning callouts near dangerous commands in the output.
        
        Strategy: Find code blocks containing dangerous patterns and insert
        the warning immediately before them.
        """
        lines = output.split('\n')
        result_lines: List[str] = []
        inserted_warnings: set = set()

        i = 0
        while i < len(lines):
            line = lines[i]

            # Check if this line starts a code block
            if line.strip().startswith('```'):
                # Gather the entire code block
                block_lines = [line]
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('```'):
                    block_lines.append(lines[i])
                    i += 1
                if i < len(lines):
                    block_lines.append(lines[i])

                block_content = '\n'.join(block_lines)

                # Check if any warnings apply to this block
                for pattern, warning_msg in self.warning_patterns:
                    if (
                        re.search(pattern, block_content, re.IGNORECASE)
                        and warning_msg not in inserted_warnings
                    ):
                        # Insert warning before the code block
                        result_lines.append('')
                        result_lines.append(f'> {warning_msg}')
                        result_lines.append('')
                        inserted_warnings.add(warning_msg)

                result_lines.extend(block_lines)
            else:
                result_lines.append(line)

            i += 1

        # Add any uninserted warnings at the top
        remaining_warnings = [w for w in warnings if w not in inserted_warnings]
        if remaining_warnings:
            header_warnings = []
            for w in remaining_warnings:
                header_warnings.append(f'\n> {w}\n')
            return '\n'.join(header_warnings) + '\n' + '\n'.join(result_lines)

        return '\n'.join(result_lines)

    def _check_explanation_density(self, output: str) -> str:
        """
        Verify that code blocks aren't presented as bulk scripts
        without sufficient explanation between them.
        """
        lines = output.split('\n')
        in_code_block = False
        consecutive_command_lines = 0
        max_commands = self.config.max_consecutive_commands
        flagged = False

        for line in lines:
            stripped = line.strip()

            if stripped.startswith('```'):
                if in_code_block:
                    # End of code block
                    in_code_block = False
                    consecutive_command_lines = 0
                else:
                    # Start of code block
                    in_code_block = True
                    consecutive_command_lines = 0
                continue

            if in_code_block:
                # Count non-empty, non-comment lines as commands
                if stripped and not stripped.startswith('#'):
                    consecutive_command_lines += 1
                    if consecutive_command_lines > max_commands:
                        flagged = True

        if flagged:
            advisory = (
                "\n\n📝 **Note:** Some command blocks above contain several commands. "
                "Please read and understand each command individually before running them. "
                "If anything is unclear, ask me to explain a specific command.\n"
            )
            output += advisory
            logger.info(
                "Advisory note added — code block exceeded "
                f"{max_commands} consecutive commands."
            )

        return output

    def _check_script_blocks(self, output: str) -> str:
        """
        Check for what appears to be a complete script (shebang, functions, etc.)
        and add a notice if found.
        """
        script_indicators = [
            r'#!/bin/(ba)?sh',
            r'#!/usr/bin/env\s+(ba)?sh',
            r'function\s+\w+\s*\(\)',
            r'\w+\s*\(\)\s*\{',
            r'for\s+\w+\s+in\s+.*;\s*do',
            r'while\s+.*;\s*do',
            r'if\s+\[.*\];\s*then',
        ]

        has_script = False
        for pattern in script_indicators:
            if re.search(pattern, output, re.MULTILINE):
                has_script = True
                break

        if has_script:
            notice = (
                "\n\n📝 **Note:** The above contains script-like constructs. "
                "This is meant for your understanding — please review each section "
                "carefully. If you'd prefer individual step-by-step commands instead, "
                "just ask!\n"
            )
            if notice not in output:
                output += notice

        return output


class InputSanitizer:
    """
    Sanitize and analyze user input before sending to LLM.
    
    This does NOT block user input — it flags suspicious patterns
    so the agent can be aware. The system prompt's instructions
    are the primary defense against prompt injection.
    """

    INJECTION_PATTERNS: List[Tuple[str, str]] = [
        (r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?|guidelines?)",
         "Instruction override attempt"),
        (r"you\s+are\s+now\s+",
         "Role reassignment attempt"),
        (r"new\s+(system\s+)?instructions?\s*:",
         "Instruction injection"),
        (r"system\s*prompt\s*:",
         "System prompt injection"),
        (r"forget\s+(everything|all|your\s+(rules?|instructions?))",
         "Memory wipe attempt"),
        (r"pretend\s+(you\s+)?(are|have|can|don.t)",
         "Role pretend attempt"),
        (r"act\s+as\s+if\s+(you\s+)?(have\s+no|there\s+are\s+no)\s+restrict",
         "Restriction bypass attempt"),
        (r"(output|print|show|reveal|display)\s+(your\s+)?(system|initial|original)\s+prompt",
         "Prompt extraction attempt"),
        (r"(BEGIN|START)\s+(JAILBREAK|OVERRIDE|HACK|DAN)",
         "Jailbreak attempt"),
        (r"do\s+anything\s+now",
         "DAN-style jailbreak"),
        (r"\[INST\]|\[/INST\]|<<SYS>>|<\|im_start\|>",
         "Prompt format injection"),
        (r"ignore\s+safety",
         "Safety bypass attempt"),
    ]

    @classmethod
    def analyze_input(cls, user_input: str) -> Tuple[str, List[str], bool]:
        """
        Analyze user input for potential prompt injection.
        
        Returns:
            Tuple of (input_text, warnings, is_suspicious)
            
        Note: We NEVER modify user input. We only flag and log.
        The system prompt handles behavioral enforcement.
        """
        warnings: List[str] = []
        is_suspicious = False

        for pattern, description in cls.INJECTION_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                warnings.append(
                    f"Prompt injection pattern detected: {description}"
                )
                is_suspicious = True
                logger.warning(
                    f"Potential prompt injection: {description} | "
                    f"Input fragment: {user_input[:100]}"
                )

        # Check for extremely long inputs (potential context stuffing)
        if len(user_input) > 10000:
            warnings.append(
                "Unusually long input detected. Processing normally but flagged."
            )
            logger.warning(f"Long input: {len(user_input)} characters")

        return user_input, warnings, is_suspicious

    @classmethod
    def is_within_scope(cls, user_input: str) -> Tuple[bool, str]:
        """
        Check if the user's request falls within the agent's scope.
        
        Returns:
            Tuple of (is_in_scope, reason_if_out_of_scope)
        """
        out_of_scope_patterns = [
            (r"\b(hack|exploit|crack|bypass|break\s+into)\b.*\b(system|server|password|account)\b",
             "I only provide defensive security guidance. I can't help with "
             "offensive security or bypassing controls."),
            (r"\b(windows|macos|mac\s+os)\b.*\b(harden|secur|config|setup)\b",
             "I specialize in Linux security. For Windows or macOS hardening, "
             "I'd recommend consulting platform-specific resources."),
            (r"\bwrite\s+(me\s+)?a?\s*(malware|virus|trojan|ransomware|keylogger)\b",
             "I can't help create malicious software. I'm here to help you "
             "defend against such threats."),
        ]

        input_lower = user_input.lower()
        for pattern, reason in out_of_scope_patterns:
            if re.search(pattern, input_lower):
                return False, reason

        return True, ""