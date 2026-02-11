"""
Core agent logic — the brain that orchestrates everything.

This module ties together:
- LLM communication
- Safety validation
- Conversation state management
- Environment detection
"""

import os
import time
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from config import AgentConfig, LLMConfig, LLMProvider
from agent.prompts import build_full_prompt, get_environment_detection_prompt
from agent.safety import OutputSafetyValidator, InputSanitizer

logger = logging.getLogger("secguide.core")


@dataclass
class Message:
    """A single conversation message."""
    role: str       # "system", "user", "assistant"
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversationState:
    """Tracks the ongoing conversation and detected environment."""
    messages: List[Message] = field(default_factory=list)

    # Detected environment info
    distro: Optional[str] = None
    distro_version: Optional[str] = None
    package_manager: Optional[str] = None
    init_system: Optional[str] = None
    server_type: Optional[str] = None
    access_method: Optional[str] = None
    experience_level: Optional[str] = None
    firewall_framework: Optional[str] = None

    # Topic tracking
    selected_topics: List[str] = field(default_factory=list)
    completed_steps: List[str] = field(default_factory=list)
    current_module: Optional[str] = None

    # Safety tracking
    injection_attempts: int = 0
    total_turns: int = 0

    def get_environment_dict(self) -> Dict[str, Optional[str]]:
        """Return detected environment as a dictionary."""
        return {
            "distro": self.distro,
            "distro_version": self.distro_version,
            "package_manager": self.package_manager,
            "init_system": self.init_system,
            "server_type": self.server_type,
            "access_method": self.access_method,
            "experience_level": self.experience_level,
            "firewall_framework": self.firewall_framework,
        }

    def has_environment_info(self) -> bool:
        """Check if we have basic environment information."""
        return self.distro is not None


class SecurityGuideAgent:
    """
    The main security guide agent.
    
    ARCHITECTURAL INVARIANT: This agent NEVER executes commands.
    It provides expert guidance for the user to follow manually.
    There are no subprocess, os.system, or exec calls in this codebase.
    """

    def __init__(
        self,
        agent_config: Optional[AgentConfig] = None,
        llm_config: Optional[LLMConfig] = None,
    ):
        self.config = agent_config or AgentConfig()
        self.llm_config = llm_config or LLMConfig()
        self.safety = OutputSafetyValidator(self.config)
        self.state = ConversationState()

        # ── Enforce safety invariants ──
        config_errors = self.config.validate()
        if config_errors:
            for error in config_errors:
                logger.critical(error)
            raise ValueError(
                "Configuration validation failed:\n" +
                "\n".join(f"  • {e}" for e in config_errors)
            )

        # ── Initialize LLM client ──
        self.llm_client = self._init_llm_client()

        logger.info(
            f"Agent initialized: provider={self.llm_config.provider.value}, "
            f"model={self.llm_config.get_model_name()}"
        )

    def _init_llm_client(self):
        """Initialize the LLM client based on configuration."""
        api_key = self.llm_config.get_api_key()

        if self.llm_config.provider == LLMProvider.OPENAI:
            try:
                from openai import OpenAI
                return OpenAI(
                    api_key=api_key,
                    timeout=self.llm_config.request_timeout,
                    max_retries=self.llm_config.max_retries,
                )
            except ImportError:
                raise ImportError(
                    "OpenAI package not installed. Run: pip install openai"
                )

        elif self.llm_config.provider == LLMProvider.ANTHROPIC:
            try:
                from anthropic import Anthropic
                return Anthropic(
                    api_key=api_key,
                    timeout=self.llm_config.request_timeout,
                    max_retries=self.llm_config.max_retries,
                )
            except ImportError:
                raise ImportError(
                    "Anthropic package not installed. Run: pip install anthropic"
                )

        raise ValueError(f"Unsupported LLM provider: {self.llm_config.provider}")

    def start(self) -> str:
        """
        Start a new conversation. Returns the agent's greeting.
        """
        # Build system prompt with all topic contexts
        system_prompt = build_full_prompt([
            "wireguard", "fail2ban", "hardening"
        ])

        self.state.messages.append(
            Message(role="system", content=system_prompt)
        )

        # Trigger the greeting
        greeting = self._call_llm(
            extra_user_message=(
                "Hello! I'd like help securing my Linux server. "
                "Please introduce yourself and ask me about my setup "
                "so you can provide the right guidance."
            )
        )

        self.state.messages.append(
            Message(role="assistant", content=greeting)
        )

        return greeting

    def chat(self, user_input: str) -> str:
        """
        Process user input and return agent response.
        
        Flow:
        1. Analyze input for safety
        2. Check scope
        3. Add to conversation
        4. Update environment detection
        5. Call LLM
        6. Validate output safety
        7. Return safe response
        """
        self.state.total_turns += 1

        # Check conversation length limit
        if self.state.total_turns > self.config.max_conversation_turns:
            return (
                "We've had a very long conversation! For best results, I'd "
                "recommend starting a fresh session with `restart`. This helps "
                "me stay focused and accurate. Your progress so far:\n" +
                self.get_progress_summary()
            )

        # ── Step 1: Analyze input safety ──
        analyzed_input, input_warnings, is_suspicious = (
            InputSanitizer.analyze_input(user_input)
        )

        if is_suspicious:
            self.state.injection_attempts += 1
            logger.warning(
                f"Suspicious input #{self.state.injection_attempts}: "
                f"{input_warnings}"
            )
            # We still process it — the system prompt handles behavioral control
            # But if there are repeated attempts, we note it
            if self.state.injection_attempts >= 3:
                return (
                    "I've noticed some unusual input patterns. Just to be clear: "
                    "I'm a Linux security hardening advisor. I can help you "
                    "set up WireGuard, Fail2Ban, and harden your Linux system. "
                    "What would you like help with?"
                )

        # ── Step 2: Check scope ──
        in_scope, scope_reason = InputSanitizer.is_within_scope(user_input)
        if not in_scope:
            return (
                f"📋 {scope_reason}\n\n"
                f"I'm here to help with:\n"
                f"  • 🔒 WireGuard VPN setup\n"
                f"  • 🛡️ Fail2Ban configuration\n"
                f"  • 🔧 Linux hardening (SSH, firewall, kernel, users, services)\n\n"
                f"What would you like to work on?"
            )

        # ── Step 3: Add to conversation ──
        self.state.messages.append(
            Message(
                role="user",
                content=analyzed_input,
                metadata={"warnings": input_warnings},
            )
        )

        # ── Step 4: Update environment detection ──
        self._update_environment_detection(analyzed_input)

        # ── Step 5: Build context and call LLM ──
        # Inject environment context if we have it
        env_context = get_environment_detection_prompt(
            self.state.get_environment_dict()
        )
        extra_context = env_context if env_context else None

        try:
            raw_response = self._call_llm(extra_context=extra_context)
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return (
                "I encountered an error communicating with my AI backend. "
                "Please check your API key and network connection.\n\n"
                f"Error: {str(e)}\n\n"
                "In the meantime, you can check the official documentation:\n"
                "  • WireGuard: https://www.wireguard.com/quickstart/\n"
                "  • Fail2Ban: https://github.com/fail2ban/fail2ban/wiki\n"
                "  • CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks"
            )

        # ── Step 6: Validate output safety ──
        safety_result = self.safety.validate_output(raw_response)

        if safety_result.blocked_content:
            logger.warning(
                f"Safety blocks triggered: {safety_result.blocked_content}"
            )

        final_response = safety_result.modified_output

        # ── Step 7: Store and return ──
        self.state.messages.append(
            Message(
                role="assistant",
                content=final_response,
                metadata={
                    "safety_warnings": safety_result.warnings,
                    "safety_blocks": safety_result.blocked_content,
                },
            )
        )

        return final_response

    def _call_llm(
        self,
        extra_user_message: Optional[str] = None,
        extra_context: Optional[str] = None,
    ) -> str:
        """
        Call the LLM with the conversation history.
        
        Args:
            extra_user_message: Optional message to add as user input
                               (used for initial greeting trigger).
            extra_context: Optional context to inject into the conversation.
        """
        # Build messages list for API
        messages = []
        for m in self.state.messages:
            messages.append({"role": m.role, "content": m.content})

        # Inject extra context as a system-level addition
        if extra_context:
            messages.append({
                "role": "system",
                "content": extra_context,
            })

        # Add triggering message if provided
        if extra_user_message:
            messages.append({
                "role": "user",
                "content": extra_user_message,
            })

        # ── Call the appropriate provider ──
        if self.llm_config.provider == LLMProvider.OPENAI:
            return self._call_openai(messages)
        elif self.llm_config.provider == LLMProvider.ANTHROPIC:
            return self._call_anthropic(messages)
        else:
            raise ValueError(f"Unsupported provider: {self.llm_config.provider}")

    def _call_openai(self, messages: List[Dict[str, str]]) -> str:
        """Call OpenAI API."""
        response = self.llm_client.chat.completions.create(
            model=self.llm_config.get_model_name(),
            messages=messages,
            temperature=self.llm_config.temperature,
            max_tokens=self.llm_config.max_tokens,
        )
        content = response.choices[0].message.content
        if content is None:
            raise ValueError("LLM returned empty response")
        return content

    def _call_anthropic(self, messages: List[Dict[str, str]]) -> str:
        """Call Anthropic API."""
        # Anthropic separates system prompt from messages
        system_parts = []
        conversation_messages = []

        for msg in messages:
            if msg["role"] == "system":
                system_parts.append(msg["content"])
            else:
                conversation_messages.append(msg)

        # Ensure conversation starts with user message (Anthropic requirement)
        if not conversation_messages or conversation_messages[0]["role"] != "user":
            conversation_messages.insert(0, {
                "role": "user",
                "content": "Hello, I'd like help securing my Linux server."
            })

        # Merge consecutive same-role messages (Anthropic requirement)
        merged_messages = []
        for msg in conversation_messages:
            if merged_messages and merged_messages[-1]["role"] == msg["role"]:
                merged_messages[-1]["content"] += "\n\n" + msg["content"]
            else:
                merged_messages.append(msg.copy())

        response = self.llm_client.messages.create(
            model=self.llm_config.get_model_name(),
            system="\n\n".join(system_parts),
            messages=merged_messages,
            temperature=self.llm_config.temperature,
            max_tokens=self.llm_config.max_tokens,
        )

        return response.content[0].text

    def _update_environment_detection(self, user_input: str):
        """
        Parse user input to detect/update environment information.
        This enables accurate distro-specific guidance.
        """
        input_lower = user_input.lower()

        # ── Distro detection ──
        distro_keywords = {
            "ubuntu 24.04": ("ubuntu", "24.04"),
            "ubuntu 22.04": ("ubuntu", "22.04"),
            "ubuntu 20.04": ("ubuntu", "20.04"),
            "ubuntu": ("ubuntu", None),
            "debian 12": ("debian", "12"),
            "debian 11": ("debian", "11"),
            "debian bookworm": ("debian", "12"),
            "debian bullseye": ("debian", "11"),
            "debian": ("debian", None),
            "fedora 40": ("fedora", "40"),
            "fedora 39": ("fedora", "39"),
            "fedora": ("fedora", None),
            "centos stream 9": ("centos", "stream-9"),
            "centos 9": ("centos", "9"),
            "centos 8": ("centos", "8"),
            "centos": ("centos", None),
            "rhel 9": ("rhel", "9"),
            "rhel 8": ("rhel", "8"),
            "red hat": ("rhel", None),
            "rocky linux 9": ("rocky", "9"),
            "rocky linux 8": ("rocky", "8"),
            "rocky 9": ("rocky", "9"),
            "rocky 8": ("rocky", "8"),
            "rocky": ("rocky", None),
            "almalinux 9": ("alma", "9"),
            "almalinux 8": ("alma", "8"),
            "alma": ("alma", None),
            "arch linux": ("arch", None),
            "arch": ("arch", None),
            "manjaro": ("arch", None),
            "opensuse": ("opensuse", None),
            "suse": ("opensuse", None),
            "linux mint": ("mint", None),
            "mint": ("mint", None),
        }

        # Check longer patterns first for accuracy
        for keyword, (distro, version) in sorted(
            distro_keywords.items(), key=lambda x: -len(x[0])
        ):
            if keyword in input_lower:
                self.state.distro = distro
                if version:
                    self.state.distro_version = version
                break

        # ── Package manager inference ──
        pkg_manager_map = {
            "ubuntu": "apt", "debian": "apt", "mint": "apt",
            "fedora": "dnf", "centos": "dnf", "rhel": "dnf",
            "rocky": "dnf", "alma": "dnf",
            "arch": "pacman",
            "opensuse": "zypper",
        }
        if self.state.distro and not self.state.package_manager:
            self.state.package_manager = pkg_manager_map.get(self.state.distro)

        # ── Init system inference ──
        if self.state.distro and not self.state.init_system:
            # All modern distros use systemd
            self.state.init_system = "systemd"

        # ── Access method detection ──
        access_keywords = {
            "ssh only": "ssh_only",
            "remote only": "ssh_only",
            "only ssh": "ssh_only",
            "only remote": "ssh_only",
            "vps": "ssh_only",
            "cloud server": "ssh_only",
            "digitalocean": "ssh_only",
            "linode": "ssh_only",
            "vultr": "ssh_only",
            "hetzner": "ssh_only",
            "aws ec2": "ssh_only",
            "console access": "console_available",
            "physical access": "console_available",
            "local access": "console_available",
            "home server": "console_available",
            "home lab": "console_available",
            "raspberry pi": "console_available",
            "virtual machine": "console_available",
            "vm": "console_available",
            "proxmox": "console_available",
            "vmware": "console_available",
            "virtualbox": "console_available",
        }

        for keyword, access in access_keywords.items():
            if keyword in input_lower:
                self.state.access_method = access
                break

        # ── Server type detection ──
        server_keywords = {
            "vps": "vps",
            "virtual private": "vps",
            "cloud": "vps",
            "dedicated": "dedicated",
            "bare metal": "dedicated",
            "raspberry pi": "raspberry_pi",
            "home server": "home_server",
            "home lab": "home_lab",
            "virtual machine": "vm",
            "vm": "vm",
            "container": "container",
            "docker": "container",
            "lxc": "container",
        }

        for keyword, stype in server_keywords.items():
            if keyword in input_lower:
                self.state.server_type = stype
                break

        # ── Experience level detection ──
        exp_keywords = {
            "beginner": "beginner",
            "new to linux": "beginner",
            "newbie": "beginner",
            "first time": "beginner",
            "not experienced": "beginner",
            "intermediate": "intermediate",
            "some experience": "intermediate",
            "familiar with": "intermediate",
            "advanced": "advanced",
            "experienced": "advanced",
            "sysadmin": "advanced",
            "devops": "advanced",
            "expert": "advanced",
        }

        for keyword, level in exp_keywords.items():
            if keyword in input_lower:
                self.state.experience_level = level
                break

        # ── Firewall framework detection ──
        fw_keywords = {
            "ufw": "ufw",
            "firewalld": "firewalld",
            "iptables": "iptables",
            "nftables": "nftables",
        }

        for keyword, fw in fw_keywords.items():
            if keyword in input_lower:
                self.state.firewall_framework = fw
                break

        # ── Topic detection ──
        topic_keywords = {
            "wireguard": "wireguard",
            "vpn": "wireguard",
            "fail2ban": "fail2ban",
            "brute force": "fail2ban",
            "ban": "fail2ban",
            "ssh": "ssh_hardening",
            "firewall": "firewall",
            "kernel": "kernel_hardening",
            "sysctl": "kernel_hardening",
            "user": "user_management",
            "permission": "file_permissions",
            "audit": "audit_logging",
            "update": "automatic_updates",
            "service": "service_minimization",
            "harden": "hardening",
            "everything": "all",
            "all three": "all",
            "all of them": "all",
        }

        for keyword, topic in topic_keywords.items():
            if keyword in input_lower and topic not in self.state.selected_topics:
                if topic == "all":
                    self.state.selected_topics = [
                        "wireguard", "fail2ban", "ssh_hardening",
                        "firewall", "kernel_hardening"
                    ]
                else:
                    self.state.selected_topics.append(topic)

    def get_progress_summary(self) -> str:
        """Return a formatted summary of conversation progress."""
        lines = [
            "",
            " **Session Progress**",
            "─" * 45,
        ]

        # Environment info
        env = self.state.get_environment_dict()
        env_items = {k: v for k, v in env.items() if v is not None}
        if env_items:
            lines.append("\n  **Detected Environment:**")
            display_names = {
                "distro": "Distribution",
                "distro_version": "Version",
                "package_manager": "Package Manager",
                "init_system": "Init System",
                "server_type": "Server Type",
                "access_method": "Access Method",
                "experience_level": "Experience",
                "firewall_framework": "Firewall",
            }
            for key, value in env_items.items():
                label = display_names.get(key, key)
                lines.append(f"   • {label}: {value}")
        else:
            lines.append("\n  Environment: Not yet detected (tell me about your system!)")

        # Selected topics
        if self.state.selected_topics:
            lines.append("\n **Topics Selected:**")
            for topic in self.state.selected_topics:
                lines.append(f"   • {topic.replace('_', ' ').title()}")
        else:
            lines.append("\n Topics: Not yet selected")

        # Completed steps
        if self.state.completed_steps:
            lines.append("\n **Completed:**")
            for step in self.state.completed_steps:
                lines.append(f"    {step}")

        # Current module
        if self.state.current_module:
            lines.append(
                f"\n🔧 **Currently working on:** "
                f"{self.state.current_module.replace('_', ' ').title()}"
            )

        # Session stats
        lines.append(f"\n📊 Conversation turns: {self.state.total_turns}")

        return "\n".join(lines)

    def mark_step_complete(self, step_name: str):
        """Mark a hardening step as complete."""
        if step_name not in self.state.completed_steps:
            self.state.completed_steps.append(step_name)
            logger.info(f"Step completed: {step_name}")

    def set_current_module(self, module_name: str):
        """Set the current working module."""
        self.state.current_module = module_name
        logger.info(f"Current module: {module_name}")

    def export_conversation(self, filepath: str) -> str:
        """
        Export the conversation to a Markdown file for reference.
        
        SECURITY: Excludes the system prompt to prevent prompt leakage.
        
        Returns:
            The filepath where the session was saved.
        """
        # Ensure export directory exists
        export_dir = os.path.dirname(filepath) or "."
        os.makedirs(export_dir, exist_ok=True)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("#  SecGuide — Security Hardening Session Log\n\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Environment summary
            env = self.state.get_environment_dict()
            env_items = {k: v for k, v in env.items() if v}
            if env_items:
                f.write("## Environment\n\n")
                for key, value in env_items.items():
                    f.write(f"- **{key}:** {value}\n")
                f.write("\n")

            # Completed steps
            if self.state.completed_steps:
                f.write("## Completed Steps\n\n")
                for step in self.state.completed_steps:
                    f.write(f"- {step}\n")
                f.write("\n")

            f.write("## Conversation\n\n")
            f.write("---\n\n")

            for msg in self.state.messages:
                if msg.role == "system":
                    continue  # Never export system prompt
                if msg.role == "user":
                    f.write(f"###  You\n\n{msg.content}\n\n---\n\n")
                elif msg.role == "assistant":
                    f.write(f"### SecGuide\n\n{msg.content}\n\n---\n\n")

            f.write(
                "\n\n*This session log was exported from SecGuide. "
                "Review all commands carefully before applying them to "
                "a production system.*\n"
            )

        logger.info(f"Session exported to {filepath}")
        return filepath