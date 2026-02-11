#!/usr/bin/env python3
"""Linux Security Advisor - Advisory-only CLI agent.

Defense-in-depth architecture:
  Layer 1: Architectural constraints (sandbox.py) - no shell, no exec
  Layer 2: LLM behavioral controls (prompt.py) - anti-script, safe sequencing
  Layer 3: Output validation (safety.py) - block dangerous patterns
  Layer 4: Input validation (input_guard.py) - detect injection, enforce scope
  Layer 5: User as executor - human reviews and runs all commands
"""

import sys
import logging
import argparse

# Layer 0: Enforce agent isolation - block all incoming connections
from modules.isolation import enforce as enforce_isolation
enforce_isolation()

# Layer 1: Enforce architectural constraints - no shell, no exec
from modules.sandbox import enforce as enforce_sandbox
enforce_sandbox()

from modules.loader import load_all_knowledge
from agent.chat import ChatSession
from agent.config import load_config
from agent.providers import get_provider


def setup_logging():
    """Configure logging for security events."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.FileHandler("security.log", mode="a"),
            logging.StreamHandler(sys.stderr),
        ],
    )


def main():
    parser = argparse.ArgumentParser(
        description="Linux Security Advisor - Advisory-only security guidance agent"
    )
    parser.add_argument(
        "--provider",
        choices=["openai", "anthropic"],
        help="LLM provider (overrides config/env)",
    )
    parser.add_argument(
        "--model",
        help="Model name (overrides config/env)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to settings file (default: settings.py)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    setup_logging()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger = logging.getLogger("main")
    logger.info("Starting Linux Security Advisor")
    logger.info("Layer 0: Isolation enforced - no incoming connections")
    logger.info("Layer 1: Sandbox enforced")

    # Load all knowledge modules
    load_all_knowledge()
    logger.info("Knowledge modules loaded")

    config = load_config(args.config)

    if args.provider:
        config["provider"] = args.provider
    if args.model:
        config["model"] = args.model

    provider_name = config.get("provider")
    if not provider_name:
        print("Error: No provider specified.")
        print("Set via --provider, settings.py, or LSA_PROVIDER env var")
        sys.exit(1)

    try:
        provider = get_provider(provider_name, config)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    session = ChatSession(provider, config)

    print("=" * 60)
    print("  Linux Security Advisor")
    print("  Advisory-only. No commands will be executed.")
    print(f"  Provider: {provider_name} | Model: {config.get('model', 'default')}")
    print("  Defense: 5-layer protection active")
    print("=" * 60)
    print()
    print("Ask me about WireGuard, SSH hardening, Fail2Ban, UFW,")
    print("or general Linux security. Type 'quit' or 'exit' to leave.")
    print("Type 'clear' to reset conversation history.")
    print()

    while True:
        try:
            user_input = input("\033[1;32myou>\033[0m ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            break

        if not user_input:
            continue

        if user_input.lower() in ("quit", "exit"):
            print("Goodbye.")
            break

        if user_input.lower() == "clear":
            session.clear()
            print("Conversation cleared.\n")
            continue

        print()
        try:
            response = session.send(user_input)
            print(f"\033[1;36madvisor>\033[0m {response}\n")
        except Exception as e:
            logger.error(f"Error: {e}")
            print(f"\033[1;31merror>\033[0m {e}\n")


if __name__ == "__main__":
    main()
