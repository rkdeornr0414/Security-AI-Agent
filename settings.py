"""
Linux Security Advisor - Configuration
========================================

Edit the values below to configure the agent.
Environment variables override these settings.

Supported providers: "openai", "anthropic"

Environment variable overrides:
  LSA_PROVIDER       - Provider name
  LSA_MODEL          - Model name (applies to selected provider)
  OPENAI_API_KEY     - OpenAI API key
  OPENAI_BASE_URL    - Custom OpenAI-compatible endpoint
  ANTHROPIC_API_KEY  - Anthropic API key
"""

CONFIG = {

    # ── Provider ─────────────────────────────────────────────
    # Which LLM provider to use: "openai" or "anthropic"
    "provider": "anthropic",

    # ── Model Override ───────────────────────────────────────
    # Set a model here to override the provider default.
    # Leave as None to use the provider's default model.
    "model": None,

    # ── Conversation ─────────────────────────────────────────
    # Maximum number of message pairs to keep in memory.
    # Older messages are trimmed to stay within this limit.
    "max_history": 50,

    # ── OpenAI ───────────────────────────────────────────────
    "openai": {
        # API key (or set OPENAI_API_KEY environment variable)
        "api_key": None,

        # Model to use
        "model": "gpt-5.2",

        # Custom base URL for OpenAI-compatible APIs (e.g. local LLM)
        # Set to None for default OpenAI endpoint
        "base_url": None,
    },

    # ── Anthropic ────────────────────────────────────────────
    "anthropic": {
        # API key (or set ANTHROPIC_API_KEY environment variable)
        "api_key": None,

        # Model to use
        "model": "claude-opus-4-6",

        # Maximum tokens in response
        "max_tokens": 4096,
    },
}
