"""Configuration loader."""

import os
from pathlib import Path


DEFAULT_CONFIG = {
    "provider": None,
    "model": None,
    "max_history": 50,
    "openai": {
        "api_key": None,
        "model": "gpt-4o",
        "base_url": None,
    },
    "anthropic": {
        "api_key": None,
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 4096,
    },
}


def load_config(config_path=None):
    """Load configuration from config.py and environment variables."""
    config = _deep_copy(DEFAULT_CONFIG)

    # Load from settings module
    if config_path is None:
        config_path = Path(__file__).parent.parent / "settings.py"

    if Path(config_path).exists():
        settings = {}
        with open(config_path, "r") as f:
            exec(f.read(), settings)
        file_config = settings.get("CONFIG", {})
        config = _deep_merge(config, file_config)

    # Environment variable overrides
    env_map = {
        "LSA_PROVIDER": "provider",
        "LSA_MODEL": "model",
        "OPENAI_API_KEY": ("openai", "api_key"),
        "OPENAI_BASE_URL": ("openai", "base_url"),
        "ANTHROPIC_API_KEY": ("anthropic", "api_key"),
    }

    for env_var, key_path in env_map.items():
        value = os.environ.get(env_var)
        if value:
            if isinstance(key_path, tuple):
                config[key_path[0]][key_path[1]] = value
            else:
                config[key_path] = value

    if config.get("model"):
        provider = config.get("provider", "")
        if provider in config and isinstance(config[provider], dict):
            config[provider]["model"] = config["model"]

    return config


def _deep_copy(d):
    result = {}
    for k, v in d.items():
        result[k] = _deep_copy(v) if isinstance(v, dict) else v
    return result


def _deep_merge(base, override):
    result = _deep_copy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
