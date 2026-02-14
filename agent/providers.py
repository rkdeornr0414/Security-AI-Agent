"""LLM provider implementations."""

from abc import ABC, abstractmethod
from agent.prompt import build_system_prompt


class Provider(ABC):
    """Base LLM provider."""

    @abstractmethod
    def chat(self, messages: list[dict]) -> str:
        ...

    def get_system_prompt(self) -> str:
        return build_system_prompt()


class OpenAIProvider(Provider):
    """OpenAI-compatible provider."""

    def __init__(self, config: dict):
        try:
            from openai import OpenAI
        except ImportError:
            raise ValueError("openai package not installed. Run: pip install openai")

        oa_config = config.get("openai", {})
        api_key = oa_config.get("api_key")
        if not api_key:
            raise ValueError(
                "OpenAI API key not set. Set OPENAI_API_KEY or in settings.py"
            )

        kwargs = {"api_key": api_key}
        if oa_config.get("base_url"):
            kwargs["base_url"] = oa_config["base_url"]

        self.client = OpenAI(**kwargs)
        self.model = oa_config.get("model", "gpt-4o")

    def chat(self, messages: list[dict]) -> str:
        full_messages = [
            {"role": "system", "content": self.get_system_prompt()}
        ] + messages

        response = self.client.chat.completions.create(
            model=self.model,
            messages=full_messages,
        )
        return response.choices[0].message.content


class AnthropicProvider(Provider):
    """Anthropic provider."""

    def __init__(self, config: dict):
        try:
            import anthropic
        except ImportError:
            raise ValueError("anthropic package not installed. Run: pip install anthropic")

        ac_config = config.get("anthropic", {})
        api_key = ac_config.get("api_key")
        if not api_key:
            raise ValueError(
                "Anthropic API key not set. Set ANTHROPIC_API_KEY or in settings.py"
            )

        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = ac_config.get("model", "claude-sonnet-4-20250514")
        self.max_tokens = ac_config.get("max_tokens", 4096)

    def chat(self, messages: list[dict]) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=self.get_system_prompt(),
            messages=messages,
        )
        return response.content[0].text


def get_provider(name: str, config: dict) -> Provider:
    """Factory to get provider by name."""
    providers = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
    }

    if name not in providers:
        raise ValueError(
            f"Unknown provider: {name}. Choose from: {', '.join(providers)}"
        )

    return providers[name](config)
