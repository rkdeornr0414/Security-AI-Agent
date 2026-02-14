"""Knowledge module registry. Auto-loads all modules in this package."""

from knowledge.registry import KnowledgeRegistry

registry = KnowledgeRegistry()


def register(name: str, content: str):
    """Register a knowledge module."""
    registry.register(name, content)
