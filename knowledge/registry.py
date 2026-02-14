"""Knowledge module registry."""

from dataclasses import dataclass


@dataclass
class KnowledgeModule:
    name: str
    content: str


class KnowledgeRegistry:
    """Stores and retrieves knowledge modules."""

    def __init__(self):
        self._modules: dict[str, KnowledgeModule] = {}

    def register(self, name: str, content: str):
        self._modules[name] = KnowledgeModule(name=name, content=content)

    def get(self, name: str) -> KnowledgeModule | None:
        return self._modules.get(name)

    def get_all(self) -> list[KnowledgeModule]:
        return list(self._modules.values())

    def names(self) -> list[str]:
        return list(self._modules.keys())
