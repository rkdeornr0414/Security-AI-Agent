"""Module loader. Auto-imports all knowledge modules at startup."""

import importlib
import pkgutil
import knowledge


def load_all_knowledge():
    """Import all modules in the knowledge package to trigger registration."""
    package_path = knowledge.__path__
    for importer, module_name, is_pkg in pkgutil.iter_modules(package_path):
        if module_name in ("__init__", "registry"):
            continue
        importlib.import_module(f"knowledge.{module_name}")
