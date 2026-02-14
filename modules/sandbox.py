"""Layer 1: Architectural constraints.

Eliminates subprocess, os.system, exec, and any shell access.
Enforces zero system privileges and strict command execution constraints.
"""

import sys
import types

# Dangerous modules that must never be imported
BLOCKED_MODULES = (
    "subprocess",
    "shlex",
    "pty",
    "pdb",
    "code",
    "codeop",
    "compileall",
    "py_compile",
)

# Dangerous builtins that must be neutered
BLOCKED_BUILTINS = (
    "exec",
    "eval",
    "compile",
    "__import__",
)


class BlockedModuleError(ImportError):
    """Raised when a blocked module is imported."""
    pass


class _BlockedModuleFinder:
    """Meta path finder that blocks dangerous module imports."""

    def find_module(self, fullname, path=None):
        base = fullname.split(".")[0]
        if base in BLOCKED_MODULES:
            return self
        return None

    def load_module(self, fullname):
        raise BlockedModuleError(
            f"Import of '{fullname}' is blocked. "
            f"This agent has no shell or command execution capabilities."
        )

    def find_spec(self, fullname, path=None, target=None):
        """Modern import hook (Python 3.4+)."""
        base = fullname.split(".")[0]
        if base in BLOCKED_MODULES:
            raise BlockedModuleError(
                f"Import of '{fullname}' is blocked. "
                f"This agent has no shell or command execution capabilities."
            )
        return None


def _blocked_os_system(*args, **kwargs):
    raise PermissionError(
        "os.system() is blocked. This agent cannot execute system commands."
    )


def _blocked_os_popen(*args, **kwargs):
    raise PermissionError(
        "os.popen() is blocked. This agent cannot execute system commands."
    )


def _blocked_os_exec(*args, **kwargs):
    raise PermissionError(
        "os.exec*() is blocked. This agent cannot execute system commands."
    )


def enforce():
    """Activate Layer 1 architectural constraints.

    Must be called at startup before any other imports.
    """
    # Block dangerous module imports
    sys.meta_path.insert(0, _BlockedModuleFinder())

    # Neuter os.system, os.popen, os.exec*
    import os
    os.system = _blocked_os_system
    os.popen = _blocked_os_popen
    os.execl = _blocked_os_exec
    os.execle = _blocked_os_exec
    os.execlp = _blocked_os_exec
    os.execlpe = _blocked_os_exec
    os.execv = _blocked_os_exec
    os.execve = _blocked_os_exec
    os.execvp = _blocked_os_exec
    os.execvpe = _blocked_os_exec
    if hasattr(os, "spawn"):
        os.spawn = _blocked_os_exec
    if hasattr(os, "spawnl"):
        os.spawnl = _blocked_os_exec
    if hasattr(os, "spawnle"):
        os.spawnle = _blocked_os_exec
    if hasattr(os, "spawnlp"):
        os.spawnlp = _blocked_os_exec
    if hasattr(os, "spawnlpe"):
        os.spawnlpe = _blocked_os_exec
    if hasattr(os, "spawnv"):
        os.spawnv = _blocked_os_exec
    if hasattr(os, "spawnve"):
        os.spawnve = _blocked_os_exec
    if hasattr(os, "spawnvp"):
        os.spawnvp = _blocked_os_exec
    if hasattr(os, "spawnvpe"):
        os.spawnvpe = _blocked_os_exec
