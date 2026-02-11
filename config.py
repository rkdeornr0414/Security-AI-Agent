"""
Agent configuration - Safety-first defaults.
This agent NEVER executes commands. It only advises.
"""

from dataclasses import dataclass, field
from typing import List
from enum import Enum

class SecurityLevel(Enum):
    """How agressive the hardening recommendations should be."""
    MINIMAL = "minimal"
    MODERATE = "moderate"
    STRICT = "strict"

class OutputMode(Enum):
    """How commands should format its output."""
    EXPLAIN_FIRST = "explain_first"
    COMMAND_ANNOTATED = "annotated" # Comand with inline explanations
    STEP_BY_STEP = "step_by_step"

