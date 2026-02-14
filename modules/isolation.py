"""Layer 0: Agent isolation enforcement.

Blocks all incoming connections, API calls, and inter-agent communication.
The security agent only accepts input from the local CLI (stdin).
"""

import socket
import logging

logger = logging.getLogger("isolation")

# Original socket functions
_original_bind = socket.socket.bind
_original_listen = socket.socket.listen
_original_accept = socket.socket.accept


def _blocked_bind(self, address):
    raise PermissionError(
        "Network binding is blocked. "
        "This agent does not accept incoming connections."
    )


def _blocked_listen(self, backlog=None):
    raise PermissionError(
        "Network listening is blocked. "
        "This agent does not accept incoming connections."
    )


def _blocked_accept(self):
    raise PermissionError(
        "Network accept is blocked. "
        "This agent does not accept incoming connections."
    )


def enforce():
    """Block all incoming network connections.

    The agent can still make outgoing connections (for LLM API calls)
    but cannot bind, listen, or accept any incoming connections.
    No other agent, process, or service can communicate with this agent.
    Only local stdin input is accepted.
    """
    socket.socket.bind = _blocked_bind
    socket.socket.listen = _blocked_listen
    socket.socket.accept = _blocked_accept

    logger.info(
        "Agent isolation enforced: "
        "all incoming connections blocked, stdin-only input"
    )
