"""SSH hardening knowledge module."""

from knowledge import register

register("SSH Hardening", """
SSH server hardening options and best practices.

Key sshd_config options (/etc/ssh/sshd_config):

Restrict listen address (WireGuard-only SSH):
  ListenAddress 10.0.0.1
  WARNING: If WireGuard goes down, SSH is unreachable. Keep backup access.

Disable root login:
  PermitRootLogin no
  Or key-only: PermitRootLogin prohibit-password

Key-based auth (disable passwords):
  PasswordAuthentication no
  PubkeyAuthentication yes

Restrict users:
  AllowUsers kang
  AllowGroups ssh-users

Rate limiting:
  MaxAuthTries 3
  LoginGraceTime 30
  MaxStartups 3:50:10

Disable unused features:
  X11Forwarding no
  AllowTcpForwarding no
  AllowAgentForwarding no

Idle timeout:
  ClientAliveInterval 300
  ClientAliveCountMax 2

Recommended hardened config:
  Port 22
  ListenAddress 10.0.0.1
  PermitRootLogin prohibit-password
  MaxAuthTries 3
  LoginGraceTime 30
  PubkeyAuthentication yes
  PasswordAuthentication no
  PermitEmptyPasswords no
  KbdInteractiveAuthentication no
  X11Forwarding no
  AllowTcpForwarding no
  AllowAgentForwarding no
  ClientAliveInterval 300
  ClientAliveCountMax 2
  MaxStartups 3:50:10

Applying changes:
  sudo sshd -t                    # Test config syntax
  sudo systemctl reload sshd      # Apply without dropping sessions

Verification:
  sudo ss -tlnp | grep sshd       # Check listening addresses
  ssh -v user@host                 # Verbose connection test
  journalctl -u sshd -f           # Watch auth logs
""")
