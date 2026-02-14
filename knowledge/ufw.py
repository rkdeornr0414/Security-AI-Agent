"""UFW firewall knowledge module."""

from knowledge import register

register("UFW Firewall", """
Uncomplicated Firewall (UFW) setup and management.

Installation: sudo apt update && sudo apt install ufw

Basic setup:
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow 22/tcp         # SSH (ALWAYS allow before enabling)
  sudo ufw allow 51820/udp      # WireGuard
  sudo ufw enable

Common rules:
  sudo ufw allow 80/tcp                      # HTTP
  sudo ufw allow 443/tcp                     # HTTPS
  sudo ufw allow from 10.0.0.0/24            # VPN subnet
  sudo ufw allow in on wg0                   # All on WireGuard interface

Restrict SSH to VPN only:
  sudo ufw deny 22/tcp                       # Block public SSH
  sudo ufw allow in on wg0 to any port 22    # Allow SSH on WireGuard only
  Or: sudo ufw allow from 10.0.0.0/24 to any port 22

Rule management:
  sudo ufw status verbose       # Show all rules
  sudo ufw status numbered      # Rules with numbers
  sudo ufw delete <number>      # Delete by number
  sudo ufw reset                # Remove all and disable

Rate limiting:
  sudo ufw limit 22/tcp         # 6 attempts in 30s

Logging:
  sudo ufw logging on
  sudo ufw logging medium       # low|medium|high|full

Safe order for WireGuard + SSH lockdown:
  1. Verify WireGuard works and you can connect
  2. Keep a backup SSH session open
  3. Allow WireGuard: sudo ufw allow 51820/udp
  4. Allow SSH on VPN: sudo ufw allow from 10.0.0.0/24 to any port 22
  5. Enable UFW: sudo ufw enable
  6. Test SSH through VPN in new terminal
  7. Only then remove public SSH rule if it exists
""")
