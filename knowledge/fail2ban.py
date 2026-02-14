"""Fail2Ban knowledge module."""

from knowledge import register

register("Fail2Ban", """
Intrusion prevention with Fail2Ban.

Installation: sudo apt update && sudo apt install fail2ban

Config structure:
- /etc/fail2ban/jail.conf   (defaults, do not edit)
- /etc/fail2ban/jail.local  (user overrides, create this)
- /etc/fail2ban/jail.d/     (drop-in configs)
- /etc/fail2ban/filter.d/   (log filters)
- /etc/fail2ban/action.d/   (ban actions)

Basic SSH jail (/etc/fail2ban/jail.local):
  [DEFAULT]
  bantime = 1h
  findtime = 10m
  maxretry = 5
  banaction = iptables-multiport

  [sshd]
  enabled = true
  port = ssh
  logpath = %(sshd_log)s
  backend = systemd
  maxretry = 3
  bantime = 24h

Aggressive (permanent bans):
  [sshd]
  enabled = true
  maxretry = 3
  bantime = -1
  findtime = 1h

Recidive jail (ban repeat offenders longer):
  [recidive]
  enabled = true
  logpath = /var/log/fail2ban.log
  banaction = iptables-allports
  bantime = 1w
  findtime = 1d
  maxretry = 3

Whitelisting:
  [DEFAULT]
  ignoreip = 127.0.0.1/8 ::1 10.0.0.0/24

Management:
  sudo systemctl enable fail2ban
  sudo fail2ban-client status              # List jails
  sudo fail2ban-client status sshd         # SSH jail details
  sudo fail2ban-client set sshd unbanip IP # Unban
  sudo fail2ban-client set sshd banip IP   # Manual ban
  sudo fail2ban-client reload              # Reload config

Monitoring:
  sudo tail -f /var/log/fail2ban.log
  sudo zgrep 'Ban' /var/log/fail2ban.log*  # Count bans
""")
