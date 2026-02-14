"""General Linux hardening knowledge module."""

from knowledge import register

register("General Linux Hardening", """
General Linux security hardening measures.

Automatic security updates (Debian/Ubuntu):
  sudo apt install unattended-upgrades
  sudo dpkg-reconfigure -plow unattended-upgrades
  Verify: sudo unattended-upgrades --dry-run --debug

User management:
  sudo adduser <name>
  sudo usermod -aG sudo <name>
  sudo passwd -l root             # Disable root password

Kernel hardening (/etc/sysctl.d/99-hardening.conf):
  net.ipv4.ip_forward = 0                         # Disable unless routing VPN
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.default.accept_redirects = 0
  net.ipv6.conf.all.accept_redirects = 0
  net.ipv4.conf.all.accept_source_route = 0
  net.ipv4.tcp_syncookies = 1                     # SYN flood protection
  net.ipv4.conf.all.log_martians = 1
  net.ipv4.icmp_echo_ignore_broadcasts = 1
  kernel.kptr_restrict = 2
  kernel.dmesg_restrict = 1
  Apply: sudo sysctl --system

Service auditing:
  systemctl list-units --type=service --state=running
  Disable unneeded: sudo systemctl disable --now <service>
  Review: cups, avahi-daemon, bluetooth, snapd

File permissions:
  Find world-writable: sudo find / -xdev -type f -perm -0002 -ls
  Find SUID/SGID: sudo find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -ls
  Secure: chmod 600 /etc/shadow, chmod 644 /etc/passwd, chmod 700 /root

Audit logging:
  sudo apt install auditd
  sudo systemctl enable auditd
  Watch files: sudo auditctl -w /etc/passwd -p wa -k passwd_changes
  Search: sudo ausearch -k passwd_changes

Login banner (/etc/issue.net):
  "Unauthorized access prohibited. All activity is monitored."
  Enable in sshd_config: Banner /etc/issue.net
""")
