"""WireGuard VPN knowledge module."""

from knowledge import register

register("WireGuard VPN", """
Setup, configuration, key management, and troubleshooting for WireGuard VPN.

Installation:
- Debian/Ubuntu: sudo apt update && sudo apt install wireguard
- RHEL/Fedora: sudo dnf install wireguard-tools
- Arch: sudo pacman -S wireguard-tools

Key Generation:
- Generate keypair: wg genkey | tee privatekey | wg pubkey > publickey
- Generate preshared key: wg genpsk > presharedkey

Server Config (/etc/wireguard/wg0.conf):
  [Interface]
  PrivateKey = <server-private-key>
  Address = 10.0.0.1/24
  ListenPort = 51820
  # Optional NAT for routing client traffic:
  PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

  [Peer]
  PublicKey = <client-public-key>
  AllowedIPs = 10.0.0.2/32

Client Config (/etc/wireguard/wg0.conf):
  [Interface]
  PrivateKey = <client-private-key>
  Address = 10.0.0.2/32

  [Peer]
  PublicKey = <server-public-key>
  Endpoint = <server-ip>:51820
  AllowedIPs = 10.0.0.1/32
  PersistentKeepalive = 25

AllowedIPs patterns:
- 10.0.0.1/32 = tunnel to server only (split tunnel)
- 10.0.0.0/24 = tunnel to VPN subnet
- 0.0.0.0/0, ::/0 = route ALL traffic (full tunnel)

Service management:
- sudo systemctl enable wg-quick@wg0
- sudo systemctl start wg-quick@wg0
- sudo wg show wg0

Troubleshooting:
- No handshake: check endpoint, firewall UDP port, key matching
- Handshake but no traffic: check AllowedIPs, IP forwarding, routing
- DNS issues: set DNS in client [Interface] section
""")
