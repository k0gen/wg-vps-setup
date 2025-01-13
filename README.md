# StartOS WireGuard VPS Setup Tool

Automated WireGuard VPN deployment tool for StartOS that configures a remote VPS server and sets up secure tunneling in under a minute. This project builds upon the excellent [wireguard-install](https://github.com/Nyr/wireguard-install) script.

## Features

- One-command VPS configuration and WireGuard installation
- Automatic SSH key generation and deployment
- Seamless NetworkManager integration
- Built-in validation and error handling
- Clear step-by-step feedback
- Support for custom SSH keys and ports

## Quick Start

Download and run the script:

```bash
wget https://raw.githubusercontent.com/k0gen/wireguard-install/master/wg-vps-setup.sh
chmod +x wg-vps-setup.sh
sudo ./wg-vps-setup.sh -i YOUR_VPS_IP
```

## Usage Options
```bash
-i    VPS IP address
-u    SSH username (default: root)
-p    SSH port (default: 22)
-k    Path to custom SSH private key
-h    Show help message
```

## Post-Setup Steps

The script guides you through essential next steps:
- ACME certificate management for SSL/TLS
- Domain configuration for your services
- Public port binding setup

## Requirements

- Fresh VPS with root access
- StartOS on your local machine
- Basic networking knowledge

## Contributing

Your contributions make this project better! Pull requests and issues are welcome.
