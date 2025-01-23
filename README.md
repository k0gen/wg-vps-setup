<p align="center">
  <img src="icon.png" alt="Project Logo" width="21%">
</p>

# StartOS WireGuard VPS Setup Tool

This repository contains the VPS configuration script used by the `wg-vps-setup` command in StartOS 3.6+. While the script can be used standalone to manually configure a VPS for StartOS, the recommended method is using the built-in `wg-vps-setup` command on your StartOS system.

## For StartOS Users

Simply use the built-in command:

```bash
wg-vps-setup -i YOUR_VPS_IP
```

### Usage Options

```bash
-i    VPS IP address
-u    SSH username (default: root)
-p    SSH port (default: 22)
-k    Path to custom SSH private key
-h    Show help message
```

## Manual VPS Configuration

If you need to manually configure a VPS for StartOS use:

```bash
curl -OL https://raw.githubusercontent.com/start9labs/wg-vps-setup/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

## Requirements

- Fresh VPS with root access
- StartOS 3.6+ for automated setup
- Basic networking knowledge

## Contributing

Your contributions make this project better! Pull requests and issues are welcome.
