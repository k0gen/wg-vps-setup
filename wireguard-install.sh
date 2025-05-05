#!/bin/bash
#
# StartOS WireGuard VPS Setup Tool
# https://github.com/start9labs/wg-vps-setup
# Derived from github.com/Nyr/wireguard-install (MIT License)

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
  echo -e "${BLUE}==>${NC} $1"
}

print_success() {
  echo -e "${GREEN}==>${NC} $1"
}

print_error() {
  echo -e "${RED}==>${NC} $1"
}

print_warning() {
  echo -e "${YELLOW}==>${NC} $1"
}

# Function to print usage
print_usage() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  --add-client [NAME]    Add a new client with optional name"
  echo "  --remove-client [NAME] Remove an existing client"
  echo "  --list-clients        List all existing clients"
  echo "  --help                Show this help message"
  echo
  echo "If no options are provided, the script will run in interactive mode."
}

new_client_setup() {
  # Given a list of the assigned internal IPv4 addresses, obtain the lowest still
  # available octet. Important to start looking at 2, because 1 is our gateway.
  octet=2
  while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
    ((octet++))
  done
  # Don't break the WireGuard configuration in case the address space is full
  if [[ "$octet" -eq 255 ]]; then
    print_error "253 clients are already configured. The WireGuard internal subnet is full!"
    exit 1
  fi
  key=$(wg genkey)
  psk=$(wg genpsk)
  # Configure client in the server
  cat <<EOF >>/etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<<$key)
PresharedKey = $psk
AllowedIPs = 10.59.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
  # Create client configuration
  server_private_key=$(grep '^PrivateKey = ' /etc/wireguard/wg0.conf | cut -d " " -f 3)
  server_public_key=$(wg pubkey <<<"$server_private_key")
  cat <<EOF >~/"$client".conf
[Interface]
Address = 10.59.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
PrivateKey = $key
DNS = 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $server_public_key
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
  print_success "Client configuration created: ~/$client.conf"

  # Display QR code if qrencode is available
  if command -v qrencode &>/dev/null; then
    print_status "Scan this QR code with your WireGuard app:"
    qrencode -t ansiutf8 <~/"$client".conf
  else
    print_warning "qrencode not found. Install it to display QR codes for client configurations."
  fi
}

# Function to handle command line arguments
handle_args() {
  case "$1" in
  --add-client)
    if [ -n "$2" ]; then
      client="$2"
    else
      print_error "Client name is required for --add-client"
      exit 1
    fi
    new_client_setup
    exit 0
    ;;
  --remove-client)
    if [ -n "$2" ]; then
      client="$2"
      # Remove client configuration
      if grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; then
        wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
        sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
        print_success "Client '$client' removed successfully!"
      else
        print_error "Client '$client' not found!"
        exit 1
      fi
    else
      print_error "Client name is required for --remove-client"
      exit 1
    fi
    exit 0
    ;;
  --list-clients)
    if [ -f /etc/wireguard/wg0.conf ]; then
      echo -e "\n${BLUE}Existing clients:${NC}"
      grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3
    else
      print_error "No WireGuard configuration found!"
      exit 1
    fi
    exit 0
    ;;
  --help)
    print_usage
    exit 0
    ;;
  *)
    # If no arguments provided, continue with interactive mode
    return
    ;;
  esac
}

# Handle command line arguments
if [ $# -gt 0 ]; then
  handle_args "$@"
fi

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
  print_error 'This installer needs to be run with "bash", not "sh".'
  exit 1
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
  os="ubuntu"
  os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
  os="debian"
  os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
  os="centos"
  os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
elif [[ -e /etc/fedora-release ]]; then
  os="fedora"
  os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
else
  print_error "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
  exit 1
fi

# Check OS version requirements
if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
  print_error "Ubuntu 22.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
  exit 1
fi

if [[ "$os" == "debian" ]]; then
  if grep -q '/sid' /etc/debian_version; then
    print_error "Debian Testing and Debian Unstable are unsupported by this installer."
    exit 1
  fi
  if [[ "$os_version" -lt 11 ]]; then
    print_error "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
    exit 1
  fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
  os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
  print_error "$os_name 9 or higher is required to use this installer.
This version of $os_name is too old and unsupported."
  exit 1
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<<"$PATH"; then
  print_error '$PATH does not include sbin. Try using "su -" instead of "su".'
  exit 1
fi

# Detect if BoringTun (userspace WireGuard) needs to be used
if ! systemd-detect-virt -cq; then
  # Not running inside a container
  use_boringtun="0"
elif grep -q '^wireguard ' /proc/modules; then
  # Running inside a container, but the wireguard kernel module is available
  use_boringtun="0"
else
  # Running inside a container and the wireguard kernel module is not available
  use_boringtun="1"
fi

if [[ "$EUID" -ne 0 ]]; then
  print_error "This installer needs to be run with superuser privileges."
  exit 1
fi

if [[ "$use_boringtun" -eq 1 ]]; then
  if [ "$(uname -m)" != "x86_64" ]; then
    print_error "In containerized systems without the wireguard kernel module, this installer
supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
    exit 1
  fi
  # TUN device is required to use BoringTun
  if [[ ! -e /dev/net/tun ]] || ! (exec 7<>/dev/net/tun) 2>/dev/null; then
    print_error "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
    exit 1
  fi
fi

get_primary_interface() {
  # Get the interface with default route
  local interface=$(ip -4 route show default | grep -Po '(?<=dev )(\S+)')
  if [[ -z "$interface" ]]; then
    # Fallback to first non-loopback interface
    interface=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
  fi
  echo "$interface"
}
PRIMARY_INTERFACE=$(get_primary_interface)

# Main script flow
if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
  # Install required packages and upgrade the system
  print_status "Installing required packages..."
  apt-get update
  apt-get install -y wireguard iptables resolvconf qrencode

  if [[ "$use_boringtun" -eq 1 ]]; then
    print_status "Installing BoringTun..."
    apt-get install -y curl
    curl -Lo /usr/local/bin/boringtun "https://github.com/cloudflare/boringtun/releases/latest/download/boringtun-linux-x86_64"
    chmod +x /usr/local/bin/boringtun
  fi
elif [[ "$os" == "centos" ]]; then
  # Install required packages and upgrade the system
  print_status "Installing required packages..."
  dnf install -y epel-release
  dnf install -y wireguard-tools iptables qrencode

  if [[ "$use_boringtun" -eq 1 ]]; then
    print_status "Installing BoringTun..."
    dnf install -y curl
    curl -Lo /usr/local/bin/boringtun "https://github.com/cloudflare/boringtun/releases/latest/download/boringtun-linux-x86_64"
    chmod +x /usr/local/bin/boringtun
  fi
elif [[ "$os" == "fedora" ]]; then
  # Install required packages and upgrade the system
  print_status "Installing required packages..."
  dnf install -y wireguard-tools iptables qrencode

  if [[ "$use_boringtun" -eq 1 ]]; then
    print_status "Installing BoringTun..."
    dnf install -y curl
    curl -Lo /usr/local/bin/boringtun "https://github.com/cloudflare/boringtun/releases/latest/download/boringtun-linux-x86_64"
    chmod +x /usr/local/bin/boringtun
  fi
fi

# Enable IP forwarding
print_status "Enabling IP forwarding..."
echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/99-wireguard.conf
echo "net.ipv6.conf.all.forwarding = 1" >>/etc/sysctl.d/99-wireguard.conf
sysctl --system

# Generate WireGuard configuration
print_status "Generating WireGuard configuration..."
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey >/etc/wireguard/server_public.key
chmod 600 /etc/wireguard/server_private.key

# Get server IP
SERVER_IP=$(curl -s https://api.ipify.org)
if [[ -z "$SERVER_IP" ]]; then
  print_error "Could not determine server IP address."
  exit 1
fi

# Create WireGuard configuration
cat <<EOF >/etc/wireguard/wg0.conf
[Interface]
PrivateKey = $(cat /etc/wireguard/server_private.key)
Address = 10.59.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE

# ENDPOINT $SERVER_IP
EOF

# Start and enable WireGuard
print_status "Starting WireGuard service..."
if [[ "$use_boringtun" -eq 1 ]]; then
  systemctl enable --now boringtun@wg0
else
  systemctl enable --now wg-quick@wg0
fi

print_success "WireGuard has been installed and configured successfully!"
print_status "You can now use the wireguard-vps-proxy-setup script to manage clients."

exit 0
