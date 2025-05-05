#!/bin/bash
#
# StartOS WireGuard VPS Setup Tool
# https://github.com/start9labs/wg-vps-setup
# Derived from github.com/Nyr/wireguard-install (MIT License)

# --- Initial Checks and Setup ---

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
  echo 'This installer needs to be run with "bash", not "sh".'
  exit 1
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Helper Functions ---

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

# Function to get primary network interface
get_primary_interface() {
    # Get the interface with default route
    local interface=$(ip -4 route show default | grep -Po '(?<=dev )(\S+)')
    if [[ -z "$interface" ]]; then
        # Fallback to first non-loopback interface
        interface=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
    fi
    # Fallback to first non-loopback interface if still empty
    if [[ -z "$interface" ]]; then
        interface=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n1 | sed 's/ //g')
    fi

    if [[ -z "$interface" ]]; then
        print_error "Could not detect the primary network interface."
        exit 1
    fi
    echo "$interface"
}

# Function to get public IPv4 address
get_ipv4() {
  local ip
  ip=$(ip -4 addr show "$PRIMARY_INTERFACE" | grep "inet" | head -1 | awk '{print $2}' | cut -d "/" -f 1)
  # Fallback to external service if local detection fails or yields private IP
  if [[ -z "$ip" ]] || [[ "$ip" == 10.* || "$ip" == 192.168.* || "$ip" == 172.{16..31}.* ]]; then
    ip=$(curl -s https://api.ipify.org || curl -s https://icanhazip.com)
  fi
  if [[ -z "$ip" ]]; then
    print_error "Could not automatically determine the public IPv4 address."
    # Attempt manual input if interactive
    if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
        read -p "Enter the public IPv4 address: " ip
        if [[ -z "$ip" ]]; then
            print_error "Public IPv4 address is required."
            exit 1
        fi
    else
        print_error "Public IPv4 address detection failed in non-interactive mode."
        exit 1
    fi
  fi
  echo "$ip"
}

# Function to get public IPv6 address (basic detection)
get_ipv6() {
  local ip6
  ip6=$(ip -6 addr show "$PRIMARY_INTERFACE" | grep 'inet6' | grep -v 'fe80' | grep 'global' | head -n1 | awk '{print $2}' | cut -d'/' -f1)
  # Optionally add external service check if needed
  echo "$ip6"
}


# Function to setup a new client
new_client_setup () {
  local client_arg="$1"
  local client=""
  local default_client_name=""

  # Determine default client name
  if [[ -n "$STARTOS_HOSTNAME" ]]; then
    default_client_name="${STARTOS_HOSTNAME}"
  else
    # Find the next available default name like client1, client2, etc.
    local i=1
    while grep -q "^# BEGIN_PEER client${i}$" /etc/wireguard/wg0.conf 2>/dev/null; do
        ((i++))
    done
    default_client_name="client${i}"
  fi


  # If client name is not provided via argument or --client-name flag
  if [[ -z "$client_arg" ]] && [[ -z "$CLIENT_NAME" ]]; then
      if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
          client="$default_client_name"
          print_status "Using default client name: $client"
      else
          echo
          echo "Provide a name for the client (leave empty for default: $default_client_name):"
          read -p "Name: " unsanitized_client
          if [[ -z "$unsanitized_client" ]]; then
              unsanitized_client="$default_client_name"
          fi
          # Allow a limited length and set of characters to avoid conflicts
          client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
          while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
              echo "$client: invalid name or already exists."
              read -p "Name: " unsanitized_client
               if [[ -z "$unsanitized_client" ]]; then
                  unsanitized_client="$default_client_name" # Re-check default availability if empty
              fi
              client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
          done
      fi
  elif [[ -n "$client_arg" ]]; then
      client="$client_arg"
  elif [[ -n "$CLIENT_NAME" ]]; then
      client="$CLIENT_NAME"
  fi


  # Sanitize the client name (again, just in case)
  client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$client" | cut -c-15)

  # Check if sanitized name is empty or exists (needed if CLIENT_NAME was provided)
  if [[ -z "$client" ]]; then
       print_error "Client name cannot be empty after sanitization."
       return 1
  fi
   if grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; then
        if [[ "$NON_INTERACTIVE" -eq 1 ]] || [[ "$CLIENT_NAME" != "" ]]; then
            print_error "Client '$client' already exists."
            return 1
        else
            # This case should have been caught by the interactive loop, but handle defensively
             print_error "Client '$client' already exists."
             return 1
        fi
   fi


  # Given a list of the assigned internal IPv4 addresses, obtain the lowest still
  # available octet. Important to start looking at 2, because 1 is our gateway.
  local octet=2
  while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
    (( octet++ ))
  done
  # Don't break the WireGuard configuration in case the address space is full
  if [[ "$octet" -gt 254 ]]; then # Allow up to .254
    print_error "253 clients are already configured. The WireGuard internal IPv4 subnet is full!"
    exit 1
  fi

  local key=$(wg genkey)
  local psk=$(wg genpsk)
  local server_pubkey=$(wg pubkey < /etc/wireguard/server_private.key)
  local server_endpoint=$(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3)
  local server_port=$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
  local client_conf_path=~/"$client.conf"

  # Determine IPv6 parts
  local wg_ipv6_enabled=$(grep -q 'fddd:2c4:2c4:2c4::1/64' /etc/wireguard/wg0.conf && echo "yes")
  local ipv6_peer_part=""
  local ipv6_client_part=""
  if [[ "$wg_ipv6_enabled" == "yes" ]]; then
      ipv6_peer_part=", fddd:2c4:2c4:2c4::$octet/128"
      ipv6_client_part=", fddd:2c4:2c4:2c4::$octet/64"
  fi

  # Configure client in the server config file
  cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = 10.59.0.$octet/32$ipv6_peer_part
# END_PEER $client
EOF

  # Create client configuration file
  cat << EOF > "$client_conf_path"
[Interface]
Address = 10.59.0.$octet/24$ipv6_client_part
PrivateKey = $key
DNS = 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $server_pubkey
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $server_endpoint:$server_port
PersistentKeepalive = 25
EOF

  chmod 600 "$client_conf_path"
  print_success "Client configuration created: $client_conf_path"

  # Display QR code if qrencode is available
  if command -v qrencode &> /dev/null; then
    print_status "Scan this QR code with your WireGuard app (or view file content):"
    qrencode -t ansiutf8 < "$client_conf_path"
    echo # Newline after QR code
  else
    print_warning "qrencode not found. Install it to display QR codes for client configurations."
    print_status "Client config file content:"
    cat "$client_conf_path"
    echo # Newline after file content
  fi
  return 0 # Success
}


# Function to list all clients
list_clients() {
  if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    print_error "WireGuard is not installed. There are no clients to list."
    return 1
  fi

  print_status "WireGuard clients:"
  if ! grep -q '^# BEGIN_PEER' /etc/wireguard/wg0.conf; then
      echo "  No clients configured yet."
      return 0
  fi
  grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
  return 0
}

# Function to remove a client
remove_client() {
  local client_arg="$1"
  local client=""

  if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    print_error "WireGuard is not installed. There are no clients to remove."
    return 1
  fi

  local number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
  if [[ "$number_of_clients" = 0 ]]; then
    print_error "There are no existing clients to remove!"
    return 1
  fi

  # If client name is not provided via argument or --client-name flag, ask interactively
  if [[ -z "$client_arg" ]] && [[ -z "$CLIENT_NAME" ]]; then
       if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
            print_error "Client name must be specified with --client-name in non-interactive mode for removal."
            return 1
       fi
      echo
      echo "Select the client to remove:"
      # Ensure list_clients prints before the prompt
      list_clients || return 1 # Exit if listing fails (e.g., no clients)

      # Re-count in case list_clients found none despite initial check
      number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
      if [[ "$number_of_clients" = 0 ]]; then
           # Message already printed by list_clients or earlier check
           return 1
      fi

      read -p "Client number: " client_number
      until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -ge 1 && "$client_number" -le "$number_of_clients" ]]; do
        echo "$client_number: invalid selection."
        read -p "Client number: " client_number
      done
      client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
  elif [[ -n "$client_arg" ]]; then
      client="$client_arg"
  elif [[ -n "$CLIENT_NAME" ]]; then
       client="$CLIENT_NAME"
  fi

   # Sanitize the client name just in case
  client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$client" | cut -c-15)


  # Check if client exists after determining the name
  if ! grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; then
    print_error "Client '$client' does not exist."
    return 1
  fi

  # Confirmation (skip in non-interactive mode)
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    echo
    read -p "Confirm removal of client '$client'? [y/N]: " remove
    until [[ "$remove" =~ ^[yYnN]*$ ]]; do
      echo "$remove: invalid selection."
      read -p "Confirm removal of client '$client'? [y/N]: " remove
    done
    if [[ ! "$remove" =~ ^[yY]$ ]]; then
      print_warning "Client '$client' removal aborted!"
      return 1
    fi
  fi

  # Get client's public key to remove from live interface
  local client_pubkey=$(sed -n "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)

  # Remove from the live interface if the service is active
  if systemctl is-active --quiet wg-quick@wg0.service || systemctl is-active --quiet boringtun@wg0.service; then
      print_status "Removing peer $client_pubkey from live interface..."
      wg set wg0 peer "$client_pubkey" remove
      if [[ $? -ne 0 ]]; then
         print_warning "Failed to remove peer from live interface. It might already be gone or the interface isn't fully up."
      fi
  else
      print_warning "WireGuard service not active, skipping removal from live interface."
  fi


  # Remove from the configuration file
  print_status "Removing client '$client' from configuration file..."
  sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf

  # Remove the client's conf file
  local client_conf_path=~/"$client.conf"
   if [[ -f "$client_conf_path" ]]; then
       print_status "Removing client configuration file: $client_conf_path"
       rm -f "$client_conf_path"
   fi


  print_success "Client '$client' removed successfully!"
  return 0
}


# Function to remove WireGuard completely
remove_wireguard() {
    local ip=$(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3 2>/dev/null)
    local ip6=$(get_ipv6) # Re-detect just in case
    local port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3 2>/dev/null || echo "51820") # Default if not found

    print_status "Removing WireGuard..."

    # Stop WireGuard service
    if systemctl is-active --quiet wg-quick@wg0.service; then
        systemctl disable --now wg-quick@wg0.service
    fi
     if systemctl is-active --quiet boringtun@wg0.service; then
        systemctl disable --now boringtun@wg0.service
    fi


    # Remove firewall rules
    if systemctl is-active --quiet firewalld.service; then
      print_status "Removing firewalld rules..."
      # Use permanent first to ensure removal even if runtime fails
      firewall-cmd --permanent --remove-port="$port"/udp
      firewall-cmd --permanent --zone=trusted --remove-source=10.59.0.0/24
      firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to "$ip"
      firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -i wg0 -j ACCEPT
      firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -o wg0 -j ACCEPT
      firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
      firewall-cmd --permanent --direct --remove-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
      firewall-cmd --permanent --direct --remove-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2
      firewall-cmd --permanent --direct --remove-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
      firewall-cmd --permanent --direct --remove-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
      firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
      firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
      firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -j ACCEPT


      # Remove IPv6 rules if they were likely added
      if grep -qs 'fddd:2c4:2c4:2c4::1/64' /etc/wireguard/wg0.conf 2>/dev/null; then
            firewall-cmd --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
            firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
            firewall-cmd --permanent --direct --remove-rule ipv6 filter FORWARD 0 -i wg0 -j ACCEPT
            firewall-cmd --permanent --direct --remove-rule ipv6 filter FORWARD 0 -o wg0 -j ACCEPT
            firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
            firewall-cmd --permanent --direct --remove-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --permanent --direct --remove-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --permanent --direct --remove-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --permanent --direct --remove-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1
            firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source fddd:2c4:2c4:2c4::1
            firewall-cmd --permanent --direct --remove-rule ipv6 filter FORWARD 0 -j ACCEPT
      fi
      firewall-cmd --reload # Apply permanent changes
    elif [[ -f /etc/systemd/system/wg-iptables.service ]]; then
      print_status "Removing iptables service..."
      systemctl disable --now wg-iptables.service
      rm -f /etc/systemd/system/wg-iptables.service
      systemctl daemon-reload
    else
        print_warning "No firewalld or wg-iptables service found. Manual firewall rule cleanup might be needed."
    fi

    # Remove sysctl config
    print_status "Removing sysctl configuration..."
    rm -f /etc/sysctl.d/99-wireguard-forward.conf /etc/sysctl.d/99-wireguard.conf
    sysctl --system # Reload sysctl rules

    # Remove BoringTun components if they exist
    if [[ -f /usr/local/sbin/boringtun-upgrade ]]; then
        print_status "Removing BoringTun components..."
        { crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
        rm -f /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
    fi
    rm -f /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf # Remove override if present
    systemctl daemon-reload


    # Remove WireGuard packages and configuration directory
    print_status "Removing WireGuard packages and configuration..."
    rm -rf /etc/wireguard/
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt-get remove --purge -y wireguard wireguard-tools qrencode curl &> /dev/null # Suppress output
        apt-get autoremove -y &> /dev/null
    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
        dnf remove -y wireguard-tools qrencode curl &> /dev/null # Suppress output
        # Epel-release might be needed by others, don't remove automatically
    fi


    print_success "WireGuard removed successfully!"
}


# Function to display help information
show_help() {
  echo "Usage: $(basename $0) [OPTIONS]"
  echo
  echo "Installs and manages a WireGuard VPN server, tailored for StartOS VPS proxy setup."
  echo
  echo "Options:"
  echo "  --non-interactive         Run in non-interactive mode (uses defaults or requires --client-name)"
  echo "  --add-client              Add a new client (requires WireGuard installed)"
  echo "  --remove-client           Remove an existing client (requires WireGuard installed)"
  echo "  --list-clients            List all existing clients (requires WireGuard installed)"
  echo "  --client-name NAME        Specify client name for --add-client / --remove-client"
  echo "                            (sanitized, max 15 chars: a-z, A-Z, 0-9, _, -)"
  echo "  -h, --help                Show this help message"
  echo
  echo "Examples:"
  echo "  $(basename $0)                              # Run interactively (install or manage)"
  echo "  $(basename $0) --non-interactive           # Install WireGuard non-interactively (first client named 'client1' or STARTOS_HOSTNAME)"
  echo "  $(basename $0) --add-client                # Add a client interactively"
  echo "  $(basename $0) --add-client --client-name phone # Add a client named 'phone'"
  echo "  $(basename $0) --non-interactive --add-client --client-name phone # Add 'phone' non-interactively"
  echo "  $(basename $0) --remove-client              # Remove a client interactively"
  echo "  $(basename $0) --remove-client --client-name laptop # Remove client named 'laptop'"
  echo "  $(basename $0) --list-clients              # List all clients"
}


# --- Script Execution Start ---

# Command line parameters initialization
NON_INTERACTIVE=0
ADD_CLIENT=0
REMOVE_CLIENT=0
LIST_CLIENTS=0
CLIENT_NAME=""
SHOW_HELP=0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    --add-client)
      ADD_CLIENT=1
      shift
      ;;
    --remove-client)
      REMOVE_CLIENT=1
      shift
      ;;
    --list-clients)
      LIST_CLIENTS=1
      shift
      ;;
    --client-name)
      if [[ -z "$2" ]] || [[ "$2" == --* ]]; then
         print_error "--client-name requires a NAME argument."
         exit 1
      fi
      CLIENT_NAME="$2"
      shift 2
      ;;
    -h|--help)
      SHOW_HELP=1
      shift
      ;;
    *)
      # Unknown option
      print_warning "Unknown option: $1"
      shift
      ;;
  esac
done

# Show help and exit if requested
if [[ "$SHOW_HELP" -eq 1 ]]; then
    show_help
    exit 0
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
  os="ubuntu"
  os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
  os="debian"
  os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
  # Treat Rocky, Alma, and CentOS 9+ as 'centos' for simplicity
  os="centos"
  os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
elif [[ -e /etc/fedora-release ]]; then
  os="fedora"
  os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
else
  print_error "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu (22.04+), Debian (11+), AlmaLinux/Rocky/CentOS (9+), and Fedora."
  exit 1
fi

# Check OS version requirements
if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
  print_error "Ubuntu 22.04 or higher is required to use this installer."
  exit 1
fi

if [[ "$os" == "debian" ]]; then
  if grep -q '/sid' /etc/debian_version; then
    print_error "Debian Testing and Debian Unstable are unsupported by this installer."
    exit 1
  fi
  if [[ "$os_version" -lt 11 ]]; then
    print_error "Debian 11 or higher is required to use this installer."
    exit 1
  fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
  os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1 || echo "This EL variant")
  print_error "$os_name 9 or higher is required to use this installer."
  exit 1
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
  print_error '$PATH does not include sbin directories. Try using "su -" instead of "su".'
  exit 1
fi

# Root check
if [[ "$EUID" -ne 0 ]]; then
  print_error "This installer needs to be run with superuser privileges (e.g., using sudo)."
  exit 1
fi

# Detect if BoringTun (userspace WireGuard) needs to be used
use_boringtun="0" # Default to kernel module
# Check if running in a container AND wireguard module is NOT loaded
if systemd-detect-virt -cq && ! grep -q '^wireguard ' /proc/modules; then
  use_boringtun="1"
  print_warning "WireGuard kernel module not found, likely running in a container."
  print_warning "Will attempt to use BoringTun (userspace implementation)."

  if [ "$(uname -m)" != "x86_64" ]; then
    print_error "BoringTun setup supports only x86_64 architecture in containerized environments without the kernel module."
    exit 1
  fi
  # TUN device is required to use BoringTun
  if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
    print_error "The system does not have the TUN device available (/dev/net/tun)."
    print_error "TUN needs to be enabled/passed-through by the container host."
    exit 1
  fi
fi


# --- Handle Command Line Actions ---

PRIMARY_INTERFACE=$(get_primary_interface) # Detect early for potential use in actions

# Handle specific command line operations before checking installation status
if [[ "$LIST_CLIENTS" -eq 1 ]]; then
  list_clients
  exit $?
fi

if [[ "$ADD_CLIENT" -eq 1 ]]; then
  if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    print_error "WireGuard is not installed. Cannot add client."
    print_status "Run the script without flags to install WireGuard first."
    exit 1
  fi
  # Call new_client_setup, respecting CLIENT_NAME if provided
  if new_client_setup "$CLIENT_NAME"; then
        # Get the client name used (it might be default or sanitized)
        added_client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | tail -n 1 | cut -d ' ' -f 3)
        # Append new client configuration to the WireGuard interface live
        print_status "Adding peer configuration to live interface..."
        wg addconf wg0 <(sed -n "/^# BEGIN_PEER $added_client$/,/^# END_PEER $added_client$/p" /etc/wireguard/wg0.conf)
        if [[ $? -eq 0 ]]; then
            print_success "Client '$added_client' added and configuration applied."
        else
            print_error "Failed to apply configuration to live interface. Restarting service might be needed."
        fi
        exit 0
    else
        # Error message printed by new_client_setup
        exit 1
    fi
fi

if [[ "$REMOVE_CLIENT" -eq 1 ]]; then
  if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    print_error "WireGuard is not installed. Cannot remove client."
    exit 1
  fi
  # remove_client handles CLIENT_NAME and NON_INTERACTIVE checks internally
  remove_client
  exit $?
fi

# --- Main Logic: Install or Manage ---

# Check if WireGuard is already installed
if [[ -e /etc/wireguard/wg0.conf ]]; then
  # --- WireGuard is already installed: Interactive Management Menu ---
  # If non-interactive flag was used without a specific action, it's an error here.
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    print_error "WireGuard is already installed. Use --add-client, --remove-client, or --list-clients options in non-interactive mode."
    exit 1
  fi

  clear
  print_status "WireGuard is already installed."
  echo
  echo "Select an option:"
  echo "   1) Add a new client"
  echo "   2) Remove an existing client"
  echo "   3) List existing clients"
  echo "   4) Remove WireGuard completely"
  echo "   5) Exit"
  echo
  read -p "Option [1-5]: " option
  until [[ "$option" =~ ^[1-5]$ ]]; do
    echo "$option: invalid selection."
    read -p "Option [1-5]: " option
  done
  case "$option" in
    1)
      # Call new_client_setup - it handles interaction and defaults
      if new_client_setup ""; then # Pass empty string to trigger interactive name prompt if needed
            # Get the client name used
            added_client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | tail -n 1 | cut -d ' ' -f 3)
            # Append new client configuration to the WireGuard interface live
            print_status "Adding peer configuration to live interface..."
            wg addconf wg0 <(sed -n "/^# BEGIN_PEER $added_client$/,/^# END_PEER $added_client$/p" /etc/wireguard/wg0.conf)
             if [[ $? -eq 0 ]]; then
                print_success "Client '$added_client' added and configuration applied."
            else
                print_error "Failed to apply configuration to live interface. Restarting service might be needed."
             fi
      else
          # Error message printed by new_client_setup
          exit 1 # Exit script after failed attempt
      fi
      exit 0
      ;;
    2)
      # remove_client handles interaction
      remove_client "" # Pass empty string to trigger interactive selection
      exit $?
      ;;
    3)
       list_clients
       exit $?
       ;;
    4)
      echo
      read -p "Confirm WireGuard removal? This is irreversible. [y/N]: " remove
      until [[ "$remove" =~ ^[yYnN]*$ ]]; do
        echo "$remove: invalid selection."
        read -p "Confirm WireGuard removal? [y/N]: " remove
      done
      if [[ "$remove" =~ ^[yY]$ ]]; then
        remove_wireguard
      else
        echo
        print_warning "WireGuard removal aborted!"
      fi
      exit 0
      ;;
    5)
      exit 0
      ;;
  esac

else
  # --- WireGuard is NOT installed: Proceed with Installation ---
  print_status "WireGuard is not installed. Starting installation process..."

  # Get network configuration
  # PRIMARY_INTERFACE already detected
  ip=$(get_ipv4)
  ip6=$(get_ipv6) # May be empty if no IPv6 found
  port="51820" # Default WireGuard port
  enable_ipv6=0
  boringtun_updates="n" # Default for BoringTun updates

  # Interactive prompts if not in non-interactive mode
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
      echo
      read -p "Public IPv4 address [$ip]: " input_ip
      ip=${input_ip:-$ip}

      if [[ -n "$ip6" ]]; then
          read -p "Public IPv6 address [$ip6]: " input_ip6
          ip6=${input_ip6:-$ip6}
      fi

      read -p "WireGuard port [$port]: " input_port
      port=${input_port:-$port}
      # Basic port validation
      until [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; do
           echo "$port: invalid port."
           read -p "WireGuard port [51820]: " input_port
           port=${input_port:-51820}
      done


      if [[ -n "$ip6" ]]; then
        echo
        read -p "Enable IPv6 routing for WireGuard? [y/N]: " enable_ipv6_input
         until [[ "$enable_ipv6_input" =~ ^[yYnN]*$ ]]; do
            echo "$enable_ipv6_input: invalid selection."
            read -p "Enable IPv6 routing for WireGuard? [y/N]: " enable_ipv6_input
        done
        if [[ "$enable_ipv6_input" =~ ^[yY]$ ]]; then
            enable_ipv6=1
        fi
      fi

      if [[ "$use_boringtun" -eq 1 ]]; then
          echo
          read -p "Enable automatic updates for BoringTun? [y/N]: " boringtun_updates_input
          until [[ "$boringtun_updates_input" =~ ^[yYnN]*$ ]]; do
              echo "$boringtun_updates_input: invalid selection."
              read -p "Enable automatic updates for BoringTun? [y/N]: " boringtun_updates_input
          done
          if [[ "$boringtun_updates_input" =~ ^[yY]$ ]]; then
              boringtun_updates="y"
          fi
      fi
  elif [[ -n "$ip6" ]]; then
      # Default enable IPv6 if detected in non-interactive mode
      enable_ipv6=1
      print_status "IPv6 detected, enabling IPv6 routing."
  fi


  # Install required packages and potentially BoringTun
  print_status "Updating package list and installing required packages..."
  if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive # Avoid prompts
    apt-get update -qq
    apt-get install -y -qq wireguard iptables qrencode curl ca-certificates &> /dev/null
    if [[ "$use_boringtun" -eq 1 ]]; then
        print_status "Installing BoringTun..."
        # Use curl already installed
        curl -sLo /usr/local/sbin/boringtun "https://wg.nyr.be/1/latest/download" || \
        curl -sLo /usr/local/sbin/boringtun "https://github.com/cloudflare/boringtun/releases/latest/download/boringtun-linux-x86_64"
        if [[ ! -f /usr/local/sbin/boringtun ]]; then
             print_error "Failed to download BoringTun."
             exit 1
        fi
        chmod +x /usr/local/sbin/boringtun
    fi
  elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
    # CentOS/Rocky/Alma need EPEL for qrencode. Fedora usually has it.
    if [[ "$os" == "centos" ]]; then
        dnf install -y -q epel-release &> /dev/null || print_warning "Could not install EPEL release. Qrencode might fail."
    fi
    dnf install -y -q wireguard-tools iptables qrencode curl ca-certificates &> /dev/null
    if [[ "$use_boringtun" -eq 1 ]]; then
      print_status "Installing BoringTun..."
      # Use curl already installed
      curl -sLo /usr/local/sbin/boringtun "https://wg.nyr.be/1/latest/download" || \
      curl -sLo /usr/local/sbin/boringtun "https://github.com/cloudflare/boringtun/releases/latest/download/boringtun-linux-x86_64"
      if [[ ! -f /usr/local/sbin/boringtun ]]; then
           print_error "Failed to download BoringTun."
           exit 1
      fi
      chmod +x /usr/local/sbin/boringtun
    fi
  fi
  print_success "Required packages installed."

  # Enable IP forwarding
  print_status "Enabling IP forwarding..."
  # Use 99-wireguard-forward.conf to maybe avoid conflict with Nyr script's 99-wireguard.conf if run later
  echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard-forward.conf
  if [[ "$enable_ipv6" -eq 1 ]]; then
    echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard-forward.conf
  else
     # Explicitly disable if not enabled, or remove if exists
     sed -i '/net.ipv6.conf.all.forwarding/d' /etc/sysctl.d/99-wireguard-forward.conf
  fi
  sysctl -p /etc/sysctl.d/99-wireguard-forward.conf &> /dev/null # Apply silently


  # Generate WireGuard keys and configuration directory
  print_status "Generating WireGuard server keys..."
  mkdir -p /etc/wireguard
  chmod 700 /etc/wireguard
  wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
  chmod 600 /etc/wireguard/server_private.key
  print_success "Server keys generated."

  # Create initial WireGuard configuration file (Interface section only)
  print_status "Creating WireGuard configuration file /etc/wireguard/wg0.conf..."
  cat << EOF > /etc/wireguard/wg0.conf
[Interface]
PrivateKey = $(cat /etc/wireguard/server_private.key)
Address = 10.59.0.1/24$( [[ "$enable_ipv6" -eq 1 ]] && echo ", fddd:2c4:2c4:2c4::1/64" )
ListenPort = $port
# PostUp/PostDown rules are handled by wg-iptables.service or firewalld rules below
# Add endpoint info for client config generation
# ENDPOINT $ip
EOF
  chmod 600 /etc/wireguard/wg0.conf
  print_success "Initial configuration file created."


  # Set up firewall rules
  print_status "Setting up firewall rules..."
  if systemctl is-active --quiet firewalld.service; then
    # Using Firewalld
    print_status "Firewalld detected. Adding rules..."
    # Add WireGuard port
    firewall-cmd --add-port="$port"/udp --permanent
    # Add WireGuard subnet to trusted zone for inter-client communication (optional, but often useful)
    firewall-cmd --zone=trusted --add-source=10.59.0.0/24 --permanent

    # Add MASQUERADE rule for outgoing traffic from VPN clients
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to "$ip"

    # Port forwarding rules (StartOS specific: forward all non-SSH/WG traffic to first client 10.59.0.2)
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i wg0 -j ACCEPT
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -o wg0 -j ACCEPT
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
    firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
    firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2
    firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
    firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -j ACCEPT

    # IPv6 rules if enabled
    if [[ "$enable_ipv6" -eq 1 ]] && [[ -n "$ip6" ]]; then
      print_status "Adding IPv6 firewall rules..."
      firewall-cmd --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64 --permanent
      firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
      firewall-cmd --permanent --direct --add-rule ipv6 filter FORWARD 0 -i wg0 -j ACCEPT
      firewall-cmd --permanent --direct --add-rule ipv6 filter FORWARD 0 -o wg0 -j ACCEPT
      firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
      firewall-cmd --permanent --direct --add-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --permanent --direct --add-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --permanent --direct --add-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --permanent --direct --add-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1
      firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source fddd:2c4:2c4:2c4::1
      firewall-cmd --permanent --direct --add-rule ipv6 filter FORWARD 0 -j ACCEPT
    fi
    print_status "Reloading Firewalld to apply rules..."
    firewall-cmd --reload
  else
    # Using iptables via systemd service
    print_status "Firewalld not active. Setting up iptables rules via systemd service..."
    iptables_path=$(command -v iptables)
    ip6tables_path=$(command -v ip6tables)

    # Check for iptables-legacy if needed (OpenVZ specific case)
    if [[ $(systemd-detect-virt 2>/dev/null) == "openvz" ]] && readlink -f "$iptables_path" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
      print_status "Detected OpenVZ with nftables backend, using iptables-legacy."
      iptables_path=$(command -v iptables-legacy)
      ip6tables_path=$(command -v ip6tables-legacy)
    fi

    # Create the systemd service file for iptables rules persistence
    cat << EOF > /etc/systemd/system/wg-iptables.service
[Unit]
Description=WireGuard IPTables Rules
After=network.target network-online.target
Requires=network-online.target
Wants=wg-quick@wg0.service boringtun@wg0.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c ' \
    "$iptables_path" -t nat -A POSTROUTING -s 10.59.0.0/24 ! -d 10.59.0.0/24 -o "$PRIMARY_INTERFACE" -j SNAT --to-source "$ip"; \
    "$iptables_path" -I INPUT -p udp --dport "$port" -j ACCEPT; \
    "$iptables_path" -I FORWARD -i wg0 -j ACCEPT; \
    "$iptables_path" -I FORWARD -o wg0 -j ACCEPT; \
    "$iptables_path" -t nat -A POSTROUTING -s 10.59.0.0/24 -o "$PRIMARY_INTERFACE" -j MASQUERADE; \
    "$iptables_path" -t nat -A PREROUTING -i "$PRIMARY_INTERFACE" -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2; \
    "$iptables_path" -t nat -A PREROUTING -i "$PRIMARY_INTERFACE" -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2; \
    "$iptables_path" -t nat -A PREROUTING -i wg0 -s 10.59.0.0/24 -d "$ip" -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2; \
    "$iptables_path" -t nat -A PREROUTING -i wg0 -s 10.59.0.0/24 -d "$ip" -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2; \
    "$iptables_path" -t nat -A POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1; \
    "$iptables_path" -t nat -A POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,"$port" -j SNAT --to-source 10.59.0.1; \
    "$iptables_path" -A FORWARD -j ACCEPT; \
    '$( [[ "$enable_ipv6" -eq 1 && -n "$ip6" ]] && echo ' \
    "$ip6tables_path" -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -o "$PRIMARY_INTERFACE" -j SNAT --to-source "$ip6"; \
    "$ip6tables_path" -I INPUT -p udp --dport "$port" -j ACCEPT; \
    "$ip6tables_path" -I FORWARD -i wg0 -j ACCEPT; \
    "$ip6tables_path" -I FORWARD -o wg0 -j ACCEPT; \
    "$ip6tables_path" -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 -o "$PRIMARY_INTERFACE" -j MASQUERADE; \
    "$ip6tables_path" -t nat -A PREROUTING -i "$PRIMARY_INTERFACE" -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2; \
    "$ip6tables_path" -t nat -A PREROUTING -i "$PRIMARY_INTERFACE" -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2; \
    "$ip6tables_path" -t nat -A PREROUTING -i wg0 -s fddd:2c4:2c4:2c4::/64 -d "$ip6" -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2; \
    "$ip6tables_path" -t nat -A PREROUTING -i wg0 -s fddd:2c4:2c4:2c4::/64 -d "$ip6" -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2; \
    "$ip6tables_path" -t nat -A POSTROUTING -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1; \
    "$ip6tables_path" -t nat -A POSTROUTING -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,"$port" -j SNAT --to-source fddd:2c4:2c4:2c4::1; \
    "$ip6tables_path" -A FORWARD -j ACCEPT; \
    ')

ExecStop=/bin/sh -c ' \
    "$iptables_path" -t nat -D POSTROUTING -s 10.59.0.0/24 ! -d 10.59.0.0/24 -o "$PRIMARY_INTERFACE" -j SNAT --to-source "$ip"; \
    "$iptables_path" -D INPUT -p udp --dport "$port" -j ACCEPT; \
    "$iptables_path" -D FORWARD -i wg0 -j ACCEPT; \
    "$iptables_path" -D FORWARD -o wg0 -j ACCEPT; \
    "$iptables_path" -t nat -D POSTROUTING -s 10.59.0.0/24 -o "$PRIMARY_INTERFACE" -j MASQUERADE; \
    "$iptables_path" -t nat -D PREROUTING -i "$PRIMARY_INTERFACE" -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2; \
    "$iptables_path" -t nat -D PREROUTING -i "$PRIMARY_INTERFACE" -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2; \
    "$iptables_path" -t nat -D PREROUTING -i wg0 -s 10.59.0.0/24 -d "$ip" -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2; \
    "$iptables_path" -t nat -D PREROUTING -i wg0 -s 10.59.0.0/24 -d "$ip" -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2; \
    "$iptables_path" -t nat -D POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1; \
    "$iptables_path" -t nat -D POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,"$port" -j SNAT --to-source 10.59.0.1; \
    "$iptables_path" -D FORWARD -j ACCEPT; \
    '$( [[ "$enable_ipv6" -eq 1 && -n "$ip6" ]] && echo ' \
    "$ip6tables_path" -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -o "$PRIMARY_INTERFACE" -j SNAT --to-source "$ip6"; \
    "$ip6tables_path" -D INPUT -p udp --dport "$port" -j ACCEPT; \
    "$ip6tables_path" -D FORWARD -i wg0 -j ACCEPT; \
    "$ip6tables_path" -D FORWARD -o wg0 -j ACCEPT; \
    "$ip6tables_path" -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 -o "$PRIMARY_INTERFACE" -j MASQUERADE; \
    "$ip6tables_path" -t nat -D PREROUTING -i "$PRIMARY_INTERFACE" -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2; \
    "$ip6tables_path" -t nat -D PREROUTING -i "$PRIMARY_INTERFACE" -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2; \
    "$ip6tables_path" -t nat -D PREROUTING -i wg0 -s fddd:2c4:2c4:2c4::/64 -d "$ip6" -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2; \
    "$ip6tables_path" -t nat -D PREROUTING -i wg0 -s fddd:2c4:2c4:2c4::/64 -d "$ip6" -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2; \
    "$ip6tables_path" -t nat -D POSTROUTING -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1; \
    "$ip6tables_path" -t nat -D POSTROUTING -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,"$port" -j SNAT --to-source fddd:2c4:2c4:2c4::1; \
    "$ip6tables_path" -D FORWARD -j ACCEPT; \
    ') || true # Ignore errors on stop

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/wg-iptables.service
    systemctl daemon-reload
    systemctl enable --now wg-iptables.service
  fi
  print_success "Firewall rules configured."


  # Setup the first client (will be 10.59.0.2 / fddd:...::2)
  print_status "Setting up the first client..."
  # new_client_setup handles interactive naming if needed, or uses defaults
  if ! new_client_setup ""; then
      print_error "Failed to set up the initial client."
      # Attempt cleanup? For now, just exit.
      exit 1
  fi
  first_client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | head -n 1 | cut -d ' ' -f 3) # Get the actual name used

  # Enable and start the WireGuard service
  print_status "Starting WireGuard service..."
  if [[ "$use_boringtun" -eq 1 ]]; then
      # Need to override the ExecStart for wg-quick to use boringtun
      mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
      cat << EOF > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_QUICK_SETUID_HELPER=1
ExecStart=
ExecStart=/usr/bin/wg-quick up %i
EOF
    systemctl daemon-reload
    systemctl enable --now wg-quick@wg0.service # Use wg-quick with override
    print_success "WireGuard service (using BoringTun) started and enabled."
  else
    systemctl enable --now wg-quick@wg0.service
    print_success "WireGuard service (using kernel module) started and enabled."
  fi

  # Set up automatic updates for BoringTun if requested
  if [[ "$use_boringtun" -eq 1 ]] && [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
    print_status "Setting up automatic BoringTun updates..."
    # Deploy upgrade script
    cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
# BoringTun auto-update script

# Source URL for latest version info and download link prefix
LATEST_INFO_URL="https://wg.nyr.be/1/latest"
DOWNLOAD_URL_PREFIX="https://wg.nyr.be/1/latest"
ALT_DOWNLOAD_URL_PREFIX="https://github.com/cloudflare/boringtun/releases/latest" # Fallback
BORINGTUN_BIN="/usr/local/sbin/boringtun"
SERVICE_NAME="wg-quick@wg0.service" # Service using BoringTun

# Fetch latest version info
latest_output=$(wget -qO- "$LATEST_INFO_URL" 2>/dev/null || curl -sL "$LATEST_INFO_URL" 2>/dev/null)

# Check if we got valid info
if ! echo "$latest_output" | head -1 | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
  echo "Update server unavailable or returned invalid data." >&2
  exit 1
fi
latest_version=$(echo "$latest_output" | head -1)

# Get current version
if [[ ! -x "$BORINGTUN_BIN" ]]; then
    echo "BoringTun binary not found at $BORINGTUN_BIN" >&2
    exit 1
fi
current_version=$("$BORINGTUN_BIN" -V)

echo "Current version: $current_version"
echo "Latest version:  $latest_version"

if [[ "$current_version" != "$latest_version" ]]; then
  echo "New version available. Attempting upgrade..."
  download_url="${DOWNLOAD_URL_PREFIX}/download"
  alt_download_url="${ALT_DOWNLOAD_URL_PREFIX}/download/boringtun-linux-x86_64"

  tmp_dir=$(mktemp -d)
  if [[ ! "$tmp_dir" || ! -d "$tmp_dir" ]]; then
    echo "Failed to create temporary directory" >&2
    exit 1
  fi
  trap 'rm -rf "$tmp_dir"' EXIT # Cleanup tmp dir on exit

  # Try primary download URL
  echo "Attempting download from $download_url..."
  if ! { wget -qO- "$download_url" 2>/dev/null || curl -sL "$download_url"; } > "$tmp_dir/boringtun.download"; then
      echo "Primary download failed. Trying alternative URL: $alt_download_url..."
      if ! { wget -qO "$tmp_dir/boringtun.download" "$alt_download_url" 2>/dev/null || curl -sLo "$tmp_dir/boringtun.download" "$alt_download_url"; }; then
          echo "Alternative download also failed." >&2
          exit 1
      fi
  fi

  # Check if downloaded file is executable (GitHub release) or needs extraction (Nyr source)
  if file "$tmp_dir/boringtun.download" | grep -q 'executable'; then
      echo "Downloaded executable."
      mv "$tmp_dir/boringtun.download" "$tmp_dir/boringtun"
      chmod +x "$tmp_dir/boringtun"
  elif file "$tmp_dir/boringtun.download" | grep -q 'gzip compressed data'; then
       echo "Downloaded archive, extracting..."
      if ! tar xzf "$tmp_dir/boringtun.download" -C "$tmp_dir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
          echo "Failed to extract BoringTun binary from archive." >&2
          exit 1
      fi
  else
      echo "Downloaded file is not a recognized format (executable or tar.gz)." >&2
      exit 1
  fi


  if [[ ! -f "$tmp_dir/boringtun" ]]; then
      echo "Extracted binary not found." >&2
      exit 1
  fi

  echo "Stopping WireGuard service..."
  systemctl stop "$SERVICE_NAME"
  sleep 1 # Give service time to stop

  echo "Replacing binary..."
  # Use mv which is atomic on the same filesystem
  if mv "$tmp_dir/boringtun" "$BORINGTUN_BIN"; then
      chmod +x "$BORINGTUN_BIN"
      echo "Starting WireGuard service..."
      systemctl start "$SERVICE_NAME"
      sleep 1 # Give service time to start
      new_version=$("$BORINGTUN_BIN" -V)
      echo "Successfully updated to $new_version"
  else
      echo "Failed to replace BoringTun binary. Attempting to restore service..." >&2
      systemctl start "$SERVICE_NAME" # Try starting old version if possible
      exit 1
  fi
else
  echo "$current_version is already the latest version."
fi

exit 0
EOF
    chmod +x /usr/local/sbin/boringtun-upgrade
    # Add cron job to run the updater daily at a random time between 3:00 and 5:59 AM
    print_status "Adding cron job for daily update check..."
    ( crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade'; \
      echo "$(( $RANDOM % 60 )) $(( $RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ) \
      | crontab -
    print_success "BoringTun auto-update configured."
  fi

  echo
  print_success "WireGuard installation and setup finished!"
  echo
  print_status "The first client configuration is available in:" ~/"$first_client.conf"
  print_status "You can add more clients using: $(basename $0) --add-client"

fi # End of installation check (if/else)

exit 0