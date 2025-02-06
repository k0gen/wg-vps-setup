#!/bin/bash
#
# StartOS WireGuard VPS Setup Tool
# https://github.com/start9labs/wg-vps-setup
# Derived from github.com/Nyr/wireguard-install (MIT License)

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$/exe | grep -q "dash"; then
  echo 'This installer needs to be run with "bash", not "sh".'
  exit
fi

# Function to ensure script runs with root privileges by auto-elevating if needed
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        exec sudo "$0"
    fi
}

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
  echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
  exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
  echo "Ubuntu 22.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
  exit
fi

if [[ "$os" == "debian" ]]; then
  if grep -q '/sid' /etc/debian_version; then
    echo "Debian Testing and Debian Unstable are unsupported by this installer."
    exit
  fi
  if [[ "$os_version" -lt 11 ]]; then
    echo "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
    exit
  fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
  os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
  echo "$os_name 9 or higher is required to use this installer.
This version of $os_name is too old and unsupported."
  exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
  echo '$PATH does not include sbin. Try using "su -" instead of "su".'
  exit
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

# Check if the script is run as root before anything else
check_root

if [[ "$use_boringtun" -eq 1 ]]; then
  if [ "$(uname -m)" != "x86_64" ]; then
    echo "In containerized systems without the wireguard kernel module, this installer
supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
    exit
  fi
  # TUN device is required to use BoringTun
  if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
    echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
    exit
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

new_client_setup () {
  # Given a list of the assigned internal IPv4 addresses, obtain the lowest still
  # available octet. Important to start looking at 2, because 1 is our gateway.
  octet=2
  while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
    (( octet++ ))
  done
  # Don't break the WireGuard configuration in case the address space is full
  if [[ "$octet" -eq 255 ]]; then
    echo "253 clients are already configured. The WireGuard internal subnet is full!"
    exit
  fi
  key=$(wg genkey)
  psk=$(wg genpsk)
  # Configure client in the server
  cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = 10.59.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
  # Create client configuration
  cat << EOF > ~/"$client".conf
[Interface]
Address = 10.59.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
}

if [[ ! -e /etc/wireguard/wg0.conf ]]; then
  # Detect some Debian minimal setups where neither wget nor curl are installed
  if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
    echo "Wget is required to use this installer."
    read -n1 -r -p "Press any key to install Wget and continue..."
    apt-get update
    apt-get install -y wget
  fi
  clear
  echo 'Welcome to StartOS WireGuard Clearnet Gateway Setup!'
  # If system has a single IPv4, it is selected automatically. Else, ask the user
  if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
    ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
  else
    number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
    echo
    echo "Which IPv4 address should be used?"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
    read -p "IPv4 address [1]: " ip_number
    until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
      echo "$ip_number: invalid selection."
      read -p "IPv4 address [1]: " ip_number
    done
    [[ -z "$ip_number" ]] && ip_number="1"
    ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
  fi
  #  If $ip is a private IP address, the server must be behind NAT
  if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
    echo
    echo "This server is behind NAT. What is the public IPv4 address or hostname?"
    # Get public IP and sanitize with grep
    get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
    read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
    # If the checkip service is unavailable and user didn't provide input, ask again
    until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
      echo "Invalid input."
      read -p "Public IPv4 address / hostname: " public_ip
    done
    [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
  fi
  # If system has a single IPv6, it is selected automatically
  if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
    ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
  fi
  # If system has multiple IPv6, ask the user to select one
  if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
    number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
    echo
    echo "Which IPv6 address should be used?"
    ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
    read -p "IPv6 address [1]: " ip6_number
    until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
      echo "$ip6_number: invalid selection."
      read -p "IPv6 address [1]: " ip6_number
    done
    [[ -z "$ip6_number" ]] && ip6_number="1"
    ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
  fi
  echo
  echo "What port should WireGuard listen to?"
  read -p "Port [51820]: " port
  until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
    echo "$port: invalid port."
    read -p "Port [51820]: " port
  done
  [[ -z "$port" ]] && port="51820"
  echo
  echo "Enter a name for the first client:"
  # Use STARTOS_HOSTNAME if set, otherwise default to "sos-client"
  default_name="${STARTOS_HOSTNAME:-sos-client}"
  read -p "Name [$default_name]: " unsanitized_client
  # Allow a limited length and set of characters to avoid conflicts
  client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "${unsanitized_client:-$default_name}" | cut -c-15)
  echo
  # Set up automatic updates for BoringTun if the user is fine with that
  if [[ "$use_boringtun" -eq 1 ]]; then
    echo
    echo "BoringTun will be installed to set up WireGuard in the system."
    read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
    until [[ "$boringtun_updates" =~ ^[yYnN]*$ ]]; do
      echo "$remove: invalid selection."
      read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
    done
    [[ -z "$boringtun_updates" ]] && boringtun_updates="y"
    if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
      if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
        cron="cronie"
      elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
        cron="cron"
      fi
    fi
  fi
  echo
  echo "WireGuard installation is ready to begin."
  # Install a firewall if firewalld or iptables are not already available
  if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
    if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
      firewall="firewalld"
      # We don't want to silently enable firewalld, so we give a subtle warning
      # If the user continues, firewalld will be installed and enabled during setup
      echo "firewalld, which is required to manage routing tables, will also be installed."
    elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
      # iptables is way less invasive than firewalld so no warning is given
      firewall="iptables"
    fi
  fi
  read -n1 -r -p "Press any key to continue..."
  # Install WireGuard
  # If BoringTun is not required, set up with the WireGuard kernel module
  if [[ "$use_boringtun" -eq 0 ]]; then
    if [[ "$os" == "ubuntu" ]]; then
      # Ubuntu
      apt-get update
      apt-get install -y wireguard $firewall
    elif [[ "$os" == "debian" ]]; then
      # Debian
      apt-get update
      apt-get install -y wireguard $firewall
    elif [[ "$os" == "centos" ]]; then
      # CentOS
      dnf install -y epel-release
      dnf install -y wireguard-tools $firewall
    elif [[ "$os" == "fedora" ]]; then
      # Fedora
      dnf install -y wireguard-tools $firewall
      mkdir -p /etc/wireguard/
    fi
  else
    # Install required packages
    if [[ "$os" == "ubuntu" ]]; then
      # Ubuntu
      apt-get update
      apt-get install -y ca-certificates $cron $firewall
      apt-get install -y wireguard-tools --no-install-recommends
    elif [[ "$os" == "debian" ]]; then
      # Debian
      apt-get update
      apt-get install -y ca-certificates $cron $firewall
      apt-get install -y wireguard-tools --no-install-recommends
    elif [[ "$os" == "centos" ]]; then
      # CentOS
      dnf install -y epel-release
      dnf install -y wireguard-tools ca-certificates tar $cron $firewall
    elif [[ "$os" == "fedora" ]]; then
      # Fedora
      dnf install -y wireguard-tools ca-certificates tar $cron $firewall
      mkdir -p /etc/wireguard/
    fi
    # Grab the BoringTun binary using wget or curl and extract into the right place.
    # Don't use this service elsewhere without permission! Contact me before you do!
    { wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || curl -sL https://wg.nyr.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
    # Configure wg-quick to use BoringTun
    mkdir /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
    echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
    if [[ -n "$cron" ]] && [[ "$os" == "centos" || "$os" == "fedora" ]]; then
      systemctl enable --now crond.service
    fi
  fi
  # If firewalld was just installed, enable it
  if [[ "$firewall" == "firewalld" ]]; then
    systemctl enable --now firewalld.service
  fi
  # Generate wg0.conf
  cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.59.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
  chmod 600 /etc/wireguard/wg0.conf
  # Enable net.ipv4.ip_forward for the system
  echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
  # Enable without waiting for a reboot or service restart
  echo 1 > /proc/sys/net/ipv4/ip_forward
  if [[ -n "$ip6" ]]; then
    # Enable net.ipv6.conf.all.forwarding for the system
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
    # Enable without waiting for a reboot or service restart
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
  fi
  if systemctl is-active --quiet firewalld.service; then
    # Original VPN rules
    firewall-cmd --add-port="$port"/udp
    firewall-cmd --zone=trusted --add-source=10.59.0.0/24
    firewall-cmd --permanent --add-port="$port"/udp
    firewall-cmd --permanent --zone=trusted --add-source=10.59.0.0/24
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to "$ip"
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to "$ip"

    # Port forwarding rules
    firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i wg0 -j ACCEPT
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
    firewall-cmd --direct --add-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
    firewall-cmd --direct --add-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2
    firewall-cmd --direct --add-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
    firewall-cmd --direct --add-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
    firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -j ACCEPT

    # Make rules permanent
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i wg0 -j ACCEPT
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
    firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
    firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2
    firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
    firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -j ACCEPT

    # IPv6 rules if enabled
    if [[ -n "$ip6" ]]; then
      firewall-cmd --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
      firewall-cmd --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
      firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
      firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"

      firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i wg0 -j ACCEPT
      firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
      firewall-cmd --direct --add-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --direct --add-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --direct --add-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --direct --add-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1
      firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source fddd:2c4:2c4:2c4::1
      firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -j ACCEPT

      firewall-cmd --permanent --direct --add-rule ipv6 filter FORWARD 0 -i wg0 -j ACCEPT
      firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
      firewall-cmd --permanent --direct --add-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --permanent --direct --add-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --permanent --direct --add-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --permanent --direct --add-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
      firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1
      firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source fddd:2c4:2c4:2c4::1
      firewall-cmd --permanent --direct --add-rule ipv6 filter FORWARD 0 -j ACCEPT
    fi
  else
    # Create a service to set up persistent iptables rules
    iptables_path=$(command -v iptables)
    ip6tables_path=$(command -v ip6tables)
    # nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
    # if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
    if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
      iptables_path=$(command -v iptables-legacy)
      ip6tables_path=$(command -v ip6tables-legacy)
    fi
    
    if [[ -n "$ip6" ]]; then
      echo "[Unit]
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
# IPv4 rules
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.59.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStart=$iptables_path -t nat -A POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE
ExecStart=$iptables_path -t nat -A PREROUTING -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
ExecStart=$iptables_path -t nat -A PREROUTING -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
ExecStart=$iptables_path -t nat -A PREROUTING -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
ExecStart=$iptables_path -t nat -A PREROUTING -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
ExecStart=$iptables_path -t nat -A POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
ExecStart=$iptables_path -t nat -A POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
ExecStart=$iptables_path -A FORWARD -j ACCEPT
# IPv6 rules
ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStart=$ip6tables_path -A FORWARD -i wg0 -j ACCEPT
ExecStart=$ip6tables_path -t nat -A POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE
ExecStart=$ip6tables_path -t nat -A PREROUTING -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
ExecStart=$ip6tables_path -t nat -A PREROUTING -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
ExecStart=$ip6tables_path -t nat -A PREROUTING -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
ExecStart=$ip6tables_path -t nat -A PREROUTING -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
ExecStart=$ip6tables_path -t nat -A POSTROUTING -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1
ExecStart=$ip6tables_path -t nat -A POSTROUTING -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source fddd:2c4:2c4:2c4::1
ExecStart=$ip6tables_path -A FORWARD -j ACCEPT
# IPv4 stop rules
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.59.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE
ExecStop=$iptables_path -t nat -D PREROUTING -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
ExecStop=$iptables_path -t nat -D PREROUTING -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
ExecStop=$iptables_path -t nat -D PREROUTING -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
ExecStop=$iptables_path -t nat -D PREROUTING -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
ExecStop=$iptables_path -t nat -D POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
ExecStop=$iptables_path -t nat -D POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
ExecStop=$iptables_path -D FORWARD -j ACCEPT
# IPv6 stop rules
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -i wg0 -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE
ExecStop=$ip6tables_path -t nat -D PREROUTING -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
ExecStop=$ip6tables_path -t nat -D PREROUTING -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
ExecStop=$ip6tables_path -t nat -D PREROUTING -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
ExecStop=$ip6tables_path -t nat -D PREROUTING -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
ExecStop=$ip6tables_path -t nat -D POSTROUTING -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1
ExecStop=$ip6tables_path -t nat -D POSTROUTING -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source fddd:2c4:2c4:2c4::1
ExecStop=$ip6tables_path -D FORWARD -j ACCEPT

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/wg-iptables.service
    else
      echo "[Unit]
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
# IPv4 rules
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.59.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStart=$iptables_path -t nat -A POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE
ExecStart=$iptables_path -t nat -A PREROUTING -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
ExecStart=$iptables_path -t nat -A PREROUTING -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
ExecStart=$iptables_path -t nat -A PREROUTING -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
ExecStart=$iptables_path -t nat -A PREROUTING -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
ExecStart=$iptables_path -t nat -A POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
ExecStart=$iptables_path -t nat -A POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
ExecStart=$iptables_path -A FORWARD -j ACCEPT
# IPv4 stop rules
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.59.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE
ExecStop=$iptables_path -t nat -D PREROUTING -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
ExecStop=$iptables_path -t nat -D PREROUTING -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
ExecStop=$iptables_path -t nat -D PREROUTING -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
ExecStop=$iptables_path -t nat -D PREROUTING -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
ExecStop=$iptables_path -t nat -D POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
ExecStop=$iptables_path -t nat -D POSTROUTING -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
ExecStop=$iptables_path -D FORWARD -j ACCEPT

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/wg-iptables.service
    fi
    systemctl enable --now wg-iptables.service
  fi
  # Generates the custom client.conf
  new_client_setup
  # Enable and start the wg-quick service
  systemctl enable --now wg-quick@wg0.service
  # Set up automatic updates for BoringTun if the user wanted to
  if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
    # Deploy upgrade script
    cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
latest=$(wget -qO- https://wg.nyr.be/1/latest 2>/dev/null || curl -sL https://wg.nyr.be/1/latest 2>/dev/null)
# If server did not provide an appropriate response, exit
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
  echo "Update server unavailable"
  exit
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
  download="https://wg.nyr.be/1/latest/download"
  xdir=$(mktemp -d)
  # If download and extraction are successful, upgrade the boringtun binary
  if { wget -qO- "$download" 2>/dev/null || curl -sL "$download" ; } | tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
    systemctl stop wg-quick@wg0.service
    rm -f /usr/local/sbin/boringtun
    mv "$xdir"/boringtun /usr/local/sbin/boringtun
    systemctl start wg-quick@wg0.service
    echo "Succesfully updated to $(/usr/local/sbin/boringtun -V)"
  else
    echo "boringtun update failed"
  fi
  rm -rf "$xdir"
else
  echo "$current is up to date"
fi
EOF
    chmod +x /usr/local/sbin/boringtun-upgrade
    # Add cron job to run the updater daily at a random time between 3:00 and 5:59
    { crontab -l 2>/dev/null; echo "$(( $RANDOM % 60 )) $(( $RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ; } | crontab -
  fi
  echo
  echo "Finished!"
  echo
  echo "The client configuration is available in:" ~/"$client.conf"
else
  clear
  echo "WireGuard is already installed."
  echo
  echo "Select an option:"
  echo "   1) Remove WireGuard"
  echo "   2) Connect and exit"
  read -p "Option: " option
  until [[ "$option" =~ ^[1-2]$ ]]; do
    echo "$option: invalid selection."
    read -p "Option: " option
  done
  case "$option" in
    1)
      echo
      read -p "Confirm WireGuard removal? [y/N]: " remove
      until [[ "$remove" =~ ^[yYnN]*$ ]]; do
        echo "$remove: invalid selection."
        read -p "Confirm WireGuard removal? [y/N]: " remove
      done
      if [[ "$remove" =~ ^[yY]$ ]]; then
        port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
        if systemctl is-active --quiet firewalld.service; then
          # Remove IPv4 rules
          firewall-cmd --remove-port="$port"/udp
          firewall-cmd --zone=trusted --remove-source=10.59.0.0/24
          firewall-cmd --permanent --remove-port="$port"/udp
          firewall-cmd --permanent --zone=trusted --remove-source=10.59.0.0/24
          firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to "$ip"
          firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.59.0.0/24 ! -d 10.59.0.0/24 -j SNAT --to "$ip"

          firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i wg0 -j ACCEPT
          firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
          firewall-cmd --direct --remove-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
          firewall-cmd --direct --remove-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2
          firewall-cmd --direct --remove-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
          firewall-cmd --direct --remove-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
          firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
          firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
          firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -j ACCEPT

          firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -i wg0 -j ACCEPT
          firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
          firewall-cmd --permanent --direct --remove-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
          firewall-cmd --permanent --direct --remove-rule ipv4 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination 10.59.0.2
          firewall-cmd --permanent --direct --remove-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p tcp ! --dport 22 -j DNAT --to-destination 10.59.0.2
          firewall-cmd --permanent --direct --remove-rule ipv4 nat PREROUTING 0 -i wg0 -s 10.59.0.0/24 -d $ip -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination 10.59.0.2
          firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p tcp ! --dport 22 -j SNAT --to-source 10.59.0.1
          firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -o wg0 -s 10.59.0.0/24 -d 10.59.0.2/32 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source 10.59.0.1
          firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -j ACCEPT

          # Remove IPv6 rules if they exist
          if grep -qs 'fddd:2c4:2c4:2c4::1/64' /etc/wireguard/wg0.conf; then
            firewall-cmd --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
            firewall-cmd --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
            firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
            firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"

            firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i wg0 -j ACCEPT
            firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
            firewall-cmd --direct --remove-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --direct --remove-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --direct --remove-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --direct --remove-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1
            firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source fddd:2c4:2c4:2c4::1
            firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -j ACCEPT

            firewall-cmd --permanent --direct --remove-rule ipv6 filter FORWARD 0 -i wg0 -j ACCEPT
            firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -o $PRIMARY_INTERFACE -j MASQUERADE
            firewall-cmd --permanent --direct --remove-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --permanent --direct --remove-rule ipv6 nat PREROUTING 0 -i $PRIMARY_INTERFACE -p udp -m multiport ! --dports 22,"$port" -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --permanent --direct --remove-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p tcp ! --dport 22 -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --permanent --direct --remove-rule ipv6 nat PREROUTING 0 -i wg0 -s fddd:2c4:2c4:2c4::/64 -d $ip6 -p udp -m multiport ! --dports 22,$port -j DNAT --to-destination fddd:2c4:2c4:2c4::2
            firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p tcp ! --dport 22 -j SNAT --to-source fddd:2c4:2c4:2c4::1
            firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -o wg0 -s fddd:2c4:2c4:2c4::/64 -d fddd:2c4:2c4:2c4::/64 -p udp -m multiport ! --dports 22,$port -j SNAT --to-source fddd:2c4:2c4:2c4::1
            firewall-cmd --permanent --direct --remove-rule ipv6 filter FORWARD 0 -j ACCEPT
          fi
        else
          systemctl disable --now wg-iptables.service
          rm -f /etc/systemd/system/wg-iptables.service
        fi
        systemctl disable --now wg-quick@wg0.service
        rm -f /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
        rm -f /etc/sysctl.d/99-wireguard-forward.conf
        # Different stuff was installed depending on whether BoringTun was used or not
        if [[ "$use_boringtun" -eq 0 ]]; then
          if [[ "$os" == "ubuntu" ]]; then
            # Ubuntu
            rm -rf /etc/wireguard/
            apt-get remove --purge -y wireguard wireguard-tools
          elif [[ "$os" == "debian" ]]; then
            # Debian
            rm -rf /etc/wireguard/
            apt-get remove --purge -y wireguard wireguard-tools
          elif [[ "$os" == "centos" ]]; then
            # CentOS
            dnf remove -y wireguard-tools
            rm -rf /etc/wireguard/
          elif [[ "$os" == "fedora" ]]; then
            # Fedora
            dnf remove -y wireguard-tools
            rm -rf /etc/wireguard/
          fi
        else
          { crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
          if [[ "$os" == "ubuntu" ]]; then
            # Ubuntu
            rm -rf /etc/wireguard/
            apt-get remove --purge -y wireguard-tools
          elif [[ "$os" == "debian" ]]; then
            # Debian
            rm -rf /etc/wireguard/
            apt-get remove --purge -y wireguard-tools
          elif [[ "$os" == "centos" ]]; then
            # CentOS
            dnf remove -y wireguard-tools
            rm -rf /etc/wireguard/
          elif [[ "$os" == "fedora" ]]; then
            # Fedora
            dnf remove -y wireguard-tools
            rm -rf /etc/wireguard/
          fi
          rm -f /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
        fi
        echo
        echo "WireGuard removed!"
      else
        echo
        echo "WireGuard removal aborted!"
      fi
      exit
      ;;
    2)
      exit
      ;;
  esac
fi
