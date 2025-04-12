#!/bin/bash
#
# Debian 12 (Bookworm) Minimal Server Configuration Script
# Version: 1.0
# Description: This script automates the configuration of a Debian 12 Minimal Server
#
# Author: Luis Miguel P. Freitas | DigitalXS.ca | 2025
# Date: April 12, 2025
#

set -e          # Exit immediately if a command exits with a non-zero status
set -u          # Treat unset variables as an error when substituting
set -o pipefail # Exit with non-zero status if any command in a pipeline fails

# Color definitions for pretty output
readonly RESET="\033[0m"
readonly RED="\033[0;31m"
readonly GREEN="\033[0;32m"
readonly YELLOW="\033[0;33m"
readonly BLUE="\033[0;34m"
readonly MAGENTA="\033[0;35m"
readonly CYAN="\033[0;36m"
readonly BOLD="\033[1m"

# Global variables
NETWORK_INTERFACE=""
USE_DHCP="no"
IP_ADDRESS=""
NETMASK=""
NETWORK=""
BROADCAST=""
GATEWAY=""
HOSTNAME=""
DOMAIN=""
FQDN=""
ADMIN_USER=""
PACKAGES="ssh openssh-server sudo nano vim-nox multitail tree joe git net-tools cockpit ufw chrony fail2ban unattended-upgrades htop iotop dnsutils lsof ncdu curl wget rsync screen tmux tcpdump nmap zsh ethtool logrotate ca-certificates apt-transport-https gnupg2 python3-pip python3-venv acl atop iperf3"
FIREWALL_PORTS="22 80 443 9090 10000"  # SSH, HTTP, HTTPS, Cockpit, Webmin

# Log file
LOG_FILE="/var/log/debian12-setup.log"

#
# Helper functions
#

log() {
    local message="$1"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} - ${message}" | tee -a "$LOG_FILE"
}

info() {
    log "${BLUE}[INFO]${RESET} $1"
}

success() {
    log "${GREEN}[SUCCESS]${RESET} $1"
}

warning() {
    log "${YELLOW}[WARNING]${RESET} $1"
}

error() {
    log "${RED}[ERROR]${RESET} $1"
    exit 1
}

banner() {
    local message="$1"
    local length=${#message}
    local line=""
    
    for ((i=0; i<length+4; i++)); do
        line="${line}="
    done
    
    echo -e "\n${CYAN}${line}${RESET}"
    echo -e "${CYAN}= ${BOLD}${message}${RESET} ${CYAN}=${RESET}"
    echo -e "${CYAN}${line}${RESET}\n"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

confirm() {
    local prompt="$1"
    local default="${2:-y}"
    
    if [[ "$default" == "y" ]]; then
        local options="[Y/n]"
    else
        local options="[y/N]"
    fi
    
    while true; do
        read -rp "$prompt $options " answer
        answer=${answer:-$default}
        case ${answer:0:1} in
            y|Y) return 0 ;;
            n|N) return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

#
# Configuration functions
#

detect_network_interfaces() {
    local interfaces=()
    local default=""
    local choice
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*[0-9]+:[[:space:]]+([^:[:space:]]+): ]]; then
            interface="${BASH_REMATCH[1]}"
            if [[ "$interface" != "lo" ]]; then
                interfaces+=("$interface")
                if [[ -z "$default" ]]; then
                    default="$interface"
                fi
            fi
        fi
    done < <(ip -o link show)
    
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        error "No network interfaces detected"
    elif [[ ${#interfaces[@]} -eq 1 ]]; then
        NETWORK_INTERFACE="${interfaces[0]}"
        info "Using the only available network interface: $NETWORK_INTERFACE"
    else
        echo "Available network interfaces:"
        for i in "${!interfaces[@]}"; do
            echo "  $((i+1)). ${interfaces[$i]}"
        done
        
        while true; do
            read -rp "Select a network interface [1-${#interfaces[@]}]: " choice
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#interfaces[@]}" ]; then
                NETWORK_INTERFACE="${interfaces[$((choice-1))]}"
                break
            else
                echo "Invalid selection. Please try again."
            fi
        done
    fi
}

get_current_ip() {
    local interface="$1"
    local current_ip
    
    current_ip=$(ip -4 addr show dev "$interface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
    echo "$current_ip"
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [[ "$octet" -gt 255 ]]; then
            return 1
        fi
    done
    
    return 0
}

configure_network() {
    banner "Network Configuration"
    
    detect_network_interfaces
    
    # Ask if user wants DHCP or static IP
    if confirm "Do you want to use DHCP for network configuration? (Select 'No' for static IP)"; then
        USE_DHCP="yes"
        success "DHCP configuration selected"
        return
    else
        USE_DHCP="no"
    fi
    
    local current_ip
    current_ip=$(get_current_ip "$NETWORK_INTERFACE")
    
    # Get IP address
    while true; do
        read -rp "Enter IP address [$current_ip]: " IP_ADDRESS
        IP_ADDRESS=${IP_ADDRESS:-$current_ip}
        
        if validate_ip "$IP_ADDRESS"; then
            break
        else
            echo "Invalid IP address format. Please try again."
        fi
    done
    
    # Get netmask
    while true; do
        read -rp "Enter netmask [255.255.255.0]: " NETMASK
        NETMASK=${NETMASK:-255.255.255.0}
        
        if validate_ip "$NETMASK"; then
            break
        else
            echo "Invalid netmask format. Please try again."
        fi
    done
    
    # Calculate network address
    IFS='.' read -r -a ip_octets <<< "$IP_ADDRESS"
    IFS='.' read -r -a mask_octets <<< "$NETMASK"
    
    local network_octets=()
    for i in {0..3}; do
        network_octets[$i]=$((ip_octets[$i] & mask_octets[$i]))
    done
    
    NETWORK="${network_octets[0]}.${network_octets[1]}.${network_octets[2]}.${network_octets[3]}"
    
    # Calculate broadcast address
    local broadcast_octets=()
    for i in {0..3}; do
        broadcast_octets[$i]=$((network_octets[$i] | (255 - mask_octets[$i])))
    done
    
    BROADCAST="${broadcast_octets[0]}.${broadcast_octets[1]}.${broadcast_octets[2]}.${broadcast_octets[3]}"
    
    # Get gateway
    local default_gateway
    default_gateway=$(ip route | grep default | awk '{print $3}' | head -n 1)
    default_gateway=${default_gateway:-${network_octets[0]}.${network_octets[1]}.${network_octets[2]}.1}
    
    while true; do
        read -rp "Enter gateway [$default_gateway]: " GATEWAY
        GATEWAY=${GATEWAY:-$default_gateway}
        
        if validate_ip "$GATEWAY"; then
            break
        else
            echo "Invalid gateway format. Please try again."
        fi
    done
    
    success "Network configuration completed"
}

configure_hostname() {
    banner "Hostname Configuration"
    
    local default_hostname
    default_hostname=$(hostname -s)
    
    # Get hostname
    read -rp "Enter hostname [$default_hostname]: " HOSTNAME
    HOSTNAME=${HOSTNAME:-$default_hostname}
    
    # Get domain
    local default_domain
    default_domain=$(hostname -d 2>/dev/null || echo "example.com")
    
    read -rp "Enter domain [$default_domain]: " DOMAIN
    DOMAIN=${DOMAIN:-$default_domain}
    
    FQDN="${HOSTNAME}.${DOMAIN}"
    
    success "Hostname configuration completed"
}

configure_user() {
    banner "User Configuration"
    
    # Check if we need to create an admin user
    if confirm "Do you want to create a new administrator user?"; then
        while true; do
            read -rp "Enter username for the new administrator: " ADMIN_USER
            
            if [[ -z "$ADMIN_USER" ]]; then
                echo "Username cannot be empty. Please try again."
            elif id "$ADMIN_USER" &>/dev/null; then
                if confirm "User $ADMIN_USER already exists. Do you want to add this user to sudoers?"; then
                    break
                fi
            else
                break
            fi
        done
    fi
    
    success "User configuration completed"
}

customize_packages() {
    banner "Package Configuration"
    
    # Display package categories
    echo -e "${BOLD}Default packages to install:${RESET}"
    echo "1. Essential system tools:"
    echo "   - ssh, openssh-server, sudo, ufw, chrony, fail2ban, unattended-upgrades"
    echo "2. Text editors:"
    echo "   - nano, vim-nox, joe"
    echo "3. System utilities:"
    echo "   - htop, iotop, lsof, ncdu, dnsutils, net-tools, curl, wget, rsync"
    echo "4. Monitoring and debugging:"
    echo "   - multitail, tree, tcpdump, nmap, atop, iperf3"
    echo "5. Administrative interfaces:"
    echo "   - cockpit"
    echo "6. Developer tools:"
    echo "   - git, python3-pip, python3-venv"
    echo "7. Terminal multiplexers:"
    echo "   - screen, tmux"
    echo "8. Network tools:"
    echo "   - ethtool, dnsutils"
    echo "9. System essentials:"
    echo "    - logrotate, ca-certificates, apt-transport-https, gnupg2, acl"
    echo
    
    if confirm "Do you want to customize the package list?"; then
        echo "Options:"
        echo "1. Use minimal packages (ssh, sudo, ufw, fail2ban only)"
        echo "2. Use default comprehensive package list"
        echo "3. Enter custom package list"
        
        local choice
        read -rp "Select an option [1-3]: " choice
        
        case $choice in
            1)
                PACKAGES="ssh openssh-server sudo ufw fail2ban nano"
                info "Minimal package list selected"
                ;;
            2)
                # Keep default package list
                info "Default comprehensive package list selected"
                ;;
            3)
                read -rp "Enter comma-separated list of packages to install: " custom_packages
                if [[ -n "$custom_packages" ]]; then
                    PACKAGES="$custom_packages"
                    info "Custom package list selected"
                fi
                ;;
            *)
                warning "Invalid option. Using default package list."
                ;;
        esac
    fi
    
    success "Package configuration completed"
}

customize_firewall() {
    banner "Firewall Configuration"
    
    echo "Default ports to open: $FIREWALL_PORTS (SSH, HTTP, HTTPS, Cockpit, Webmin)"
    
    if confirm "Do you want to customize the ports to open?"; then
        read -rp "Enter space-separated list of ports to open: " custom_ports
        if [[ -n "$custom_ports" ]]; then
            FIREWALL_PORTS="$custom_ports"
        fi
    fi
    
    success "Firewall configuration completed"
}

#
# Implementation functions
#

update_system() {
    banner "Updating System"
    
    info "Updating package lists"
    apt-get update -qq || error "Failed to update package lists"
    
    info "Upgrading packages"
    apt-get upgrade -y -qq || error "Failed to upgrade packages"
    
    success "System updated successfully"
}

apply_network_config() {
    banner "Applying Network Configuration"
    
    local interfaces_file="/etc/network/interfaces"
    local interfaces_backup="${interfaces_file}.bak"
    
    # Backup original file
    cp "$interfaces_file" "$interfaces_backup" || error "Failed to backup interfaces file"
    info "Backed up interfaces file to $interfaces_backup"
    
    # Write new configuration
    if [[ "$USE_DHCP" == "yes" ]]; then
        # DHCP configuration
        cat > "$interfaces_file" << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto $NETWORK_INTERFACE
iface $NETWORK_INTERFACE inet dhcp

# This is an autoconfigured IPv6 interface
iface $NETWORK_INTERFACE inet6 auto
EOF
        info "Network configuration set to use DHCP"
    else
        # Static IP configuration
        cat > "$interfaces_file" << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto $NETWORK_INTERFACE
iface $NETWORK_INTERFACE inet static
        address $IP_ADDRESS
        netmask $NETMASK
        network $NETWORK
        broadcast $BROADCAST
        gateway $GATEWAY

# This is an autoconfigured IPv6 interface
iface $NETWORK_INTERFACE inet6 auto
EOF
        info "Network configuration applied with static IP: $IP_ADDRESS"
    fi
    
    # Restart networking only if confirming
    if confirm "Do you want to restart networking now? This might disconnect you if connected via SSH"; then
        info "Restarting networking service"
        systemctl restart networking || warning "Failed to restart networking service"
    else
        warning "Network changes will take effect after reboot"
    fi
    
    success "Network configuration applied"
}

apply_hostname_config() {
    banner "Applying Hostname Configuration"
    
    # Update /etc/hostname
    echo "$HOSTNAME" > /etc/hostname || error "Failed to update hostname file"
    info "Updated /etc/hostname"
    
    # Update /etc/hosts
    local hosts_file="/etc/hosts"
    local hosts_backup="${hosts_file}.bak"
    
    # Backup original file
    cp "$hosts_file" "$hosts_backup" || error "Failed to backup hosts file"
    info "Backed up hosts file to $hosts_backup"
    
    # Write new configuration
    cat > "$hosts_file" << EOF
127.0.0.1       localhost.localdomain   localhost
$IP_ADDRESS     $FQDN   $HOSTNAME

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF
    
    info "Hostname configuration applied to $hosts_file"
    
    success "Hostname configuration applied"
}

install_required_packages() {
    banner "Installing Required Packages"
    
    info "Installing packages: $PACKAGES"
    apt-get install -y $PACKAGES || error "Failed to install required packages"
    
    success "Required packages installed"
}

setup_admin_user() {
    banner "Setting Up Administrator User"
    
    if [[ -n "$ADMIN_USER" ]]; then
        if ! id "$ADMIN_USER" &>/dev/null; then
            info "Creating user $ADMIN_USER"
            adduser --gecos "" "$ADMIN_USER" || error "Failed to create user $ADMIN_USER"
            
            # Add SSH public key for the user if provided
            if confirm "Do you want to add an SSH public key for $ADMIN_USER?"; then
                local ssh_dir="/home/$ADMIN_USER/.ssh"
                local auth_keys="$ssh_dir/authorized_keys"
                
                # Create .ssh directory if it doesn't exist
                mkdir -p "$ssh_dir" || error "Failed to create SSH directory for $ADMIN_USER"
                
                # Set proper permissions
                chown "$ADMIN_USER:$ADMIN_USER" "$ssh_dir"
                chmod 700 "$ssh_dir"
                
                # Add SSH key
                read -rp "Enter or paste the SSH public key: " ssh_key
                if [[ -n "$ssh_key" ]]; then
                    echo "$ssh_key" > "$auth_keys" || error "Failed to add SSH key"
                    chown "$ADMIN_USER:$ADMIN_USER" "$auth_keys"
                    chmod 600 "$auth_keys"
                    info "SSH public key added for $ADMIN_USER"
                fi
            fi
        fi
        
        info "Adding $ADMIN_USER to sudo group"
        usermod -aG sudo "$ADMIN_USER" || error "Failed to add $ADMIN_USER to sudo group"
        
        # Optionally disable SSH password authentication
        if confirm "For better security, do you want to disable SSH password authentication (key-based auth only)?"; then
            info "Configuring SSH to use key-based authentication only"
            sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
            systemctl restart ssh || warning "Failed to restart SSH service"
            info "SSH password authentication disabled"
        fi
        
        success "Administrator user $ADMIN_USER setup completed"
    else
        info "Skipping user setup as no admin user was specified"
    fi
}

configure_apt_sources() {
    banner "Configuring APT Sources"
    
    local sources_file="/etc/apt/sources.list"
    local sources_backup="${sources_file}.bak"
    
    # Backup original file
    cp "$sources_file" "$sources_backup" || error "Failed to backup sources.list file"
    info "Backed up sources.list to $sources_backup"
    
    # Write new configuration
    cat > "$sources_file" << EOF
deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware

deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
deb-src http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware

# bookworm-updates, to get updates before a point release is made;
# see https://www.debian.org/doc/manuals/debian-reference/ch02.en.html#_updates_and_backports
deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
EOF
    
    info "APT sources configuration applied to $sources_file"
    
    apt-get update -qq || warning "Failed to update package lists after sources.list changes"
    
    success "APT sources configured"
}

setup_firewall() {
    banner "Setting Up Firewall"
    
    info "Installing and configuring UFW"
    
    # Default policies
    ufw default deny incoming || error "Failed to set default incoming policy"
    ufw default allow outgoing || error "Failed to set default outgoing policy"
    
    # Open specified ports
    for port in $FIREWALL_PORTS; do
        info "Opening port $port"
        ufw allow "$port" || warning "Failed to open port $port"
    done
    
    # Enable UFW if it's not already enabled
    if ! ufw status | grep -q "Status: active"; then
        info "Enabling UFW"
        echo "y" | ufw enable || error "Failed to enable UFW"
    else
        info "UFW is already enabled"
    fi
    
    success "Firewall setup completed"
}

configure_chrony() {
    banner "Configuring Chrony NTP"
    
    info "Starting and enabling chrony service"
    systemctl start chrony || warning "Failed to start chrony service"
    systemctl enable chrony || warning "Failed to enable chrony service"
    
    success "Chrony NTP configured"
}

setup_fail2ban() {
    banner "Setting Up Fail2Ban"
    
    info "Configuring Fail2Ban"
    
    # Create jail.local if it doesn't exist
    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local || error "Failed to create jail.local"
        info "Created jail.local from jail.conf template"
    fi
    
    # Configure jail.local
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Ban hosts for 1 hour
bantime = 3600

# Increase ban time for repeat offenders
bantime.increment = true
bantime.factor = 2
bantime.formula = ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor

# A host is banned if it has generated maxretry during the last findtime seconds
findtime = 600
maxretry = 5

# "ignoreip" can be a list of IP addresses, CIDR masks or DNS hosts
ignoreip = 127.0.0.1/8 ::1

# Enable all jails
[sshd]
enabled = true

[sshd-ddos]
enabled = true

[apache-auth]
enabled = true

[apache-badbots]
enabled = true

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true

[apache-nohome]
enabled = true

[apache-botsearch]
enabled = true

[apache-fakegooglebot]
enabled = true

[apache-modsecurity]
enabled = true

[php-url-fopen]
enabled = true
EOF
    
    info "Restarting and enabling fail2ban service"
    systemctl restart fail2ban || warning "Failed to restart fail2ban service"
    systemctl enable fail2ban || warning "Failed to enable fail2ban service"
    
    success "Fail2Ban setup completed"
}

configure_unattended_upgrades() {
    banner "Configuring Unattended Upgrades"
    
    info "Enabling unattended-upgrades"
    systemctl enable unattended-upgrades || warning "Failed to enable unattended-upgrades service"
    systemctl start unattended-upgrades || warning "Failed to start unattended-upgrades service"
    
    # Configure unattended-upgrades
    local config_file="/etc/apt/apt.conf.d/50unattended-upgrades"
    
    # Enable security updates
    sed -i 's|//\s*"origin=Debian,codename=${distro_codename},label=Debian-Security";|"origin=Debian,codename=${distro_codename},label=Debian-Security";|g' "$config_file" || warning "Failed to enable security updates in unattended-upgrades configuration"
    
    # Configure automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF
    
    info "Automatic security updates configured"
    
    success "Unattended upgrades configured"
}

show_summary() {
    banner "Configuration Summary"
    
    echo -e "${BOLD}Network Configuration:${RESET}"
    echo "  Interface: $NETWORK_INTERFACE"
    
    if [[ "$USE_DHCP" == "yes" ]]; then
        echo "  Configuration: DHCP (automatic IP assignment)"
    else
        echo "  Configuration: Static IP"
        echo "  IP Address: $IP_ADDRESS"
        echo "  Netmask: $NETMASK"
        echo "  Network: $NETWORK"
        echo "  Broadcast: $BROADCAST"
        echo "  Gateway: $GATEWAY"
    fi
    echo
    echo -e "${BOLD}Hostname Configuration:${RESET}"
    echo "  Hostname: $HOSTNAME"
    echo "  Domain: $DOMAIN"
    echo "  FQDN: $FQDN"
    echo
    echo -e "${BOLD}User Configuration:${RESET}"
    if [[ -n "$ADMIN_USER" ]]; then
        echo "  Admin User: $ADMIN_USER"
    else
        echo "  No admin user specified"
    fi
    echo
    echo -e "${BOLD}Package Configuration:${RESET}"
    echo "  Packages: $PACKAGES"
    echo
    echo -e "${BOLD}Firewall Configuration:${RESET}"
    echo "  Open Ports: $FIREWALL_PORTS"
    echo
    echo -e "${BOLD}Log file:${RESET} $LOG_FILE"
    echo
    
    if confirm "Do you want to proceed with the configuration?"; then
        return 0
    else
        error "Configuration aborted by user"
    fi
}

configure_additional_options() {
    banner "Additional Configuration Options"
    
    # Enable/disable root SSH login
    if confirm "Do you want to disable root SSH login for better security?" "y"; then
        info "Disabling root SSH login"
        sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
        systemctl restart ssh || warning "Failed to restart SSH service"
        success "Root SSH login disabled"
    fi
    
    # Set up SSH key-based authentication only
    if [[ -n "$ADMIN_USER" ]]; then
        if confirm "Would you like to restrict SSH to key-based authentication only? (More secure, but requires SSH keys)" "n"; then
            info "Configuring SSH for key-based authentication only"
            sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
            systemctl restart ssh || warning "Failed to restart SSH service"
            success "SSH password authentication disabled"
        fi
    fi
    
    # Configure automatic security updates
    if confirm "Do you want to configure automatic security updates?" "y"; then
        configure_unattended_upgrades
    else
        info "Skipping automatic security updates configuration"
    fi
    
    # CPU governor settings
    if confirm "Would you like to configure the CPU governor for performance?" "n"; then
        info "Installing cpufrequtils"
        apt-get install -y cpufrequtils || warning "Failed to install cpufrequtils"
        
        # Set CPU governor to performance
        cpufreq-set -r -g performance || warning "Failed to set CPU governor to performance"
        
        # Make it persistent
        echo 'GOVERNOR="performance"' > /etc/default/cpufrequtils
        
        success "CPU governor set to performance mode"
    fi
    
    # Swappiness configuration
    if confirm "Would you like to configure swappiness for server optimization?" "y"; then
        info "Configuring swappiness for server performance"
        echo "vm.swappiness=10" >> /etc/sysctl.conf
        sysctl -p || warning "Failed to apply sysctl settings"
        success "Swappiness configured to 10 (better for servers)"
    fi
    
    # Set timezone
    if confirm "Would you like to set the system timezone?" "y"; then
        local timezone
        
        # Try to determine current timezone
        current_timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "Etc/UTC")
        
        read -rp "Enter timezone [$current_timezone]: " timezone
        timezone=${timezone:-$current_timezone}
        
        timedatectl set-timezone "$timezone" || warning "Failed to set timezone to $timezone"
        success "Timezone set to $timezone"
    fi
    
    success "Additional configuration completed"
}

finish_setup() {
    banner "Setup Completed"
    
    echo -e "${GREEN}Debian 12 minimal server setup has been completed successfully!${RESET}"
    echo
    echo "The following configurations have been applied:"
    
    if [[ "$USE_DHCP" == "yes" ]]; then
        echo "  - Network configured with DHCP"
    else
        echo "  - Network configured with static IP"
    fi
    
    echo "  - Hostname and hosts file updated"
    echo "  - Required packages installed"
    echo "  - APT sources configured with security updates"
    echo "  - UFW firewall configured and enabled"
    echo "  - Fail2Ban configured and enabled"
    echo "  - Chrony NTP service configured"
    
    # Display IP information for convenience
    echo
    echo -e "${BOLD}Current IP Information:${RESET}"
    ip addr show "$NETWORK_INTERFACE" | grep -w inet | awk '{print "  - IP Address: " $2}'
    
    echo
    if confirm "Do you want to reboot the system now to apply all changes?" "n"; then
        echo "Rebooting system in 5 seconds..."
        sleep 5
        reboot
    else
        echo -e "${YELLOW}Please reboot the system at your convenience to apply all changes.${RESET}"
    fi
}

#
# Main function
#

main() {
    # Clear the screen
    clear
    
    banner "Debian 12 (Bookworm) Minimal Server Setup"
    
    # Check if running as root
    check_root
    
    # Initialize log file
    touch "$LOG_FILE" || error "Cannot create log file"
    chmod 640 "$LOG_FILE" || warning "Failed to set permissions on log file"
    
    # Configuration phase
    configure_network
    configure_hostname
    configure_user
    customize_packages
    customize_firewall
    
    # Show summary and confirm
    show_summary
    
    # Implementation phase
    update_system
    apply_network_config
    apply_hostname_config
    configure_apt_sources
    install_required_packages
    setup_admin_user
    setup_firewall
    configure_chrony
    setup_fail2ban
    
    # Additional configuration options
    configure_additional_options
    
    # Finish setup
    finish_setup
}

# Run the main function
main "$@"
