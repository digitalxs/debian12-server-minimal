# Debian 12 Minimal Server Setup

<p align="center">
  <img src="https://www.debian.org/logos/openlogo-nd-100.png" alt="Debian Logo">
</p>

<p align="center">
  <strong>Automating Debian 12 (Bookworm) server setup and configuration</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-blue" alt="Version 1.0">
  <img src="https://img.shields.io/badge/License-GPL--3.0-green" alt="License GPL-3.0">
  <img src="https://img.shields.io/badge/Debian-12%20Bookworm-red" alt="Debian 12 Bookworm">
</p>

## Overview

This script automates the installation and configuration process of a Debian 12 (Bookworm) minimal server. It handles network configuration, user setup, some security hardening, package installation, and various system optimizations to get your server up and running quickly.

## Requirements

- A fresh installation of Debian 12 (Bookworm)
- Root access to the server
- Internet connectivity for package installation

## Installation

### Download and Run

```bash
# Login as root
su -

# Download the script
wget https://raw.githubusercontent.com/digitalxs/debian12-server-minimal/main/debian12-server-minimal.sh

# Make it executable
chmod +x debian12-server-minimal.sh

# Run the script as root
./debian12-server-minimal.sh
```

## Default Packages

The script installs the following packages by default:

| Package | Description |
|---------|-------------|
| ssh, openssh-server | SSH server for remote access |
| sudo | Execute commands with superuser privileges |
| ufw | Uncomplicated Firewall for simple firewall management |
| chrony | Time synchronization service |
| fail2ban | Intrusion prevention by blocking brute force attempts |
| unattended-upgrades | Automatic security updates |
| nano, vim-nox, joe | Text editors for system administration |
| htop, iotop | System monitoring tools |
| dnsutils | DNS utilities for network diagnostics |
| net-tools | Network configuration tools |
| curl, wget | Command line downloaders |
| rsync | Fast, versatile file copying tool |
| multitail | View multiple log files simultaneously |
| tree | Display directory structure graphically |
| tcpdump, nmap | Network analysis tools |
| atop, iperf3 | System and network performance monitoring |
| cockpit | Web-based server management interface |
| git | Version control system |
| python3-pip, python3-venv | Python package management |
| screen, tmux | Terminal multiplexers |
| ethtool | Ethernet device configuration |
| logrotate | Log file rotation utility |
| ca-certificates | Common SSL certificates |
| apt-transport-https | HTTPS transport for APT |
| gnupg2 | OpenPGP encryption and signing tool |
| acl | Access control list utilities |

## Configuration Files

The script modifies the following configuration files:

- `/etc/network/interfaces`: Network configuration
- `/etc/hostname`: Server hostname
- `/etc/hosts`: Host mapping
- `/etc/apt/sources.list`: APT repository sources
- `/etc/ssh/sshd_config`: SSH configuration
- `/etc/fail2ban/jail.local`: Fail2Ban configuration
- `/etc/apt/apt.conf.d/50unattended-upgrades`: Unattended upgrades

## Logging

All operations performed by the script are logged to:
```
/var/log/debian12-setup.log
```

## Customization

You can modify the script variables at the top of the file to change default behaviors:
- Default packages
- Firewall ports
- Network settings

## License

This script is released under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions, please open an issue on the GitHub repository.

---

<p align="center">
  Made with ❤️ by <a href="https://digitalxs.ca">DigitalXS.ca</a>
</p>
