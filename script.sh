#!/bin/bash

# Script for automating security audits and server hardening on Linux servers
# Version 1.0
# Author: Your Name
# Date: YYYY-MM-DD

# Function to check for root privileges
check_root() {
    if [ "$(id -u)" -ne "0" ]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

# Function to display help message
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help          Display this help message"
    echo "  -c, --check         Run security checks"
    echo "  -h, --harden        Apply security hardening"
    exit 0
}

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        -c|--check) CHECK=true ;;
        -H|--harden) HARDEN=true ;;
        *) echo "Unknown parameter passed: $1" >&2; usage ;;
    esac
    shift
done

# Run initial checks
check_root

# Function to perform user and group audits
user_group_audit() {
    echo "Performing user and group audits..."

    # List all users and groups
    echo "Users:"
    cut -d: -f1 /etc/passwd
    echo "Groups:"
    cut -d: -f1 /etc/group

    # Check for users with UID 0
    echo "Users with UID 0 (root privileges):"
    awk -F: '$3 == 0 { print $1 }' /etc/passwd

    # Check for users without passwords
    echo "Users without passwords:"
    awk -F: '($2 == "" || $2 == "*") { print $1 }' /etc/shadow

    # Check for weak passwords (if possible, based on your definition of weak)
    echo "Checking for weak passwords is not implemented in this script."
}

# Function to check file and directory permissions
file_permission_audit() {
    echo "Checking file and directory permissions..."

    # Files and directories with world-writable permissions
    find / -perm -0002 -type f -exec ls -l {} \; 2>/dev/null

    # .ssh directory permissions
    find /home -name .ssh -type d -exec ls -ld {} \; 2>/dev/null

    # Files with SUID/SGID bits set
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null
}

# Function to perform service audits
service_audit() {
    echo "Listing running services and checking for unauthorized services..."
    systemctl list-units --type=service --state=running

    # Check for critical services
    echo "Critical services status:"
    systemctl status sshd
    systemctl status iptables

    # Check for services listening on non-standard ports
    netstat -tuln
}

# Function to check firewall and network security
firewall_network_security() {
    echo "Checking firewall and network security..."

    # Check if firewall is active
    if command -v ufw >/dev/null; then
        ufw status verbose
    elif command -v iptables >/dev/null; then
        iptables -L -v -n
    else
        echo "No firewall found (ufw or iptables)."
    fi

    # Report open ports
    netstat -tuln

    # Check IP forwarding
    sysctl net.ipv4.ip_forward
}

# Function to check public vs. private IPs
ip_network_check() {
    echo "Checking IP addresses and their types..."

    IP_ADDRESSES=$(hostname -I)
    echo "IP Addresses: $IP_ADDRESSES"

    for IP in $IP_ADDRESSES; do
        if [[ "$IP" =~ ^10\. ]] || [[ "$IP" =~ ^172\.1[6-9]\. ]] || [[ "$IP" =~ ^172\.2[0-9]\. ]] || [[ "$IP" =~ ^192\.168\. ]]; then
            echo "$IP is a private IP."
        else
            echo "$IP is a public IP."
        fi
    done
}

# Function to check for security updates
security_updates() {
    echo "Checking for security updates..."

    if command -v apt-get >/dev/null; then
        apt-get update
        apt-get upgrade -s | grep -i security
    elif command -v yum >/dev/null; then
        yum check-update --security
    else
        echo "Unsupported package manager."
    fi
}

# Function to monitor logs for suspicious activity
log_monitoring() {
    echo "Checking logs for suspicious activity..."

    # Example: checking SSH logs for failed login attempts
    grep "Failed password" /var/log/auth.log
}

# Function to apply server hardening
server_hardening() {
    echo "Applying server hardening..."

    # SSH Configuration
    echo "Configuring SSH..."
    sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd

    # Disabling IPv6
    echo "Disabling IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1

    # Securing the Bootloader
    echo "Securing GRUB..."
    grub2-setpasswd

    # Firewall Configuration
    echo "Configuring firewall..."
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Automatic Updates
    echo "Configuring automatic updates..."
    apt-get install unattended-upgrades
}
# Function to apply custom security checks
custom_security_checks() {
    echo "Applying custom security checks..."

    # Custom checks can be added here
    echo "Custom security checks are not implemented in this script."
}

# Function to generate reports
generate_report() {
    echo "Generating security audit report..."

    REPORT_FILE="security_audit_report_$(date +%F).log"
    {
        echo "Security Audit Report - $(date)"
        user_group_audit
        file_permission_audit
        service_audit
        firewall_network_security
        ip_network_check
        security_updates
        log_monitoring
        server_hardening
        custom_security_checks
    } > "$REPORT_FILE"
    echo "Report generated: $REPORT_FILE"
}
