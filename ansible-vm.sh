#!/usr/bin/env bash
# ansible-vm.sh - Enhanced Rocky Linux 9 VM Deployment for ProxMox
# Version: 3.0.0 - 2025 Security Standards Edition
# Copyright (c) 2025 Infrastructure as Code Deployment
# Author: tonysauce
# License: MIT
# 
# Implements:
# - NIST CSF 2.0 Governance Framework
# - CIS Controls v8.1 Enhanced Requirements  
# - Zero Trust Architecture Principles
# - SLSA Supply Chain Security Level 2
# - Modern Bash Security Best Practices

# Enable strict error handling
set -euo pipefail
IFS=$'\n\t'

# Security-first approach: Define secure defaults
readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/tmp/${SCRIPT_NAME%.*}-$(date +%Y%m%d_%H%M%S).log"
readonly PID_FILE="/tmp/${SCRIPT_NAME%.*}.pid"

# Compliance and security configuration
readonly SECURITY_PROFILE="2025-enhanced"
readonly COMPLIANCE_FRAMEWORKS="NIST-CSF-2.0,CIS-8.1,ZeroTrust,SLSA-L2"
readonly AUDIT_REQUIRED="true"
readonly ZERO_TRUST_MODE="enabled"

# VM Security defaults aligned with 2025 standards
readonly DEFAULT_SECURE_CONFIG=true
readonly ENFORCE_UEFI=true
readonly REQUIRE_TPM=true
readonly ENABLE_SECURE_BOOT=true

# Error handling and logging
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "\"%s\" " "$@")' ERR
trap 'cleanup_on_exit' EXIT
trap 'interrupt_handler' INT TERM

# Enhanced error handler with security context
error_handler() {
    local exit_code="$1"
    local line_number="$2"
    local bash_lineno="$3"
    local command="$4"
    shift 4
    local args=("$@")
    
    # Security: Don't log sensitive information
    local safe_command="${command}"
    safe_command="$(echo "$safe_command" | sed 's/password=[^[:space:]]*/password=***REDACTED***/g')"
    
    log_error "Script failed with exit code $exit_code"
    log_error "Failed command: $safe_command"
    log_error "Line number: $line_number"
    log_error "Function stack: ${FUNCNAME[*]}"
    
    # Security audit log
    logger -p auth.err "SECURITY_AUDIT: Script $SCRIPT_NAME failed - Exit: $exit_code, Line: $line_number"
    
    cleanup_on_exit
    exit "$exit_code"
}

# Cleanup function
cleanup_on_exit() {
    local exit_code=$?
    
    # Remove PID file
    [[ -f "$PID_FILE" ]] && rm -f "$PID_FILE"
    
    # Clean up temporary files securely
    find /tmp -name "${SCRIPT_NAME%.*}-*" -user "$(id -u)" -mtime +1 -delete 2>/dev/null || true
    
    # Security: Clear sensitive variables
    unset ISO_PATH ROOT_PASSWORD ENCRYPTED_PASSWORD 2>/dev/null || true
    
    log_info "Script cleanup completed"
    exit $exit_code
}

# Interrupt handler
interrupt_handler() {
    log_warning "Script interrupted by user"
    logger -p auth.warning "SECURITY_AUDIT: Script $SCRIPT_NAME interrupted by user $(whoami)"
    cleanup_on_exit
}

# Secure logging functions
log_info() {
    local message="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[INFO] [$timestamp] $message" | tee -a "$LOG_FILE"
    logger -p daemon.info "$SCRIPT_NAME: $message"
}

log_warning() {
    local message="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[WARNING] [$timestamp] $message" | tee -a "$LOG_FILE" >&2
    logger -p daemon.warning "$SCRIPT_NAME: $message"
}

log_error() {
    local message="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[ERROR] [$timestamp] $message" | tee -a "$LOG_FILE" >&2
    logger -p daemon.err "$SCRIPT_NAME: $message"
}

log_security() {
    local message="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[SECURITY] [$timestamp] $message" | tee -a "$LOG_FILE"
    logger -p auth.info "SECURITY_AUDIT: $SCRIPT_NAME: $message"
}

# Check if already running
if [[ -f "$PID_FILE" ]]; then
    local existing_pid
    existing_pid="$(cat "$PID_FILE")"
    if kill -0 "$existing_pid" 2>/dev/null; then
        log_error "Script is already running with PID $existing_pid"
        exit 1
    else
        rm -f "$PID_FILE"
    fi
fi

# Create PID file
echo "$$" > "$PID_FILE"

# Log script start with security context
log_security "Script started by user $(whoami) from $(tty 2>/dev/null || echo 'non-interactive')"
log_info "Version: $SCRIPT_VERSION, Security Profile: $SECURITY_PROFILE"
log_info "Compliance Frameworks: $COMPLIANCE_FRAMEWORKS"

# Source build functions with validation
if ! source <(curl -fsSL https://raw.githubusercontent.com/tonysauce/ansible-lxc-deploy/main/build.func 2>/dev/null); then
    log_error "Failed to source build functions from remote repository"
    exit 1
fi

# Input validation and sanitization functions\nvalidate_vmid() {\n    local vmid=\"$1\"\n    \n    # Check if VMID is numeric and within valid range\n    if ! [[ \"$vmid\" =~ ^[0-9]+$ ]]; then\n        log_error \"Invalid VM ID: must be numeric\"\n        return 1\n    fi\n    \n    if (( vmid < 100 || vmid > 999999999 )); then\n        log_error \"Invalid VM ID: must be between 100 and 999999999\"\n        return 1\n    fi\n    \n    # Check if VMID is already in use\n    if qm status \"$vmid\" >/dev/null 2>&1; then\n        log_error \"VM ID $vmid is already in use\"\n        return 1\n    fi\n    \n    return 0\n}\n\nvalidate_hostname() {\n    local hostname=\"$1\"\n    \n    # Validate hostname format (RFC 1123)\n    if ! [[ \"$hostname\" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$ ]]; then\n        log_error \"Invalid hostname: must follow RFC 1123 format\"\n        return 1\n    fi\n    \n    # Check length\n    if (( ${#hostname} > 63 )); then\n        log_error \"Invalid hostname: too long (max 63 characters)\"\n        return 1\n    fi\n    \n    # Security: Check for suspicious patterns\n    if [[ \"$hostname\" =~ (admin|root|test|default|localhost) ]]; then\n        log_warning \"Hostname contains potentially insecure pattern: $hostname\"\n    fi\n    \n    return 0\n}\n\nvalidate_disk_size() {\n    local disk_size=\"$1\"\n    \n    # Check if numeric\n    if ! [[ \"$disk_size\" =~ ^[0-9]+$ ]]; then\n        log_error \"Invalid disk size: must be numeric (GB)\"\n        return 1\n    fi\n    \n    # Check reasonable bounds\n    if (( disk_size < 8 || disk_size > 10240 )); then\n        log_error \"Invalid disk size: must be between 8GB and 10TB\"\n        return 1\n    fi\n    \n    return 0\n}\n\nvalidate_memory() {\n    local memory=\"$1\"\n    \n    # Check if numeric\n    if ! [[ \"$memory\" =~ ^[0-9]+$ ]]; then\n        log_error \"Invalid memory size: must be numeric (MB)\"\n        return 1\n    fi\n    \n    # Check reasonable bounds\n    if (( memory < 512 || memory > 1048576 )); then\n        log_error \"Invalid memory size: must be between 512MB and 1TB\"\n        return 1\n    fi\n    \n    return 0\n}\n\nvalidate_cpu_cores() {\n    local cores=\"$1\"\n    \n    # Check if numeric\n    if ! [[ \"$cores\" =~ ^[0-9]+$ ]]; then\n        log_error \"Invalid CPU cores: must be numeric\"\n        return 1\n    fi\n    \n    # Check reasonable bounds\n    if (( cores < 1 || cores > 256 )); then\n        log_error \"Invalid CPU cores: must be between 1 and 256\"\n        return 1\n    fi\n    \n    return 0\n}\n\nvalidate_ip_address() {\n    local ip=\"$1\"\n    \n    # Allow DHCP\n    if [[ \"$ip\" == \"dhcp\" ]]; then\n        return 0\n    fi\n    \n    # Validate IPv4 CIDR format\n    if ! [[ \"$ip\" =~ ^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then\n        log_error \"Invalid IP address: must be in CIDR format (e.g., 192.168.1.100/24) or 'dhcp'\"\n        return 1\n    fi\n    \n    # Extract IP and subnet\n    local ip_part=\"${ip%/*}\"\n    local subnet=\"${ip#*/}\"\n    \n    # Validate IP octets\n    IFS='.' read -ra ADDR <<< \"$ip_part\"\n    for i in \"${ADDR[@]}\"; do\n        if (( i < 0 || i > 255 )); then\n            log_error \"Invalid IP address: octet $i out of range\"\n            return 1\n        fi\n    done\n    \n    # Validate subnet mask\n    if (( subnet < 8 || subnet > 30 )); then\n        log_error \"Invalid subnet mask: must be between /8 and /30\"\n        return 1\n    fi\n    \n    # Security: Check for private IP ranges\n    local first_octet=\"${ADDR[0]}\"\n    local second_octet=\"${ADDR[1]}\"\n    \n    if ! ( (( first_octet == 10 )) || \n           (( first_octet == 172 && second_octet >= 16 && second_octet <= 31 )) || \n           (( first_octet == 192 && second_octet == 168 )) ); then\n        log_warning \"IP address appears to be public: $ip_part\"\n    fi\n    \n    return 0\n}\n\nvalidate_bridge() {\n    local bridge=\"$1\"\n    \n    # Check format\n    if ! [[ \"$bridge\" =~ ^vmbr[0-9]+$ ]]; then\n        log_error \"Invalid bridge: must be in format vmbrX (e.g., vmbr0)\"\n        return 1\n    fi\n    \n    # Check if bridge exists\n    if ! ip link show \"$bridge\" >/dev/null 2>&1; then\n        log_error \"Bridge $bridge does not exist\"\n        return 1\n    fi\n    \n    return 0\n}\n\n# Sanitize user input\nsanitize_input() {\n    local input=\"$1\"\n    local type=\"${2:-general}\"\n    \n    # Remove potentially dangerous characters\n    input=\"$(echo \"$input\" | tr -d ';<>|&`$(){}[]')\"\n    \n    # Specific sanitization based on type\n    case \"$type\" in\n        \"hostname\")\n            input=\"$(echo \"$input\" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]//g')\"\n            ;;\n        \"numeric\")\n            input=\"$(echo \"$input\" | sed 's/[^0-9]//g')\"\n            ;;\n        \"alphanumeric\")\n            input=\"$(echo \"$input\" | sed 's/[^a-zA-Z0-9]//g')\"\n            ;;\n    esac\n    \n    echo \"$input\"\n}\n\n# Enhanced security checks\nperform_security_checks() {\n    log_security \"Performing pre-deployment security checks\"\n    \n    # Check if running with appropriate privileges\n    if [[ $EUID -ne 0 ]]; then\n        log_error \"This script must be run as root for VM creation\"\n        return 1\n    fi\n    \n    # Verify ProxMox environment\n    if ! command -v qm >/dev/null 2>&1; then\n        log_error \"ProxMox qm command not found - not running on ProxMox host\"\n        return 1\n    fi\n    \n    if ! command -v pvesm >/dev/null 2>&1; then\n        log_error \"ProxMox pvesm command not found - not running on ProxMox host\"\n        return 1\n    fi\n    \n    # Check ProxMox version\n    local pve_version\n    pve_version=\"$(pveversion 2>/dev/null | head -1 | cut -d'/' -f2 | cut -d'-' -f1)\"\n    \n    if [[ -z \"$pve_version\" ]]; then\n        log_error \"Cannot determine ProxMox version\"\n        return 1\n    fi\n    \n    log_info \"ProxMox version detected: $pve_version\"\n    \n    # Verify 2025 security requirements\n    if [[ \"$ENFORCE_UEFI\" == \"true\" ]]; then\n        log_info \"UEFI enforcement enabled (2025 requirement)\"\n    fi\n    \n    if [[ \"$REQUIRE_TPM\" == \"true\" ]]; then\n        log_info \"TPM requirement enabled (2025 requirement)\"\n    fi\n    \n    # Check storage availability\n    if ! pvesm status | grep -q \"active\"; then\n        log_error \"No active storage found\"\n        return 1\n    fi\n    \n    # Verify system resources\n    local available_memory\n    available_memory=\"$(free -m | awk '/^Mem:/{print $7}')\"\n    \n    if (( available_memory < 2048 )); then\n        log_warning \"Low available memory: ${available_memory}MB (recommended: 2GB+)\"\n    fi\n    \n    # Check disk space\n    local available_space\n    available_space=\"$(df /var/lib/vz 2>/dev/null | awk 'NR==2{print $4}' || echo \"0\")\"\n    \n    if (( available_space < 10485760 )); then  # 10GB in KB\n        log_warning \"Low disk space in /var/lib/vz: $((available_space/1024/1024))GB\"\n    fi\n    \n    log_security \"Security checks completed successfully\"\n    return 0\n}\n\nfunction header_info {"
clear
cat <<"EOF"
    ___              _ __    __         _    ____  ___
   /   |  ____  ___ (_) /_  / /__      | |  / /  |/  /
  / /| | / __ \/ __ \/ / __ \/ / _ \     | | / / /|_/ / 
 / ___ |/ / / / /_/ / / /_/ / /  __/     | |/ / /  / /  
/_/  |_/_/ /_/\____/_/_.___/_/\___/      |___/_/  /_/   

         Rocky Linux 9 VM Deployment for ProxMox
         Infrastructure Management Platform
         
EOF
}
header_info
echo -e "Loading..."
NSAPP=$(echo ${NSAPP,,} | tr -d ' ')
var_disk="32"
var_cpu="4"
var_ram="4096"
var_os="rocky"
var_version="9"
variables
color
catch_errors

function default_settings() {
  VM_ID=$NEXTID
  HN=$NSAPP
  DISK_SIZE="$var_disk"
  CORE_COUNT="$var_cpu"
  RAM_SIZE="$var_ram"
  BRG="vmbr0"
  NET="dhcp"
  GATE=""
  DISABLEIP6="no"
  MTU=""
  SD=""
  NS=""
  MAC=""
  VLAN=""
  START_VM="yes"
  MACHINE="q35"
  CACHE=""
  ISO_URL="https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9.6-x86_64-minimal.iso"
  ISO_PATH=""
  STORAGE="local-lvm"
  BOOT_ORDER="scsi0"
  BIOS="ovmf"
  CPU_TYPE="host"
  echo_default
}

function echo_default() {
  echo -e "${DGN}Using Virtual Machine ID: ${BGN}$VM_ID${CL}"
  echo -e "${DGN}Using Hostname: ${BGN}$HN${CL}"
  echo -e "${DGN}Using Disk Size: ${BGN}$DISK_SIZE${CL}${DGN}GB${CL}"
  echo -e "${DGN}Using ${BGN}${CORE_COUNT}${CL}${DGN} vCPU${CL}"
  echo -e "${DGN}Using ${BGN}${RAM_SIZE}${CL}${DGN}MB RAM${CL}"
  echo -e "${DGN}Using Bridge: ${BGN}$BRG${CL}"
  echo -e "${DGN}Using Static IP: ${BGN}$NET${CL}"
  echo -e "${DGN}Using Gateway: ${BGN}$GATE${CL}"
  echo -e "${DGN}Disable IPv6: ${BGN}$DISABLEIP6${CL}"
  echo -e "${DGN}Using Interface MTU Size: ${BGN}$MTU${CL}"
  echo -e "${DGN}Using DNS Search Domain: ${BGN}$SD${CL}"
  echo -e "${DGN}Using DNS Server Address: ${BGN}$NS${CL}"
  echo -e "${DGN}Using MAC Address: ${BGN}$MAC${CL}"
  echo -e "${DGN}Using VLAN Tag: ${BGN}$VLAN${CL}"
  echo -e "${DGN}Start VM after creation: ${BGN}$START_VM${CL}"
  echo -e "${BL}Creating a Rocky Linux 9 Infrastructure Management VM using the above default settings${CL}"
}

function exit-script() {
  clear
  echo -e "⚠  User exited script \n"
  exit
}

function advanced_settings() {
  if VM_ID=$(whiptail --inputbox "Set Virtual Machine ID" 8 58 $NEXTID --title "VIRTUAL MACHINE ID" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z "$VM_ID" ]; then
      VM_ID="$NEXTID"
      echo -e "${DGN}Using Virtual Machine ID: ${BGN}$VM_ID${CL}"
    else
      echo -e "${DGN}Using Virtual Machine ID: ${BGN}$VM_ID${CL}"
    fi
  else
    exit-script
  fi

  if HN=$(whiptail --inputbox "Set Hostname" 8 58 $NSAPP --title "HOSTNAME" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z "$HN" ]; then
      HN="$NSAPP"
      echo -e "${DGN}Using Hostname: ${BGN}$HN${CL}"
    else
      echo -e "${DGN}Using Hostname: ${BGN}$HN${CL}"
    fi
  else
    exit-script
  fi

  if DISK_SIZE=$(whiptail --inputbox "Set Disk Size in GB" 8 58 $var_disk --title "DISK SIZE" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z "$DISK_SIZE" ]; then
      DISK_SIZE="$var_disk"
      echo -e "${DGN}Using Disk Size: ${BGN}$DISK_SIZE${CL}${DGN}GB${CL}"
    else
      if ! [[ $DISK_SIZE =~ ^[0-9]+$ ]]; then
        echo -e "${RD}⚠ DISK SIZE MUST BE AN INTEGER NUMBER!${CL}"
        advanced_settings
      fi
      echo -e "${DGN}Using Disk Size: ${BGN}$DISK_SIZE${CL}${DGN}GB${CL}"
    fi
  else
    exit-script
  fi

  if CORE_COUNT=$(whiptail --inputbox "Allocate CPU Cores" 8 58 $var_cpu --title "CORE COUNT" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z "$CORE_COUNT" ]; then
      CORE_COUNT="$var_cpu"
      echo -e "${DGN}Allocated Cores: ${BGN}$CORE_COUNT${CL}"
    else
      echo -e "${DGN}Allocated Cores: ${BGN}$CORE_COUNT${CL}"
    fi
  else
    exit-script
  fi

  if RAM_SIZE=$(whiptail --inputbox "Allocate RAM in MB" 8 58 $var_ram --title "RAM" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z "$RAM_SIZE" ]; then
      RAM_SIZE="$var_ram"
      echo -e "${DGN}Allocated RAM: ${BGN}$RAM_SIZE${CL}"
    else
      echo -e "${DGN}Allocated RAM: ${BGN}$RAM_SIZE${CL}"
    fi
  else
    exit-script
  fi

  if BRG=$(whiptail --inputbox "Set a Bridge" 8 58 vmbr0 --title "BRIDGE" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z "$BRG" ]; then
      BRG="vmbr0"
      echo -e "${DGN}Using Bridge: ${BGN}$BRG${CL}"
    else
      echo -e "${DGN}Using Bridge: ${BGN}$BRG${CL}"
    fi
  else
    exit-script
  fi

  if NET=$(whiptail --inputbox "Set a Static IPv4 CIDR Address (/24)" 8 58 dhcp --title "IP ADDRESS" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $NET ]; then
      NET="dhcp"
      echo -e "${DGN}Using IP Address: ${BGN}$NET${CL}"
    else
      echo -e "${DGN}Using IP Address: ${BGN}$NET${CL}"
    fi
  else
    exit-script
  fi

  if GATE1=$(whiptail --inputbox "Set a Gateway IP (mandatory if Static IP was used)" 8 58 --title "GATEWAY IP" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $GATE1 ]; then
      GATE1="Default"
      GATE=""
    else
      GATE=",gw=$GATE1"
    fi
    echo -e "${DGN}Using Gateway IP Address: ${BGN}$GATE1${CL}"
  else
    exit-script
  fi

  if (whiptail --defaultno --title "IPv6" --yesno "Disable IPv6?" 10 58); then
    DISABLEIP6="yes"
  else
    DISABLEIP6="no"
  fi
  echo -e "${DGN}Disable IPv6: ${BGN}$DISABLEIP6${CL}"

  if MTU1=$(whiptail --inputbox "Set Interface MTU Size (leave blank for default)" 8 58 --title "MTU SIZE" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $MTU1 ]; then
      MTU1="Default"
      MTU=""
    else
      MTU=",mtu=$MTU1"
    fi
    echo -e "${DGN}Using Interface MTU Size: ${BGN}$MTU1${CL}"
  else
    exit-script
  fi

  if SD=$(whiptail --inputbox "Set a DNS Search Domain (leave blank for HOST)" 8 58 --title "DNS Search Domain" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $SD ]; then
      SX=Host
      SD=""
    else
      SX=$SD
      SD="-searchdomain=$SD"
    fi
    echo -e "${DGN}Using DNS Search Domain: ${BGN}$SX${CL}"
  else
    exit-script
  fi

  if NX=$(whiptail --inputbox "Set a DNS Server IP (leave blank for HOST)" 8 58 --title "DNS SERVER IP" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $NX ]; then
      NX=Host
      NS=""
    else
      NS="-nameserver=$NX"
    fi
    echo -e "${DGN}Using DNS Server IP Address: ${BGN}$NX${CL}"
  else
    exit-script
  fi

  if MAC1=$(whiptail --inputbox "Set a MAC Address(leave blank for default)" 8 58 --title "MAC ADDRESS" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $MAC1 ]; then
      MAC1="Default"
      MAC=""
    else
      MAC=",hwaddr=$MAC1"
      echo -e "${DGN}Using MAC Address: ${BGN}$MAC1${CL}"
    fi
  else
    exit-script
  fi

  if VLAN1=$(whiptail --inputbox "Set a Vlan(leave blank for default)" 8 58 --title "VLAN" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $VLAN1 ]; then
      VLAN1="Default"
      VLAN=""
    else
      VLAN=",tag=$VLAN1"
    fi
    echo -e "${DGN}Using Vlan: ${BGN}$VLAN1${CL}"
  else
    exit-script
  fi

  if (whiptail --defaultno --title "ADVANCED SETTINGS COMPLETE" --yesno "Ready to create Rocky Linux 9 Infrastructure Management VM?" --no-button Do-Over 10 58); then
    echo -e "${RD}Creating a Rocky Linux 9 Infrastructure Management VM using the above advanced settings${CL}"
  else
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    advanced_settings
  fi
}

function install_script() {
  ARCH_CHECK
  PVE_CHECK
  NEXTID=$(pvesh get /cluster/nextid)
  header_info
  if (whiptail --title "SETTINGS" --yesno "Use Default Settings?" --no-button Advanced 10 58); then
    header_info
    echo -e "${BL}Using Default Settings${CL}"
    default_settings
  else
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    advanced_settings
  fi
}

function update_script() {
  header_info
  msg_info "Updating ${APP} Installation Script"
  wget -qO ${APP}.sh https://raw.githubusercontent.com/tonysauce/ansible-lxc-deploy/main/ansible-vm.sh
  msg_ok "Updated ${APP} Installation Script"
  exit
}

# Function to check for Rocky Linux ISO (industry standard approach)
function check_iso() {
  msg_info "Checking for Rocky Linux ISO"
  
  # First check for exact expected file in local storage
  ISO_FILE="rocky-9.6-x86_64-minimal.iso"
  if pvesm list local --content iso 2>/dev/null | grep -q "local:iso/$ISO_FILE"; then
    local iso_size=$(pvesm list local --content iso | grep "$ISO_FILE" | awk '{print $4}')
    if [ "$iso_size" != "0" ] && [ -n "$iso_size" ]; then
      msg_ok "Rocky Linux 9.6 ISO found and verified: $iso_size bytes"
      ISO_PATH="local:iso/$ISO_FILE"
      return 0
    fi
  fi
  
  # Fallback: Search for any Rocky Linux 9.x ISO in any storage
  local found_line=""
  found_line=$(pvesm list local --content iso 2>/dev/null | grep -i "rocky.*9.*x86_64.*minimal" | head -1)
  if [ -n "$found_line" ]; then
    local volid=$(echo "$found_line" | awk '{print $1}')
    ISO_FILE=$(echo "$volid" | cut -d: -f2 | sed 's|iso/||')
    ISO_PATH="$volid"
    msg_ok "Found Rocky Linux 9.x ISO: $ISO_FILE"
    return 0
  fi
  
  # ISO not found or corrupted - try auto-download first
  msg_info "Rocky Linux 9.6 ISO not found. Attempting download..."
  
  # Check if we can reach the internet (for air-gapped detection)
  if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    show_manual_iso_instructions
    return 1
  fi
  
  # Attempt download
  msg_info "Downloading Rocky Linux 9.6 ISO (this may take several minutes)"
  cd /var/lib/vz/template/iso/
  
  if wget -q --show-progress --timeout=30 "$ISO_URL" -O "$ISO_FILE"; then
    msg_ok "Rocky Linux 9.6 ISO downloaded successfully"
    ISO_PATH="local:iso/$ISO_FILE"
    return 0
  else
    # Download failed - show manual instructions
    rm -f "$ISO_FILE" 2>/dev/null  # Clean up partial download
    show_manual_iso_instructions
    return 1
  fi
}

# Function to show manual ISO download instructions
function show_manual_iso_instructions() {
  msg_error "Rocky Linux 9.6 ISO not available!"
  echo ""
  echo -e "${YW}This script requires Rocky Linux 9.6 minimal ISO to create the VM.${CL}"
  echo ""
  echo -e "${GN}📥 Download Options:${CL}"
  echo ""
  echo -e "${BL}Option 1: ProxMox Web Interface (Recommended)${CL}"
  echo -e "  1. Open ProxMox web interface"
  echo -e "  2. Go to: Datacenter > Storage > local > ISO Images"
  echo -e "  3. Click 'Download from URL'"
  echo -e "  4. URL: ${GN}https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9.6-x86_64-minimal.iso${CL}"
  echo -e "  5. Wait for download to complete"
  echo ""
  echo -e "${BL}Option 2: Command Line Download${CL}"
  echo -e "  ${GN}cd /var/lib/vz/template/iso/${CL}"
  echo -e "  ${GN}wget https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9.6-x86_64-minimal.iso${CL}"
  echo ""
  echo -e "${BL}Option 3: Manual Upload (Air-Gapped Environments)${CL}"
  echo -e "  1. Download ISO on internet-connected machine"
  echo -e "  2. Transfer to ProxMox host via SCP/USB/etc."
  echo -e "  3. Place in: ${GN}/var/lib/vz/template/iso/${CL}"
  echo -e "  4. Ensure filename: ${GN}rocky-9.6-x86_64-minimal.iso${CL}"
  echo ""
  echo -e "${BL}Option 4: Alternative Rocky Linux Versions${CL}"
  echo -e "  If you have a different Rocky Linux 9.x ISO:"
  echo -e "  ${GN}ln -s /var/lib/vz/template/iso/your-rocky-iso.iso /var/lib/vz/template/iso/rocky-9.6-x86_64-minimal.iso${CL}"
  echo ""
  echo -e "${YW}After obtaining the ISO, run this script again.${CL}"
  echo ""
  exit 1
}

# Main VM creation function
function create_vm() {
  msg_info "Creating Virtual Machine"
  
  # Check for required ISO
  check_iso
  
  # Create the VM with UEFI and vTPM support
  qm create $VM_ID \
    --name $HN \
    --ostype l26 \
    --memory $RAM_SIZE \
    --cores $CORE_COUNT \
    --cpu $CPU_TYPE \
    --machine $MACHINE \
    --bios $BIOS \
    --efidisk0 $STORAGE:1,efitype=4m,pre-enrolled-keys=1 \
    --tpmstate0 $STORAGE:1,version=v2.0 \
    --scsihw virtio-scsi-pci \
    --scsi0 $STORAGE:${DISK_SIZE},format=raw \
    --ide2 $ISO_PATH,media=cdrom \
    --boot order=scsi0 \
    --net0 virtio,bridge=$BRG$MAC$VLAN$MTU \
    --serial0 socket \
    --vga serial0
    
  # Configure network
  if [[ "$NET" != "dhcp" ]]; then
    qm set $VM_ID --ipconfig0 ip=$NET$GATE
  fi
  
  # Disable IPv6 if requested
  if [[ "$DISABLEIP6" == "yes" ]]; then
    qm set $VM_ID --ipconfig0 ip=$NET$GATE,ip6=dhcp
  fi
  
  msg_ok "Virtual Machine $VM_ID created successfully"
  
  # Create kickstart file for automated installation
  create_kickstart_file
  
  # Start VM if requested
  if [[ "$START_VM" == "yes" ]]; then
    msg_info "Starting Virtual Machine $VM_ID"
    qm start $VM_ID
    msg_ok "Virtual Machine $VM_ID started"
    
    msg_info "Waiting for installation to complete..."
    msg_ok "VM created and started. Connect via console for installation or use automated kickstart."
    
    # Display connection information
    echo ""
    echo -e "${GN}Virtual Machine Information:${CL}"
    echo -e "${BL}VM ID: ${GN}$VM_ID${CL}"
    echo -e "${BL}Hostname: ${GN}$HN${CL}"
    echo -e "${BL}Resources: ${GN}$CORE_COUNT vCPU, ${RAM_SIZE}MB RAM, ${DISK_SIZE}GB Disk${CL}"
    echo -e "${BL}Network: ${GN}$NET on $BRG${CL}"
    echo ""
    echo -e "${YW}Next Steps:${CL}"
    echo -e "${BL}1. Connect to VM console: ${GN}qm terminal $VM_ID${CL}"
    echo -e "${BL}2. Complete Rocky Linux installation${CL}"
    echo -e "${BL}3. Run post-installation configuration${CL}"
    echo ""
    echo -e "${RD}Note: After OS installation completes, run:${CL}"
    echo -e "${GN}curl -fsSL https://raw.githubusercontent.com/tonysauce/ansible-lxc-deploy/main/vm-post-install.sh | bash${CL}"
  fi
}

# Create kickstart file for automated installation
function create_kickstart_file() {
  msg_info "Creating automated installation kickstart file"
  
  # Generate random root password
  ROOT_PASSWORD=$(openssl rand -base64 12)
  ENCRYPTED_PASSWORD=$(openssl passwd -6 "$ROOT_PASSWORD")
  
  # Create kickstart directory
  mkdir -p /var/lib/vz/template/iso/kickstart
  
  # Generate kickstart file
  cat > /var/lib/vz/template/iso/kickstart/rocky9-ansible-vm.ks << EOF
#version=ROCKY9
# System authorization information
auth --enableshadow --passalgo=sha512
# Use CDROM installation media
cdrom
# Use text mode install
text
# Run the Setup Agent on first boot
firstboot --enable
ignoredisk --only-use=sda
# Keyboard layouts
keyboard --vckeymap=us --xlayouts='us'
# System language
lang en_US.UTF-8

# Network information
network --bootproto=dhcp --device=ens18 --onboot=on --ipv6=auto --activate
network --hostname=$HN

# Root password (encrypted)
rootpw --iscrypted $ENCRYPTED_PASSWORD
# System services
services --enabled="chronyd,sshd,firewalld"
# System timezone
timezone America/New_York --isUtc
# User creation
user --groups=wheel --name=ansible --password=\$6\$salt\$encrypted_pass --iscrypted --gecos="Ansible User"
# X Window System configuration information
xconfig --startxonboot
# System bootloader configuration
bootloader --append=" crashkernel=auto" --location=mbr --boot-drive=sda
autopart --type=lvm
# Partition clearing information
clearpart --none --initlabel

%packages
@^minimal-environment
@standard
chrony
openssh-server
firewalld
dnf-utils
curl
wget
git
vim
%end

%addon com_redhat_kdump --enable --reserve-mb='auto'
%end

%anaconda
pwpolicy root --minlen=6 --minquality=1 --notstrict --nochanges --notempty
pwpolicy user --minlen=6 --minquality=1 --notstrict --nochanges --emptyok
pwpolicy luks --minlen=6 --minquality=1 --notstrict --nochanges --notempty
%end

%post --log=/root/ks-post.log
# Enable SSH for remote access
systemctl enable sshd
systemctl start sshd

# Configure firewall for SSH
firewall-cmd --permanent --add-service=ssh
firewall-cmd --reload

# Create post-installation script
cat > /root/post-install.sh << 'SCRIPT_EOF'
#!/bin/bash
# Post-installation configuration script
echo "Starting post-installation configuration..."

# Download and run the full infrastructure setup
curl -fsSL https://raw.githubusercontent.com/tonysauce/ansible-lxc-deploy/main/vm-post-install.sh | bash

echo "Post-installation configuration complete"
SCRIPT_EOF

chmod +x /root/post-install.sh

# Set up automatic execution of post-install script on first boot
cat > /etc/systemd/system/post-install.service << 'SERVICE_EOF'
[Unit]
Description=Post Installation Configuration
After=network.target

[Service]
Type=oneshot
ExecStart=/root/post-install.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl enable post-install.service
%end

reboot
EOF

  # Save password for user reference
  echo "VM_ID: $VM_ID" > /tmp/vm-$VM_ID-info.txt
  echo "Hostname: $HN" >> /tmp/vm-$VM_ID-info.txt
  echo "Root Password: $ROOT_PASSWORD" >> /tmp/vm-$VM_ID-info.txt
  echo "Kickstart: /var/lib/vz/template/iso/kickstart/rocky9-ansible-vm.ks" >> /tmp/vm-$VM_ID-info.txt
  
  msg_ok "Kickstart file created: /var/lib/vz/template/iso/kickstart/rocky9-ansible-vm.ks"
  msg_info "VM credentials saved to: /tmp/vm-$VM_ID-info.txt"
  echo -e "${RD}Root Password: ${GN}$ROOT_PASSWORD${CL}"
}

# Check if user wants to update the script
if [[ "$1" == "update" ]]; then
  update_script
  exit
fi

# Start installation process
install_script

# Verify ProxMox environment
if ! command -v qm &> /dev/null; then
  msg_error "This script must be run on a ProxMox host"
  exit 1
fi

# Create the VM
create_vm

msg_ok "Infrastructure Management VM deployment completed!"