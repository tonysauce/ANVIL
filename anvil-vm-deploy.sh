#!/usr/bin/env bash
# anvil-vm-deploy.sh - ANVIL Infrastructure Management Platform
# Version: 3.0.1 - Syntax Fixed Edition

# Enable strict error handling
set -euo pipefail

# Source build functions with error handling
if ! source <(curl -fsSL https://raw.githubusercontent.com/tonysauce/ansible-lxc-deploy/main/build.func 2>/dev/null); then
    echo "[WARNING] Could not source build functions - using fallback functions"
fi

# Ensure all color variables are defined (fallback if not set by build.func)
RED="${RED:-\033[0;31m}"
GREEN="${GREEN:-\033[0;32m}"
YELLOW="${YELLOW:-\033[1;33m}"
BLUE="${BLUE:-\033[0;34m}"
NC="${NC:-\033[0m}"

# Ensure fallback functions exist
if ! declare -f msg_info >/dev/null 2>&1; then
    msg_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
fi
if ! declare -f msg_ok >/dev/null 2>&1; then
    msg_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
fi
if ! declare -f msg_error >/dev/null 2>&1; then
    msg_error() { echo -e "${RED}[ERROR]${NC} $1"; }
fi

# Ensure all color variables used in script are defined
DGN="${DGN:-$GREEN}"
BGN="${BGN:-$BLUE}"
CL="${CL:-$NC}"
BL="${BL:-$BLUE}"
YW="${YW:-$YELLOW}"
RD="${RD:-$RED}"
GN="${GN:-$GREEN}"

# Basic logging function
log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') $1"
}

function header_info {
clear
cat <<"EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║      █████╗ ███╗   ██╗██╗   ██╗██╗██╗                        ║
║     ██╔══██╗████╗  ██║██║   ██║██║██║                        ║
║     ███████║██╔██╗ ██║██║   ██║██║██║                        ║
║     ██╔══██║██║╚██╗██║╚██╗ ██╔╝██║██║                        ║
║     ██║  ██║██║ ╚████║ ╚████╔╝ ██║███████╗                   ║
║     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝╚══════╝                   ║
║                                                               ║
║        Ansible Navigator & Virtual Infrastructure Lab        ║
║           Rocky Linux Infrastructure Management VM           ║
║                 Cockpit • Ansible • Tang • Nginx            ║
║                                                               ║
║              ⚠️  WORK IN PROGRESS - BETA SOFTWARE ⚠️           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
}

# Set default application name if not defined
NSAPP="${NSAPP:-anvil}"

header_info
echo -e "Loading..."

# Sanitize application name
NSAPP=$(echo "${NSAPP,,}" | tr -d ' ')

# VM configuration defaults
var_disk="32"
var_cpu="4"
var_ram="4096"
var_os="rocky"
var_version="9"

# Initialize build functions if available
if declare -f variables >/dev/null 2>&1; then
    variables
fi
if declare -f color >/dev/null 2>&1; then
    color
fi
if declare -f catch_errors >/dev/null 2>&1; then
    catch_errors
fi

# Fallback function definitions if not loaded from build.func
if ! declare -f ARCH_CHECK >/dev/null 2>&1; then
    ARCH_CHECK() {
        if [[ "$(uname -m)" != "x86_64" ]]; then
            msg_error "This script requires x86_64 architecture"
            exit 1
        fi
    }
fi

if ! declare -f PVE_CHECK >/dev/null 2>&1; then
    PVE_CHECK() {
        if ! command -v pveversion >/dev/null 2>&1; then
            msg_error "This script must be run on a ProxMox host"
            exit 1
        fi
    }
fi

function default_settings() {
  # Get next available VM ID
  if command -v pvesh >/dev/null 2>&1; then
    NEXTID=$(pvesh get /cluster/nextid 2>/dev/null || echo "100")
  else
    NEXTID="100"
  fi
  
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
  ISO_URL="https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9.6-x86_64-dvd.iso"
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
  echo -e "${DGN}Firmware: ${BGN}UEFI with vTPM 2.0${CL}"
  echo -e "${BL}Creating ANVIL - Infrastructure Management Platform using the above default settings${CL}"
}

function exit-script() {
  clear
  echo -e "⚠  User exited script \n"
  exit
}

function advanced_settings() {
  # Get next available VM ID
  if command -v pvesh >/dev/null 2>&1; then
    NEXTID=$(pvesh get /cluster/nextid 2>/dev/null || echo "100")
  else
    NEXTID="100"
  fi

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
    if [ -z "$NET" ]; then
      NET="dhcp"
      echo -e "${DGN}Using IP Address: ${BGN}$NET${CL}"
    else
      echo -e "${DGN}Using IP Address: ${BGN}$NET${CL}"
    fi
  else
    exit-script
  fi

  if GATE1=$(whiptail --inputbox "Set a Gateway IP (mandatory if Static IP was used)" 8 58 --title "GATEWAY IP" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z "$GATE1" ]; then
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
    if [ -z "$MTU1" ]; then
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
    if [ -z "$SD" ]; then
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
    if [ -z "$NX" ]; then
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
    if [ -z "$MAC1" ]; then
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
    if [ -z "$VLAN1" ]; then
      VLAN1="Default"
      VLAN=""
    else
      VLAN=",tag=$VLAN1"
    fi
    echo -e "${DGN}Using Vlan: ${BGN}$VLAN1${CL}"
  else
    exit-script
  fi

  if (whiptail --defaultno --title "ADVANCED SETTINGS COMPLETE" --yesno "Ready to create ANVIL Infrastructure Management Platform?" --no-button Do-Over 10 58); then
    echo -e "${RD}Creating ANVIL - Infrastructure Management Platform using the above advanced settings${CL}"
  else
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    advanced_settings
  fi
}

function install_script() {
  ARCH_CHECK
  PVE_CHECK
  
  # Get next available VM ID
  if command -v pvesh >/dev/null 2>&1; then
    NEXTID=$(pvesh get /cluster/nextid 2>/dev/null || echo "100")
  else
    NEXTID="100"
  fi
  
  header_info
  if (whiptail --title "INSTALLATION METHOD" --yesno "Use Automated Kickstart Installation?\n\nYes: Fully automated ANVIL installation\nNo: Manual installation with guidance" --no-button Manual 12 60); then
    USE_KICKSTART="yes"
    header_info
    echo -e "${GN}Using Automated Kickstart Installation${CL}"
    echo -e "${BL}ANVIL will be installed automatically with STIG compliance${CL}"
  else
    USE_KICKSTART="no"
    header_info
    echo -e "${YW}Using Manual Installation${CL}"
  fi

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
  msg_info "Updating Installation Script"
  wget -qO anvil-vm-deploy.sh https://raw.githubusercontent.com/tonysauce/anvil-infrastructure-lab/main/anvil-vm-deploy.sh
  msg_ok "Updated Installation Script"
  exit
}

# Function to check for Rocky Linux ISO (improved version)
function check_iso() {
  msg_info "Checking for Rocky Linux ISO"
  
  # First check for exact expected file in local storage (try both cases)
  for ISO_FILE in "Rocky-9.6-x86_64-dvd.iso" "rocky-9.6-x86_64-dvd.iso"; do
    if pvesm list local --content iso 2>/dev/null | grep -q "local:iso/$ISO_FILE"; then
      local iso_size=$(pvesm list local --content iso | grep "$ISO_FILE" | awk '{print $4}')
      if [ "$iso_size" != "0" ] && [ -n "$iso_size" ]; then
        msg_ok "Rocky Linux 9.6 ISO found and verified: $iso_size bytes"
        ISO_PATH="local:iso/$ISO_FILE"
        return 0
      fi
    fi
  done
  
  # Fallback: Search for any Rocky Linux 9.x ISO in any storage
  local found_line=""
  found_line=$(pvesm list local --content iso 2>/dev/null | grep -i "rocky.*9.*x86_64.*\(dvd\|minimal\)" | head -1)
  if [ -n "$found_line" ]; then
    local volid=$(echo "$found_line" | awk '{print $1}')
    ISO_FILE=$(echo "$volid" | cut -d: -f2 | sed 's|iso/||')
    ISO_PATH="$volid"
    msg_ok "Found Rocky Linux 9.x ISO: $ISO_FILE"
    return 0
  fi
  
  # ISO not found - try auto-download first
  msg_info "Rocky Linux 9.6 ISO not found. Attempting download..."
  
  # Check if we can reach the internet (for air-gapped detection)
  if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    show_manual_iso_instructions
    return 1
  fi
  
  # Attempt download
  msg_info "Downloading Rocky Linux 9.6 ISO (this may take several minutes)"
  cd /var/lib/vz/template/iso/
  
  ISO_FILE="Rocky-9.6-x86_64-dvd.iso"
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
  echo -e "  4. URL: ${GN}https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9.6-x86_64-dvd.iso${CL}"
  echo -e "  5. Wait for download to complete"
  echo ""
  echo -e "${BL}Option 2: Command Line Download${CL}"
  echo -e "  ${GN}cd /var/lib/vz/template/iso/${CL}"
  echo -e "  ${GN}wget https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9.6-x86_64-dvd.iso${CL}"
  echo ""
  echo -e "${BL}Option 3: Manual Upload (Air-Gapped Environments)${CL}"
  echo -e "  1. Download ISO on internet-connected machine"
  echo -e "  2. Transfer to ProxMox host via SCP/USB/etc."
  echo -e "  3. Place in: ${GN}/var/lib/vz/template/iso/${CL}"
  echo -e "  4. Ensure filename: ${GN}rocky-9.6-x86_64-dvd.iso${CL}"
  echo ""
  echo -e "${YW}After obtaining the ISO, run this script again.${CL}"
  echo ""
  exit 1
}

# Main VM creation function with UEFI + vTPM
function create_vm() {
  msg_info "Creating Virtual Machine with UEFI + vTPM"
  
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
    --boot order=ide2 \
    --net0 virtio,bridge=$BRG$MAC$VLAN$MTU

  # Set kickstart arguments if using automated installation
  if [[ "$USE_KICKSTART" == "yes" ]]; then
    msg_info "Configuring automated kickstart installation"
    # Note: Due to QEMU/UEFI limitations, kickstart must be added manually
    # At boot menu, press TAB and add: inst.ks=https://raw.githubusercontent.com/tonysauce/ANVIL/main/anvil-kickstart.cfg
    msg_ok "VM configured for kickstart (manual boot parameter required)"
  fi
    
  # Configure network
  if [[ "$NET" != "dhcp" ]]; then
    qm set $VM_ID --ipconfig0 ip=$NET$GATE
  fi
  
  # Disable IPv6 if requested
  if [[ "$DISABLEIP6" == "yes" ]]; then
    qm set $VM_ID --ipconfig0 ip=$NET$GATE,ip6=dhcp
  fi
  
  msg_ok "Virtual Machine $VM_ID created successfully with UEFI + vTPM"
  
  # Provide installation guidance based on method
  if [[ "$USE_KICKSTART" == "yes" ]]; then
    msg_info "VM ready for automated ANVIL kickstart installation"
  else
    msg_info "VM ready for manual Rocky Linux installation"
  fi
  
  # Start VM if requested
  if [[ "$START_VM" == "yes" ]]; then
    msg_info "Starting Virtual Machine $VM_ID"
    qm start $VM_ID
    msg_ok "Virtual Machine $VM_ID started"
    
    msg_info "VM created and started successfully"
    
    # Display connection information
    echo ""
    echo -e "${GN}Virtual Machine Information:${CL}"
    echo -e "${BL}VM ID: ${GN}$VM_ID${CL}"
    echo -e "${BL}Hostname: ${GN}$HN${CL}"
    echo -e "${BL}Resources: ${GN}$CORE_COUNT vCPU, ${RAM_SIZE}MB RAM, ${DISK_SIZE}GB Disk${CL}"
    echo -e "${BL}Network: ${GN}$NET on $BRG${CL}"
    echo -e "${BL}Firmware: ${GN}UEFI with vTPM 2.0${CL}"
    echo ""
    if [[ "$USE_KICKSTART" == "yes" ]]; then
      echo -e "${GN}✅ AUTOMATED KICKSTART INSTALLATION${CL}"
      echo -e "${BL}1. Open ProxMox web interface → VM $VM_ID → Console${CL}"
      echo -e "${BL}2. At Rocky Linux boot menu, press ${YW}TAB${CL} on 'Install Rocky Linux 9.6'${CL}"
      echo -e "${BL}3. Add to end of line: ${GN}inst.ks=https://raw.githubusercontent.com/tonysauce/ANVIL/main/anvil-kickstart.cfg${CL}"
      echo -e "${BL}4. Press ${YW}ENTER${CL} - ANVIL will install automatically${CL}"
      echo -e "${BL}5. Wait ~15-20 minutes for complete installation${CL}"
      echo ""
      echo -e "${YW}ANVIL Access Credentials:${CL}"
      echo -e "${BL}• Username: ${GN}anvil${CL} / Password: ${GN}anvil123${CL} (sudo access)"
      echo -e "${BL}• Root: ${RD}locked${CL} (use anvil user with sudo)"
      echo -e "${BL}• Disk encryption: ${GN}anvil123${CL}"
      echo -e "${BL}• Web interface: ${GN}https://[VM-IP]:9090${CL} (Cockpit)"
      echo -e "${BL}• Tang server: ${GN}https://[VM-IP]/tang${CL}"
      echo ""
      echo -e "${GN}🚀 ANVIL Stack Included:${CL}"
      echo -e "${BL}• Cockpit - Web management interface${CL}"
      echo -e "${BL}• Ansible - Infrastructure automation${CL}"
      echo -e "${BL}• Tang - Network-bound disk encryption${CL}"
      echo -e "${BL}• Nginx - Reverse proxy with SSL${CL}"
      echo -e "${BL}• CrowdSec - Modern collective security${CL}"
    else
      echo -e "${YW}Manual Installation Instructions:${CL}"
      echo -e "${BL}1. Open ProxMox web interface → VM $VM_ID → Console${CL}"
      echo -e "${BL}2. Select 'Install Rocky Linux 9.6'${CL}"
      echo -e "${BL}3. Choose language and keyboard layout${CL}"
      echo -e "${BL}4. Configure disk partitioning (automatic is fine)${CL}"
      echo -e "${BL}5. Set root password and create user account${CL}"
      echo -e "${BL}6. Wait for installation to complete${CL}"
      echo ""
      echo -e "${YW}Recommended Settings:${CL}"
      echo -e "${BL}• Root password: Create a strong password${CL}"
      echo -e "${BL}• User account: Create 'ansible' user in wheel group${CL}"
      echo -e "${BL}• Network: DHCP is pre-configured${CL}"
      echo -e "${BL}• Services: Enable SSH for remote access${CL}"
      echo ""
      echo -e "${RD}After OS installation completes, run on the VM:${CL}"
      echo -e "${GN}curl -fsSL https://raw.githubusercontent.com/tonysauce/ANVIL/main/vm-post-install.sh | bash${CL}"
    fi
  fi
}

# Installation methods supported:
# 1. Automated kickstart - Fully automated ANVIL installation
# 2. Manual installation - User completes installation through ProxMox console

# Check if user wants to update the script
if [[ "${1:-}" == "update" ]]; then
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

msg_ok "ANVIL Infrastructure Management Platform deployment completed!"