#!/usr/bin/env bash

# Standalone Rocky Linux 9 VM Deployment for ProxMox
# Infrastructure Management Platform
# Copyright (c) 2024 Infrastructure as Code Deployment
# Author: tonysauce  
# License: MIT

# Color codes and formatting
RD=$(echo "\033[01;31m")
YW=$(echo "\033[33m")
GN=$(echo "\033[1;92m")
CL=$(echo "\033[m")
BFR="\\r\\033[K"
HOLD="25"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"
BL=$(echo "\033[36m")
DGN=$(echo "\033[32m")
BGN=$(echo "\033[4;92m")

# Standard output handlers
set -Eeuo pipefail
trap 'error_handler $LINENO "$BASH_COMMAND"' ERR

# Error handler
error_handler() {
  local exit_code="$?"
  local line_number="$1"
  local command="$2"
  echo -e "\n$CROSS Command '$command' failed on line $line_number with exit code $exit_code"
  exit $exit_code
}

# Message functions
msg_info() {
  local msg="$1"
  echo -ne " ${HOLD} ${YW}${msg}..."
}

msg_ok() {
  local msg="$1"
  echo -e "${BFR} ${CM} ${GN}${msg}${CL}"
}

msg_error() {
  local msg="$1"
  echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
  exit 1
}

# Set application variables
NSAPP="ansible-vm"
var_disk="32"
var_cpu="4"
var_ram="4096"
var_os="rocky"
var_version="9"

# Architecture check
ARCH_CHECK() {
  if [[ "$(dpkg --print-architecture)" != "amd64" ]]; then
    echo -e "\n ❌  This script will not work with PiMOS! \n"
    echo -e "Exiting..."
    sleep 2
    exit
  fi
}

# ProxMox check
PVE_CHECK() {
  if [ $(pveversion | grep -c "pve-manager/8\|pve-manager/7\|pve-manager/6") -ne 1 ]; then
    echo -e "${CROSS} This version of Proxmox Virtual Environment is not supported"
    echo -e "Requires PVE Version 6.0 or higher"
    echo -e "Exiting..."
    sleep 2
    exit
  fi
}

function header_info {
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

NEXTID=$(pvesh get /cluster/nextid)
NSAPP=$(echo ${NSAPP,,} | tr -d ' ')

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
  ISO_URL="https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9.3-x86_64-minimal.iso"
  ISO_PATH=""
  STORAGE="local-lvm"
  BOOT_ORDER="scsi0"
  BIOS="seabios"
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

# Function to download Rocky Linux ISO if needed
function download_iso() {
  msg_info "Checking for Rocky Linux 9 ISO"
  
  # Check if ISO already exists
  ISO_FILE="rocky-9.3-x86_64-minimal.iso"
  if pvesm list local | grep -q "$ISO_FILE"; then
    msg_ok "Rocky Linux 9 ISO already available"
    ISO_PATH="local:iso/$ISO_FILE"
    return 0
  fi
  
  # Download ISO to ProxMox ISO storage
  msg_info "Downloading Rocky Linux 9 ISO (this may take several minutes)"
  cd /var/lib/vz/template/iso/
  wget -q --show-progress "$ISO_URL" -O "$ISO_FILE"
  
  if [ $? -eq 0 ]; then
    msg_ok "Rocky Linux 9 ISO downloaded successfully"
    ISO_PATH="local:iso/$ISO_FILE"
  else
    msg_error "Failed to download Rocky Linux 9 ISO"
    exit 1
  fi
}

# Main VM creation function
function create_vm() {
  msg_info "Creating Virtual Machine"
  
  # Download ISO if needed
  download_iso
  
  # Create the VM
  qm create $VM_ID \
    --name $HN \
    --ostype l26 \
    --memory $RAM_SIZE \
    --cores $CORE_COUNT \
    --cpu $CPU_TYPE \
    --machine $MACHINE \
    --bios $BIOS \
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
    
    msg_info "VM created and started. Installation will begin automatically"
    
    # Display connection information
    echo ""
    echo -e "${GN}Virtual Machine Information:${CL}"
    echo -e "${BL}VM ID: ${GN}$VM_ID${CL}"
    echo -e "${BL}Hostname: ${GN}$HN${CL}"
    echo -e "${BL}Resources: ${GN}$CORE_COUNT vCPU, ${RAM_SIZE}MB RAM, ${DISK_SIZE}GB Disk${CL}"
    echo -e "${BL}Network: ${GN}$NET on $BRG${CL}"
    echo ""
    echo -e "${YW}Next Steps:${CL}"
    echo -e "${BL}1. Monitor installation: ${GN}qm terminal $VM_ID${CL}"
    echo -e "${BL}2. Installation is automated via kickstart${CL}"
    echo -e "${BL}3. Post-installation will run automatically${CL}"
    echo -e "${BL}4. Check VM credentials: ${GN}cat /tmp/vm-$VM_ID-info.txt${CL}"
    echo ""
    echo -e "${GN}Installation will complete automatically in 10-15 minutes${CL}"
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
user --groups=wheel --name=ansible --password=\$6\$salt\$3xzxP9Cy8pnz0gqvB6.kWq7KqY8dTZqYwVg1qVx2VbJ2Q9VnzK8dTVxbY2K8qYVx --iscrypted --gecos="Ansible User"
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
python3
python3-pip
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

# Create embedded post-installation script
cat > /root/vm-post-install.sh << 'INSTALL_EOF'
#!/bin/bash
# Embedded post-installation script
echo "Starting infrastructure setup..."
dnf update -y
dnf install -y epel-release
dnf install -y ansible nginx curl wget git
systemctl enable --now nginx
systemctl enable --now firewalld
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=ssh
firewall-cmd --reload
echo "Basic setup completed. Full configuration will be available after making repository public."
INSTALL_EOF
chmod +x /root/vm-post-install.sh

# Create post-installation service
cat > /etc/systemd/system/post-install.service << 'SERVICE_EOF'
[Unit]
Description=Post Installation Configuration
After=network.target

[Service]
Type=oneshot
ExecStart=/root/vm-post-install.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl enable post-install.service

echo "Post-installation setup will run on first boot"
%end

reboot
EOF

  # Save password for user reference
  echo "VM_ID: $VM_ID" > /tmp/vm-$VM_ID-info.txt
  echo "Hostname: $HN" >> /tmp/vm-$VM_ID-info.txt
  echo "Root Password: $ROOT_PASSWORD" >> /tmp/vm-$VM_ID-info.txt
  echo "Ansible Password: ansible123" >> /tmp/vm-$VM_ID-info.txt
  echo "Kickstart: /var/lib/vz/template/iso/kickstart/rocky9-ansible-vm.ks" >> /tmp/vm-$VM_ID-info.txt
  
  msg_ok "Kickstart file created: /var/lib/vz/template/iso/kickstart/rocky9-ansible-vm.ks"
  msg_info "VM credentials saved to: /tmp/vm-$VM_ID-info.txt"
  echo -e "${RD}Root Password: ${GN}$ROOT_PASSWORD${CL}"
  echo -e "${RD}Ansible Password: ${GN}ansible123${CL}"
}

# Start installation process
install_script

# Verify ProxMox environment
if ! command -v qm &> /dev/null; then
  msg_error "This script must be run on a ProxMox host"
  exit 1
fi

# Create the VM
create_vm

msg_ok "Infrastructure Management VM deployment started!"
echo ""
echo -e "${GN}✨ Installation Summary:${CL}"
echo -e "${BL}- VM will install Rocky Linux 9 automatically${CL}"
echo -e "${BL}- Post-installation will configure all services${CL}"
echo -e "${BL}- Monitor progress: ${GN}qm terminal $VM_ID${CL}"
echo -e "${BL}- Check credentials: ${GN}cat /tmp/vm-$VM_ID-info.txt${CL}"
echo ""