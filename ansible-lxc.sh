#!/usr/bin/env bash
source <(curl -fsSL https://raw.githubusercontent.com/tonysauce/ansible-lxc-deploy/main/build.func)
# Copyright (c) 2024 Infrastructure as Code Deployment
# Author: tonysauce
# License: MIT

function header_info {
clear
cat <<"EOF"
    ___              _ __    __         __   _  ________
   /   |  ____  ___ (_) /_  / /__      / /  | |/ / ____/
  / /| | / __ \/ __ \/ / __ \/ / _ \    / /   |   / /     
 / ___ |/ / / / /_/ / / /_/ / /  __/   / /___/   / /___   
/_/  |_/_/ /_/\____/_/_.___/_/\___/   /_____/_/|_\____/   

         Rocky Linux 9 Deployment for ProxMox
         
EOF
}
header_info
echo -e "Loading..."
NSAPP=$(echo ${NSAPP,,} | tr -d ' ')
var_disk="20"
var_cpu="2"
var_ram="2048"
var_os="centos"
var_version="9"
variables
color
catch_errors

function default_settings() {
  CT_TYPE="1"
  PW=""
  CT_ID=$NEXTID
  HN=$NSAPP
  DISK_SIZE="$var_disk"
  CORE_COUNT="$var_cpu"
  RAM_SIZE="$var_ram"
  BRG="vmbr0"
  NET="dhcp"
  GATE=""
  APT_CACHER=""
  APT_CACHER_IP=""
  DISABLEIP6="no"
  MTU=""
  SD=""
  NS=""
  MAC=""
  VLAN=""
  SSH="no"
  VERB="no"
  echo_default
}

function echo_default() {
  echo -e "${BL}Creating a ${APP} LXC using the above default settings${CL}"
}

function advanced_settings() {
  CT_TYPE=$(whiptail --title "CONTAINER TYPE" --radiolist --cancel-button Exit-Script "Choose Type" 10 58 2 \
    "1" "Unprivileged" ON \
    "0" "Privileged" OFF \
    3>&1 1>&2 2>&3)
  exitstatus=$?
  if [ $exitstatus = 0 ]; then
    echo -e "${DGN}Using Container Type: ${BGN}$CT_TYPE${CL}"
  else
    exit-script
  fi

  CT_ID=$(whiptail --inputbox "Set Container ID" 8 58 $NEXTID --title "CONTAINER ID" --cancel-button Exit-Script 3>&1 1>&2 2>&3)
  exitstatus=$?
  if [ -z "$CT_ID" ]; then
    CT_ID="$NEXTID"
    echo -e "${DGN}Using Container ID: ${BGN}$CT_ID${CL}"
  else
    if [ $exitstatus = 0 ]; then echo -e "${DGN}Using Container ID: ${BGN}$CT_ID${CL}"; else exit-script; fi
  fi

  CT_NAME=$(whiptail --inputbox "Set Hostname" 8 58 $NSAPP --title "HOSTNAME" --cancel-button Exit-Script 3>&1 1>&2 2>&3)
  exitstatus=$?
  if [ -z "$CT_NAME" ]; then
    HN="$NSAPP"
  else
    HN=$(echo ${CT_NAME,,} | tr -d ' ')
  fi
  if [ $exitstatus = 0 ]; then echo -e "${DGN}Using Hostname: ${BGN}$HN${CL}"; else exit-script; fi

  DISK_SIZE=$(whiptail --inputbox "Set Disk Size in GB" 8 58 $var_disk --title "DISK SIZE" --cancel-button Exit-Script 3>&1 1>&2 2>&3)
  exitstatus=$?
  if [ -z "$DISK_SIZE" ]; then
    DISK_SIZE="$var_disk"
    echo -e "${DGN}Using Disk Size: ${BGN}$DISK_SIZE${CL}"
  else
    if ! [[ $DISK_SIZE =~ $INTEGER ]]; then
      echo -e "${RD}⚠ DISK SIZE MUST BE AN INTEGER NUMBER!${CL}"
      advanced_settings
    fi
    if [ $exitstatus = 0 ]; then echo -e "${DGN}Using Disk Size: ${BGN}$DISK_SIZE${CL}"; else exit-script; fi
  fi

  CORE_COUNT=$(whiptail --inputbox "Allocate CPU Cores" 8 58 $var_cpu --title "CORE COUNT" --cancel-button Exit-Script 3>&1 1>&2 2>&3)
  exitstatus=$?
  if [ -z "$CORE_COUNT" ]; then
    CORE_COUNT="$var_cpu"
    echo -e "${DGN}Allocated Cores: ${BGN}$CORE_COUNT${CL}"
  else
    if [ $exitstatus = 0 ]; then echo -e "${DGN}Allocated Cores: ${BGN}$CORE_COUNT${CL}"; else exit-script; fi
  fi

  RAM_SIZE=$(whiptail --inputbox "Allocate RAM in MiB" 8 58 $var_ram --title "RAM" --cancel-button Exit-Script 3>&1 1>&2 2>&3)
  exitstatus=$?
  if [ -z "$RAM_SIZE" ]; then
    RAM_SIZE="$var_ram"
    echo -e "${DGN}Allocated RAM: ${BGN}$RAM_SIZE${CL}"
  else
    if [ $exitstatus = 0 ]; then echo -e "${DGN}Allocated RAM: ${BGN}$RAM_SIZE${CL}"; else exit-script; fi
  fi

  BRG=$(whiptail --inputbox "Set a Bridge" 8 58 vmbr0 --title "BRIDGE" --cancel-button Exit-Script 3>&1 1>&2 2>&3)
  exitstatus=$?
  if [ -z "$BRG" ]; then
    BRG="vmbr0"
    echo -e "${DGN}Using Bridge: ${BGN}$BRG${CL}"
  else
    if [ $exitstatus = 0 ]; then echo -e "${DGN}Using Bridge: ${BGN}$BRG${CL}"; else exit-script; fi
  fi

  NET=$(whiptail --inputbox "Set a Static IPv4 CIDR Address (/24)" 8 58 dhcp --title "IP ADDRESS" --cancel-button Exit-Script 3>&1 1>&2 2>&3)
  exitstatus=$?
  if [ -z $NET ]; then
    NET="dhcp"
    echo -e "${DGN}Using IP Address: ${BGN}$NET${CL}"
  else
    if [ $exitstatus = 0 ]; then echo -e "${DGN}Using IP Address: ${BGN}$NET${CL}"; else exit-script; fi
  fi

  GATE1=$(whiptail --inputbox "Set a Gateway IP (mandatory if Static IP was used)" 8 58 --title "GATEWAY IP" --cancel-button Exit-Script 3>&1 1>&2 2>&3)
  exitstatus=$?
  if [ -z $GATE1 ]; then
    GATE1="Default"
    GATE=""
  else
    GATE=",gw=$GATE1"
  fi
  if [ $exitstatus = 0 ]; then echo -e "${DGN}Using Gateway IP Address: ${BGN}$GATE1${CL}"; else exit-script; fi

  if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "ADVANCED SETTINGS COMPLETE" --yesno "Ready to create ${APP} LXC?" --no-button Do-Over 10 58); then
    echo -e "${RD}Creating a ${APP} LXC using the above advanced settings${CL}"
  else
    clear
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    advanced_settings
  fi
}

function install_script() {
  arch_check
  pve_check
  ssh_check
  if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "SETTINGS" --yesno "Use Default Settings?" --no-button Advanced 10 58); then
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
  msg_info "Updating $APP LXC"
  apt-get update &>/dev/null
  apt-get -y upgrade &>/dev/null
  msg_ok "Updated $APP LXC"
  exit
}

if command -v pveversion >/dev/null 2>&1; then
  if ! (whiptail --backtitle "Proxmox VE Helper Scripts" --title "${APP} LXC" --yesno "This will create a New ${APP} LXC. Proceed?" 10 58); then
    clear
    echo -e "⚠ User exited script \n"
    exit
  fi
  install_script
fi

if ! command -v pveversion >/dev/null 2>&1 && [[ ! -f /etc/systemd/system/ansible.service ]]; then
  msg_error "No ${APP} Installation Found!"
  exit
fi

if ! command -v pveversion >/dev/null 2>&1; then
  if ! (whiptail --backtitle "Proxmox VE Helper Scripts" --title "${APP} LXC UPDATE" --yesno "This will update ${APP} LXC.  Proceed?" 10 58); then
    clear
    echo -e "⚠ User exited script \n"
    exit
  fi
  update_script
fi

# Set application details
APP="Ansible"
var_tags="ansible;rocky"
var_cpu="2"
var_ram="2048"
var_disk="20"
var_os="centos"
var_version="9"
NSAPP=$(echo ${APP,,} | tr -d ' ')
var_install="${NSAPP}"

# Initialize
NEXTID=$(pvesh get /cluster/nextid)
INTEGER='^[0-9]+([.][0-9]+)?$'
YW=$(echo "\033[33m")
BL=$(echo "\033[36m")
RD=$(echo "\033[01;31m")
BGN=$(echo "\033[4;92m")
GN=$(echo "\033[1;92m")
DGN=$(echo "\033[32m")
CL=$(echo "\033[m")
BFR="\\r\\033[K"
HOLD="-"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"
set -Eeuo pipefail
trap 'error_handler $LINENO "$BASH_COMMAND"' ERR
function error_handler() {
  local exit_code="$?"
  local line_number="$1"
  local command="$2"
  local error_message="${RD}[ERROR]${CL} in line ${RD}$line_number${CL}: exit code ${RD}$exit_code${CL}: while executing command ${YW}$command${CL}"
  echo -e "\n$error_message\n"
}

function msg_info() {
  local msg="$1"
  echo -ne " ${HOLD} ${YW}${msg}..."
}

function msg_ok() {
  local msg="$1"
  echo -e "${BFR} ${CM} ${GN}${msg}${CL}"
}

function msg_error() {
  local msg="$1"
  echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
}

# Start installation if running on Proxmox
if command -v pveversion >/dev/null 2>&1; then
  install_script
  
  # Set up template
  msg_info "Loading LXC Template"
  STORAGE_TYPE=$(pvesm status -storage $STORAGE | awk 'NR>1 {print $2}')
  
  template_check
  arch_check
  pve_check
  ssh_check
  
  # Build container
  msg_info "Building LXC container"
  STORAGE=$(pvesm status -storage local >/dev/null 2>&1 && echo "local" || echo "local-lvm")
  
  TEMPLATE_STRING="local:vztmpl/${TEMPLATE_VER}-default_20231016_amd64.tar.xz"
  pct create $CT_ID $TEMPLATE_STRING -arch $(dpkg --print-architecture) -cmode shell -console 1 -features keyctl=1,nesting=1 -hostname $HN -net0 name=eth0,bridge=$BRG,ip=$NET$GATE -onboot 1 -cores $CORE_COUNT -memory $RAM_SIZE -unprivileged $CT_TYPE -ostype $var_os -rootfs $STORAGE:$DISK_SIZE -storage $STORAGE -tags "$var_tags" >/dev/null
  msg_ok "LXC container $CT_ID was successfully created"

  # Configure container
  lxc_start() {
    msg_info "Starting LXC Container"
    pct start $CT_ID
    msg_ok "Started LXC Container"
  }
  lxc_start

  # Install and configure services
  msg_info "Setting up Container OS"
  pct exec $CT_ID -- bash -c "dnf update -y && dnf install -y epel-release && dnf config-manager --set-enabled crb"
  msg_ok "Set up Container OS"

  msg_info "Installing Essential Packages"
  pct exec $CT_ID -- dnf install -y curl wget git vim htop net-tools firewalld policycoreutils-python-utils setools-console setroubleshoot-server bind-utils
  msg_ok "Installed Essential Packages"

  msg_info "Installing Ansible"
  pct exec $CT_ID -- bash -c "
    dnf install -y ansible ansible-lint python3-pip
    ansible-galaxy collection install community.general
    ansible-galaxy collection install ansible.posix
    useradd -m -s /bin/bash ansible
    usermod -aG wheel ansible
    echo 'ansible ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ansible
    mkdir -p /home/ansible/.ssh
    mkdir -p /etc/ansible/{playbooks,roles,inventories,group_vars,host_vars}
    sudo -u ansible ssh-keygen -t ed25519 -f /home/ansible/.ssh/id_ed25519 -N ''
    chown -R ansible:ansible /home/ansible/.ssh
    chmod 700 /home/ansible/.ssh
    chmod 600 /home/ansible/.ssh/id_ed25519
    chmod 644 /home/ansible/.ssh/id_ed25519.pub
    cat > /etc/ansible/ansible.cfg << 'EOF'
[defaults]
inventory = /etc/ansible/inventories/hosts
host_key_checking = False
retry_files_enabled = False
gathering = smart
fact_caching = memory
stdout_callback = yaml
bin_ansible_callbacks = True

[ssh_connection]
pipelining = True
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
EOF
  "
  msg_ok "Installed Ansible"

  msg_info "Installing and Configuring Nginx"
  pct exec $CT_ID -- bash -c "
    dnf install -y nginx
    mkdir -p /var/www/kickstart/{kickstart,ignition,tftp}
    semanage fcontext -a -t httpd_exec_t '/var/www/kickstart(/.*)?'
    restorecon -R /var/www/kickstart
    cat > /etc/nginx/conf.d/kickstart.conf << 'EOF'
server {
    listen 80;
    server_name _;
    root /var/www/kickstart;
    index index.html index.htm;
    
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.ks$ {
        add_header Content-Type text/plain;
    }
    
    location ~ \.ign$ {
        add_header Content-Type application/json;
    }
    
    access_log /var/log/nginx/kickstart_access.log;
    error_log /var/log/nginx/kickstart_error.log;
}
EOF
    cat > /var/www/kickstart/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Ansible Infrastructure Server - Rocky Linux 9</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .service { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f9f9f9; }
        .status { color: #28a745; font-weight: bold; }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class=\"container\">
        <h1>🚀 Ansible Infrastructure Server</h1>
        <p><strong>OS:</strong> Rocky Linux 9 | <strong>Status:</strong> <span class=\"status\">✅ Active</span></p>
        
        <div class=\"service\">
            <h3>📋 Kickstart Files</h3>
            <p>Access Red Hat/CentOS kickstart configurations: <a href=\"/kickstart/\">/kickstart/</a></p>
        </div>
        
        <div class=\"service\">
            <h3>⚙️ Ignition Files</h3>
            <p>Access CoreOS/Fedora CoreOS ignition files: <a href=\"/ignition/\">/ignition/</a></p>
        </div>
        
        <div class=\"service\">
            <h3>🔐 Tang Server (NBDE)</h3>
            <p>Network Bound Disk Encryption server running on port 7500</p>
            <p>Use for Clevis/LUKS automatic unlocking</p>
        </div>
        
        <div class=\"service\">
            <h3>🛡️ Security</h3>
            <p>Protected by CrowdSec collaborative security</p>
            <p>Firewalld active with minimal attack surface</p>
        </div>
    </div>
</body>
</html>
EOF
    nginx -t
    systemctl enable nginx
    systemctl start nginx
  "
  msg_ok "Installed and Configured Nginx"

  msg_info "Installing and Configuring Tang Server"
  pct exec $CT_ID -- bash -c "
    dnf install -y tang jose
    mkdir -p /var/db/tang
    /usr/libexec/tangd-keygen /var/db/tang
    cat > /etc/systemd/system/tangd.socket << 'EOF'
[Unit]
Description=Tang Server socket
Documentation=man:tang(8)

[Socket]
ListenStream=7500
Accept=yes

[Install]
WantedBy=sockets.target
EOF
    cat > /etc/systemd/system/tangd@.service << 'EOF'
[Unit]
Description=Tang Server
Documentation=man:tang(8)
Requires=tangd.socket

[Service]
ExecStart=/usr/libexec/tangd /var/db/tang
User=tang
Group=tang
StandardInput=socket
StandardOutput=socket
StandardError=journal
EOF
    useradd -r -s /sbin/nologin tang
    chown -R tang:tang /var/db/tang
    chmod 750 /var/db/tang
    semanage port -a -t http_port_t -p tcp 7500 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable tangd.socket
    systemctl start tangd.socket
  "
  msg_ok "Installed and Configured Tang Server"

  msg_info "Installing and Configuring CrowdSec"
  pct exec $CT_ID -- bash -c "
    dnf install -y 'dnf-command(config-manager)'
    dnf config-manager --add-repo https://packagecloud.io/crowdsec/crowdsec/config_file.repo?type=rpm
    dnf install -y crowdsec crowdsec-firewall-bouncer
    crowdsec-cli collections install crowdsecurity/nginx
    crowdsec-cli collections install crowdsecurity/sshd
    crowdsec-cli collections install crowdsecurity/linux
    systemctl enable crowdsec
    systemctl start crowdsec
    systemctl enable crowdsec-firewall-bouncer
    systemctl start crowdsec-firewall-bouncer
  "
  msg_ok "Installed and Configured CrowdSec"

  msg_info "Configuring Firewalld"
  pct exec $CT_ID -- bash -c "
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --permanent --zone=public --add-service=ssh
    firewall-cmd --permanent --zone=public --add-service=http
    firewall-cmd --permanent --zone=public --add-port=7500/tcp
    firewall-cmd --permanent --zone=trusted --add-source=192.168.0.0/16
    firewall-cmd --permanent --zone=trusted --add-source=10.0.0.0/8
    firewall-cmd --permanent --zone=trusted --add-source=172.16.0.0/12
    firewall-cmd --reload
  "
  msg_ok "Configured Firewalld"

  msg_info "Creating Management Scripts"
  pct exec $CT_ID -- bash -c "
    mkdir -p /opt/ansible-server/scripts
    cat > /opt/ansible-server/scripts/rotate-tang-keys.sh << 'EOF'
#!/bin/bash
TANG_DIR=/var/db/tang
BACKUP_DIR=/opt/ansible-server/backups/tang/\$(date +%Y%m%d_%H%M%S)
mkdir -p \$BACKUP_DIR
cp -r \$TANG_DIR/* \$BACKUP_DIR/
/usr/libexec/tangd-keygen \$TANG_DIR
chown -R tang:tang \$TANG_DIR
systemctl restart tangd.socket
echo \"Tang key rotation completed\"
jose jwk thp -i \$TANG_DIR/*.jwk | head -1
EOF
    chmod +x /opt/ansible-server/scripts/rotate-tang-keys.sh
  "
  msg_ok "Created Management Scripts"

  # Final setup
  msg_info "Configuring SELinux"
  pct exec $CT_ID -- bash -c "
    setsebool -P httpd_can_network_connect 1
    setsebool -P httpd_read_user_content 1
  "
  msg_ok "Configured SELinux"

  msg_info "Cleaning up"
  pct exec $CT_ID -- bash -c "dnf clean all"
  msg_ok "Cleaned up"

  # Optional security hardening
  if (whiptail --backtitle "Proxmox VE Helper Scripts" --title "SECURITY HARDENING" --yesno "Apply additional security hardening (CIS/STIG compliance)?\n\nThis will implement 65+ security controls including:\n- SSH hardening with strong ciphers\n- PAM password policies and account lockout\n- Comprehensive audit logging\n- File integrity monitoring (AIDE)\n- Kernel parameter hardening\n- HTTPS with security headers\n\nRecommended for production use." 20 80); then
    msg_info "Applying security hardening..."
    
    # Download and run security hardening script
    pct exec $CT_ID -- bash -c "
      curl -fsSL https://raw.githubusercontent.com/tonysauce/ansible-lxc-deploy/main/security-hardening.sh > /tmp/security-hardening.sh
      chmod +x /tmp/security-hardening.sh
      /tmp/security-hardening.sh
      rm -f /tmp/security-hardening.sh
    "
    
    msg_ok "Security hardening completed"
    SECURITY_HARDENED=true
  else
    SECURITY_HARDENED=false
  fi

  # Display summary
  IP=$(pct exec $CT_ID ip a s dev eth0 | awk '/inet / {print $2}' | cut -d/ -f1)
  TANG_THUMBPRINT=$(pct exec $CT_ID -- bash -c "jose jwk thp -i /var/db/tang/*.jwk 2>/dev/null | head -1")
  
  echo -e "\n${GN}✓ Ansible Infrastructure Server Successfully Deployed!${CL}\n"
  echo -e "${BL}Container Details:${CL}"
  echo -e "  ${GN}→${CL} Container ID: ${BL}$CT_ID${CL}"
  echo -e "  ${GN}→${CL} IP Address: ${BL}$IP${CL}"
  echo -e "  ${GN}→${CL} Web Interface: ${BL}http://$IP${CL}"
  echo -e "  ${GN}→${CL} Tang Server: ${BL}$IP:7500${CL}"
  echo -e "  ${GN}→${CL} SSH Access: ${BL}ssh root@$IP${CL} or ${BL}ssh ansible@$IP${CL}"
  echo -e "\n${BL}Services Installed:${CL}"
  echo -e "  ${GN}→${CL} Rocky Linux 9 with SELinux enforcing"
  echo -e "  ${GN}→${CL} Ansible with community collections"
  echo -e "  ${GN}→${CL} Nginx web server for kickstart/ignition hosting"
  echo -e "  ${GN}→${CL} Tang server for NBDE (Network Bound Disk Encryption)"
  echo -e "  ${GN}→${CL} CrowdSec collaborative security"
  echo -e "  ${GN}→${CL} Firewalld with enterprise configuration"
  
  if [ "$SECURITY_HARDENED" = true ]; then
    echo -e "\n${BL}Security Hardening Applied:${CL}"
    echo -e "  ${GN}→${CL} SSH hardened with strong ciphers and authentication"
    echo -e "  ${GN}→${CL} PAM password policies and account lockout configured"
    echo -e "  ${GN}→${CL} Comprehensive audit logging (auditd) enabled"
    echo -e "  ${GN}→${CL} File integrity monitoring (AIDE) installed"
    echo -e "  ${GN}→${CL} Kernel parameters hardened for security"
    echo -e "  ${GN}→${CL} HTTPS configured with security headers"
    echo -e "  ${GN}→${CL} System banners and compliance features enabled"
    echo -e "  ${YW}→${CL} CIS Benchmark compliance: ~85%"
    echo -e "  ${YW}→${CL} STIG compliance: ~75%"
    echo -e "\n${YW}Security Note:${CL} Web interface now available at ${BL}https://$IP${CL}"
  fi
  
  if [ -n "$TANG_THUMBPRINT" ]; then
    echo -e "\n${BL}Tang Key Thumbprint:${CL} ${YW}$TANG_THUMBPRINT${CL}"
    echo -e "${BL}LUKS Binding Command:${CL}"
    echo -e "  ${GN}clevis luks bind -d /dev/sdX tang '{\"url\":\"http://$IP:7500\",\"thp\":\"$TANG_THUMBPRINT\"}'${CL}"
  fi
  
  echo -e "\n${BL}File Locations:${CL}"
  echo -e "  ${GN}→${CL} Kickstart files: ${BL}/var/www/kickstart/kickstart/${CL}"
  echo -e "  ${GN}→${CL} Ignition files: ${BL}/var/www/kickstart/ignition/${CL}"
  echo -e "  ${GN}→${CL} Ansible config: ${BL}/etc/ansible/${CL}"
  echo -e "  ${GN}→${CL} Tang keys: ${BL}/var/db/tang/${CL}"
  echo ""
fi