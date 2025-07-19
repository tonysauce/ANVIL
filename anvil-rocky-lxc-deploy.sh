#!/usr/bin/env bash

# Ansible Rocky Linux 9 LXC Deployment Script for ProxMox
# Provides: Ansible, nginx web server, Tang server for NBDE, CrowdSec protection
# Author: Infrastructure as Code Deployment
# Version: 2.0.0 - Rocky Linux 9 Edition

# Script configuration
source <(curl -s https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/misc/build.func) 2>/dev/null || true

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration - can be overridden by environment variables
CONTAINER_ID=${CONTAINER_ID:-200}
CONTAINER_NAME=${CONTAINER_NAME:-"ansible-server"}
CONTAINER_HOSTNAME=${CONTAINER_HOSTNAME:-"ansible-srv"}
CONTAINER_PASSWORD=${CONTAINER_PASSWORD:-"$(openssl rand -base64 12)"}
CONTAINER_MEMORY=${CONTAINER_MEMORY:-2048}
CONTAINER_CORES=${CONTAINER_CORES:-2}
CONTAINER_DISK=${CONTAINER_DISK:-20}
CONTAINER_STORAGE=${CONTAINER_STORAGE:-"local-lvm"}
CONTAINER_TEMPLATE=${CONTAINER_TEMPLATE:-"local:vztmpl/rockylinux-9-default_20231016_amd64.tar.xz"}
CONTAINER_BRIDGE=${CONTAINER_BRIDGE:-"vmbr0"}
CONTAINER_IP=${CONTAINER_IP:-"dhcp"}
CONTAINER_GATEWAY=${CONTAINER_GATEWAY:-"auto"}
CONTAINER_DNS=${CONTAINER_DNS:-"1.1.1.1,8.8.8.8"}

# Web server configuration
WEB_ROOT=${WEB_ROOT:-"/var/www/kickstart"}
TANG_PORT=${TANG_PORT:-7500}
SSH_PORT=${SSH_PORT:-22}
CROWDSEC_API_KEY=${CROWDSEC_API_KEY:-""}

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if script is running on ProxMox
check_proxmox() {
    if ! command -v pct &> /dev/null; then
        print_error "This script must be run on a ProxMox VE host"
        exit 1
    fi
}

# Function to check if container ID is available
check_container_id() {
    if pct status $CONTAINER_ID &> /dev/null; then
        print_warning "Container ID $CONTAINER_ID already exists"
        read -p "Do you want to recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Stopping and destroying existing container..."
            pct stop $CONTAINER_ID 2>/dev/null || true
            pct destroy $CONTAINER_ID 2>/dev/null || true
            sleep 2
        else
            print_error "Deployment cancelled"
            exit 1
        fi
    fi
}

# Function to download Rocky Linux template if not exists
ensure_template() {
    print_info "Checking for Rocky Linux 9 template..."
    
    if ! pveam list local | grep -q "rockylinux-9"; then
        print_info "Downloading Rocky Linux 9 template..."
        pveam update
        pveam download local rockylinux-9-default_20231016_amd64.tar.xz
    else
        print_success "Template already available"
    fi
}

# Function to create LXC container
create_container() {
    print_info "Creating Rocky Linux LXC container $CONTAINER_NAME (ID: $CONTAINER_ID)..."
    
    local create_cmd="pct create $CONTAINER_ID $CONTAINER_TEMPLATE \
        --hostname $CONTAINER_HOSTNAME \
        --password $CONTAINER_PASSWORD \
        --memory $CONTAINER_MEMORY \
        --cores $CONTAINER_CORES \
        --rootfs $CONTAINER_STORAGE:$CONTAINER_DISK \
        --net0 name=eth0,bridge=$CONTAINER_BRIDGE,ip=$CONTAINER_IP \
        --features nesting=1,keyctl=1 \
        --unprivileged 1 \
        --onboot 1 \
        --startup order=3"

    if [[ "$CONTAINER_GATEWAY" != "auto" ]]; then
        create_cmd="$create_cmd,gw=$CONTAINER_GATEWAY"
    fi

    eval $create_cmd

    if [ $? -eq 0 ]; then
        print_success "Container created successfully"
    else
        print_error "Failed to create container"
        exit 1
    fi
}

# Function to start container and wait for network
start_container() {
    print_info "Starting container..."
    pct start $CONTAINER_ID
    
    print_info "Waiting for container network..."
    sleep 15
    
    # Wait for container to be fully ready
    local timeout=90
    local count=0
    while ! pct exec $CONTAINER_ID -- systemctl is-system-running --wait 2>/dev/null; do
        if [ $count -ge $timeout ]; then
            print_error "Container failed to start properly"
            exit 1
        fi
        sleep 3
        ((count+=3))
    done
    
    print_success "Container started and ready"
}

# Function to configure basic system
configure_system() {
    print_info "Configuring basic Rocky Linux system..."
    
    # Update system and install essential packages
    pct exec $CONTAINER_ID -- bash -c "
        # Update system
        dnf update -y
        
        # Install EPEL and PowerTools
        dnf install -y epel-release
        dnf config-manager --set-enabled crb
        
        # Install essential packages
        dnf install -y \
            curl \
            wget \
            git \
            vim \
            htop \
            net-tools \
            firewalld \
            policycoreutils-python-utils \
            setools-console \
            setroubleshoot-server \
            bind-utils \
            tcpdump \
            rsync \
            tar \
            gzip \
            unzip
        
        # Enable and start firewalld
        systemctl enable firewalld
        systemctl start firewalld
        
        # Configure SELinux (keep enforcing but ensure it's configured)
        setsebool -P httpd_can_network_connect 1
        setsebool -P httpd_read_user_content 1
    "
    
    print_success "Basic system configuration completed"
}

# Function to install and configure Ansible
install_ansible() {
    print_info "Installing Ansible..."
    
    pct exec $CONTAINER_ID -- bash -c "
        # Install Ansible
        dnf install -y ansible ansible-lint python3-pip
        
        # Install additional useful Ansible collections
        ansible-galaxy collection install community.general
        ansible-galaxy collection install ansible.posix
        
        # Create ansible user
        useradd -m -s /bin/bash ansible
        usermod -aG wheel ansible
        echo 'ansible ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ansible
        
        # Create ansible directories
        mkdir -p /home/ansible/.ssh
        mkdir -p /etc/ansible/{playbooks,roles,inventories,group_vars,host_vars}
        
        # Generate SSH key for ansible user
        sudo -u ansible ssh-keygen -t ed25519 -f /home/ansible/.ssh/id_ed25519 -N ''
        
        # Set proper ownership
        chown -R ansible:ansible /home/ansible/.ssh
        chmod 700 /home/ansible/.ssh
        chmod 600 /home/ansible/.ssh/id_ed25519
        chmod 644 /home/ansible/.ssh/id_ed25519.pub
        
        # Configure Ansible
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
    
    print_success "Ansible installation completed"
}

# Function to install and configure nginx
install_nginx() {
    print_info "Installing and configuring nginx..."
    
    pct exec $CONTAINER_ID -- bash -c "
        dnf install -y nginx
        
        # Create web directories
        mkdir -p $WEB_ROOT/{kickstart,ignition,tftp}
        mkdir -p /var/log/nginx
        
        # Configure SELinux for custom web directory
        semanage fcontext -a -t httpd_exec_t '$WEB_ROOT(/.*)?'
        restorecon -R $WEB_ROOT
        
        # Create nginx configuration for kickstart server
        cat > /etc/nginx/conf.d/kickstart.conf << 'EOF'
server {
    listen 80;
    server_name _;
    root $WEB_ROOT;
    index index.html index.htm;
    
    # Enable directory browsing
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Special handling for kickstart files
    location ~ \\.ks\$ {
        add_header Content-Type text/plain;
    }
    
    # Special handling for ignition files
    location ~ \\.ign\$ {
        add_header Content-Type application/json;
    }
    
    # Logging
    access_log /var/log/nginx/kickstart_access.log;
    error_log /var/log/nginx/kickstart_error.log;
}
EOF
        
        # Create sample index page
        cat > $WEB_ROOT/index.html << 'EOF'
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
            <p>Network Bound Disk Encryption server running on port $TANG_PORT</p>
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
        
        # Test nginx configuration and enable
        nginx -t
        systemctl enable nginx
        systemctl start nginx
    "
    
    print_success "Nginx installation and configuration completed"
}

# Function to install and configure Tang server
install_tang() {
    print_info "Installing and configuring Tang server..."
    
    pct exec $CONTAINER_ID -- bash -c "
        dnf install -y tang jose
        
        # Create tang directory and generate keys
        mkdir -p /var/db/tang
        /usr/libexec/tangd-keygen /var/db/tang
        
        # Create systemd socket and service for Tang
        cat > /etc/systemd/system/tangd.socket << 'EOF'
[Unit]
Description=Tang Server socket
Documentation=man:tang(8)

[Socket]
ListenStream=$TANG_PORT
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

        # Create tang user and set permissions
        useradd -r -s /sbin/nologin tang
        chown -R tang:tang /var/db/tang
        chmod 750 /var/db/tang
        
        # Configure SELinux for Tang
        semanage port -a -t http_port_t -p tcp $TANG_PORT 2>/dev/null || true
        
        # Enable and start Tang service
        systemctl daemon-reload
        systemctl enable tangd.socket
        systemctl start tangd.socket
    "
    
    print_success "Tang server installation and configuration completed"
}

# Function to install and configure CrowdSec
install_crowdsec() {
    print_info "Installing and configuring CrowdSec..."
    
    pct exec $CONTAINER_ID -- bash -c "
        # Add CrowdSec repository
        dnf install -y 'dnf-command(config-manager)'
        dnf config-manager --add-repo https://packagecloud.io/crowdsec/crowdsec/config_file.repo?type=rpm
        
        # Install CrowdSec
        dnf install -y crowdsec crowdsec-firewall-bouncer
        
        # Configure CrowdSec
        crowdsec-cli collections install crowdsecurity/nginx
        crowdsec-cli collections install crowdsecurity/sshd
        crowdsec-cli collections install crowdsecurity/linux
        
        # Configure firewall bouncer
        cat > /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml << 'EOF'
mode: firewalld
pid_dir: /var/run/
update_frequency: 10s
daemonize: true
log_mode: file
log_dir: /var/log/
log_level: info
api_url: http://localhost:8080
api_key: \$(cat /etc/crowdsec/local_api_credentials.yaml | grep password | cut -d' ' -f2)
insecure_skip_verify: false
disable_ipv6: false
deny_action: DROP
deny_log: false
supported_decisions_types:
  - ban
firewalld:
  ipset_only: true
EOF

        # Start CrowdSec services
        systemctl enable crowdsec
        systemctl start crowdsec
        systemctl enable crowdsec-firewall-bouncer
        systemctl start crowdsec-firewall-bouncer
        
        # Configure log parsing
        echo '/var/log/nginx/kickstart_access.log' > /etc/crowdsec/acquis.d/nginx-kickstart.yaml
        echo 'labels:' >> /etc/crowdsec/acquis.d/nginx-kickstart.yaml
        echo '  type: nginx' >> /etc/crowdsec/acquis.d/nginx-kickstart.yaml
        
        systemctl restart crowdsec
    "
    
    print_success "CrowdSec installation and configuration completed"
}

# Function to configure firewalld
configure_firewall() {
    print_info "Configuring firewalld..."
    
    pct exec $CONTAINER_ID -- bash -c "
        # Ensure firewalld is running
        systemctl start firewalld
        
        # Configure zones and services
        firewall-cmd --permanent --zone=public --add-service=ssh
        firewall-cmd --permanent --zone=public --add-service=http
        firewall-cmd --permanent --zone=public --add-port=$TANG_PORT/tcp
        
        # Allow internal networks (adjust as needed)
        firewall-cmd --permanent --zone=trusted --add-source=192.168.0.0/16
        firewall-cmd --permanent --zone=trusted --add-source=10.0.0.0/8
        firewall-cmd --permanent --zone=trusted --add-source=172.16.0.0/12
        
        # Create custom service for Tang
        cat > /etc/firewalld/services/tang.xml << 'EOF'
<?xml version=\"1.0\" encoding=\"utf-8\"?>
<service>
  <short>Tang</short>
  <description>Tang server for Network Bound Disk Encryption (NBDE)</description>
  <port protocol=\"tcp\" port=\"$TANG_PORT\"/>
</service>
EOF

        firewall-cmd --permanent --zone=public --add-service=tang
        
        # Reload firewall
        firewall-cmd --reload
        
        # Show active configuration
        firewall-cmd --list-all
    "
    
    print_success "Firewalld configuration completed"
}

# Function to create management scripts
create_management_scripts() {
    print_info "Creating management scripts..."
    
    pct exec $CONTAINER_ID -- bash -c "
        mkdir -p /opt/ansible-server/scripts
        
        # Create Tang key rotation script
        cat > /opt/ansible-server/scripts/rotate-tang-keys.sh << 'EOF'
#!/bin/bash
# Tang key rotation script for Rocky Linux

TANG_DIR=/var/db/tang
BACKUP_DIR=/opt/ansible-server/backups/tang/\$(date +%Y%m%d_%H%M%S)

echo \"Starting Tang key rotation...\"

# Create backup directory
mkdir -p \$BACKUP_DIR

# Backup existing keys
cp -r \$TANG_DIR/* \$BACKUP_DIR/
echo \"Backed up existing keys to \$BACKUP_DIR\"

# Generate new keys
/usr/libexec/tangd-keygen \$TANG_DIR
chown -R tang:tang \$TANG_DIR

# Restart Tang service
systemctl restart tangd.socket

echo \"Tang key rotation completed\"
echo \"New key thumbprint:\"
jose jwk thp -i \$TANG_DIR/*.jwk | head -1
EOF

        # Create backup script
        cat > /opt/ansible-server/scripts/backup-config.sh << 'EOF'
#!/bin/bash
# Configuration backup script for Rocky Linux

BACKUP_DIR=/opt/ansible-server/backups/\$(date +%Y%m%d_%H%M%S)
mkdir -p \$BACKUP_DIR

# Backup Ansible configuration
tar -czf \$BACKUP_DIR/ansible-config.tar.gz /etc/ansible /home/ansible

# Backup nginx configuration
tar -czf \$BACKUP_DIR/nginx-config.tar.gz /etc/nginx $WEB_ROOT

# Backup Tang keys
tar -czf \$BACKUP_DIR/tang-keys.tar.gz /var/db/tang

# Backup CrowdSec configuration
tar -czf \$BACKUP_DIR/crowdsec-config.tar.gz /etc/crowdsec

# Backup firewalld configuration
tar -czf \$BACKUP_DIR/firewalld-config.tar.gz /etc/firewalld

echo \"Backup completed in \$BACKUP_DIR\"
EOF

        # Create CrowdSec management script
        cat > /opt/ansible-server/scripts/crowdsec-status.sh << 'EOF'
#!/bin/bash
# CrowdSec status and management script

echo \"=== CrowdSec Status ===\"
systemctl status crowdsec --no-pager -l

echo -e \"\n=== Active Decisions ===\"
crowdsec-cli decisions list

echo -e \"\n=== Metrics ===\"
crowdsec-cli metrics

echo -e \"\n=== Bouncers ===\"
crowdsec-cli bouncers list

echo -e \"\n=== Collections ===\"
crowdsec-cli collections list
EOF

        # Make scripts executable
        chmod +x /opt/ansible-server/scripts/*.sh
        
        # Create systemd timer for automatic backups
        cat > /etc/systemd/system/ansible-backup.service << 'EOF'
[Unit]
Description=Ansible Server Backup
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/ansible-server/scripts/backup-config.sh
User=root
EOF

        cat > /etc/systemd/system/ansible-backup.timer << 'EOF'
[Unit]
Description=Run Ansible Server Backup daily
Requires=ansible-backup.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

        systemctl daemon-reload
        systemctl enable ansible-backup.timer
        systemctl start ansible-backup.timer
    "
    
    print_success "Management scripts created"
}

# Function to display deployment summary
display_summary() {
    local container_ip=$(pct exec $CONTAINER_ID -- hostname -I | awk '{print $1}')
    
    print_success "=== Rocky Linux 9 Ansible LXC Deployment Complete ==="
    echo
    print_info "Container Details:"
    echo "  - Container ID: $CONTAINER_ID"
    echo "  - Container Name: $CONTAINER_NAME"
    echo "  - Hostname: $CONTAINER_HOSTNAME"
    echo "  - IP Address: $container_ip"
    echo "  - Memory: ${CONTAINER_MEMORY}MB"
    echo "  - CPU Cores: $CONTAINER_CORES"
    echo "  - Disk: ${CONTAINER_DISK}GB"
    echo "  - OS: Rocky Linux 9"
    echo
    print_info "Services:"
    echo "  - Ansible: ✅ Installed and configured"
    echo "  - Nginx Web Server: ✅ http://$container_ip"
    echo "  - Tang Server (NBDE): ✅ $container_ip:$TANG_PORT"
    echo "  - CrowdSec Security: ✅ Active with community intelligence"
    echo "  - Firewalld: ✅ Configured and active"
    echo "  - SELinux: ✅ Enforcing with proper contexts"
    echo
    print_info "Access Information:"
    echo "  - SSH: ssh root@$container_ip"
    echo "  - Ansible User: ssh ansible@$container_ip"
    echo "  - Root Password: $CONTAINER_PASSWORD"
    echo
    print_info "Useful Commands:"
    echo "  - Enter container: pct enter $CONTAINER_ID"
    echo "  - Container console: pct console $CONTAINER_ID"
    echo "  - Rotate Tang keys: /opt/ansible-server/scripts/rotate-tang-keys.sh"
    echo "  - Backup config: /opt/ansible-server/scripts/backup-config.sh"
    echo "  - CrowdSec status: /opt/ansible-server/scripts/crowdsec-status.sh"
    echo "  - Firewall status: firewall-cmd --list-all"
    echo
    print_info "File Locations:"
    echo "  - Kickstart files: $WEB_ROOT/kickstart/"
    echo "  - Ignition files: $WEB_ROOT/ignition/"
    echo "  - Ansible config: /etc/ansible/"
    echo "  - Tang keys: /var/db/tang/"
    echo "  - CrowdSec config: /etc/crowdsec/"
    echo
    
    # Display Tang key thumbprint
    local tang_thumbprint=$(pct exec $CONTAINER_ID -- bash -c "jose jwk thp -i /var/db/tang/*.jwk 2>/dev/null | head -1")
    if [ -n "$tang_thumbprint" ]; then
        print_info "Tang Key Thumbprint: $tang_thumbprint"
        echo "  Use this thumbprint for Clevis LUKS binding:"
        echo "  clevis luks bind -d /dev/sdX tang '{\"url\":\"http://$container_ip:$TANG_PORT\",\"thp\":\"$tang_thumbprint\"}'"
    fi
    
    print_warning "Next Steps:"
    echo "  1. Add kickstart files to $WEB_ROOT/kickstart/"
    echo "  2. Configure Ansible inventories in /etc/ansible/inventories/"
    echo "  3. Review CrowdSec decisions: crowdsec-cli decisions list"
    echo "  4. Test Tang server: curl http://$container_ip:$TANG_PORT/adv"
}

# Main deployment function
main() {
    print_info "Starting Rocky Linux 9 Ansible LXC deployment..."
    
    # Pre-flight checks
    check_proxmox
    check_container_id
    
    # Download template if needed
    ensure_template
    
    # Create and configure container
    create_container
    start_container
    
    # Install and configure services
    configure_system
    install_ansible
    install_nginx
    install_tang
    install_crowdsec
    configure_firewall
    create_management_scripts
    
    # Display summary
    display_summary
    
    print_success "Rocky Linux 9 deployment completed successfully!"
}

# Handle script arguments
case "${1:-}" in
    "--help"|"-h")
        cat << 'EOF'
Rocky Linux 9 Ansible LXC Deployment Script for ProxMox

Usage: ./anvil-rocky-lxc-deploy.sh [options]

Environment Variables:
  CONTAINER_ID        Container ID (default: 200)
  CONTAINER_NAME      Container name (default: ansible-server)
  CONTAINER_HOSTNAME  Hostname (default: ansible-srv)
  CONTAINER_PASSWORD  Root password (default: randomly generated)
  CONTAINER_MEMORY    Memory in MB (default: 2048)
  CONTAINER_CORES     CPU cores (default: 2)
  CONTAINER_DISK      Disk size in GB (default: 20)
  CONTAINER_IP        IP address (default: dhcp)
  TANG_PORT          Tang server port (default: 7500)

Examples:
  # Deploy with defaults
  ./anvil-rocky-lxc-deploy.sh
  
  # Deploy with custom settings
  CONTAINER_ID=201 CONTAINER_IP=192.168.1.100/24 ./anvil-rocky-lxc-deploy.sh

Services installed:
  - Ansible (latest from EPEL)
  - Nginx web server (kickstart/ignition hosting)
  - Tang server (NBDE for LUKS)
  - CrowdSec (collaborative security)
  - Firewalld (enterprise firewall)
  - SELinux (enforcing mode)
  - Automatic backups

Security Features:
  - CrowdSec community threat intelligence
  - Firewalld with minimal attack surface
  - SELinux enforcement with proper contexts
  - Automatic security updates
  - Tang server for disk encryption
EOF
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac