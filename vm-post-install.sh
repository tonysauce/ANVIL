#!/bin/bash

# Post-Installation Configuration Script for Rocky Linux 9 Infrastructure Management VM
# This script configures the VM after the initial OS installation

set -euo pipefail

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging setup
LOG_FILE="/var/log/ansible-vm-setup.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

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

print_header() {
    clear
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     🚀 Rocky Linux 9 Infrastructure Management Platform      ║
║                    Post-Installation Setup                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
}

# Environment Variables with defaults
TANG_PORT=${TANG_PORT:-7500}
ANSIBLE_USER=${ANSIBLE_USER:-ansible}
HOSTNAME=${HOSTNAME:-$(hostname)}

# Main installation function
main() {
    print_header
    print_info "Starting post-installation configuration for Infrastructure Management VM"
    print_info "This will install and configure: Ansible, Nginx, Tang, CrowdSec, and security hardening"
    
    # Phase 1: System preparation
    prepare_system
    
    # Phase 2: Core service installation
    install_core_services
    
    # Phase 3: Security configuration
    configure_security
    
    # Phase 4: Management tools
    install_management_tools
    
    # Phase 5: Final configuration
    finalize_setup
    
    print_success "Infrastructure Management VM setup completed successfully!"
    display_summary
}

# System preparation
prepare_system() {
    print_info "Phase 1: Preparing system..."
    
    # Update system
    print_info "Updating system packages..."
    dnf update -y
    
    # Install EPEL repository
    print_info "Installing EPEL repository..."
    dnf install -y epel-release
    
    # Install essential packages
    print_info "Installing essential packages..."
    dnf install -y \
        curl wget git vim nano \
        htop tree unzip \
        python3 python3-pip \
        firewalld \
        chrony \
        logrotate \
        rsyslog \
        policycoreutils-python-utils \
        selinux-policy-targeted
    
    # Configure SELinux (enforcing mode)
    print_info "Configuring SELinux..."
    setenforce 1
    sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    
    # Start essential services
    systemctl enable --now firewalld
    systemctl enable --now chronyd
    systemctl enable --now rsyslog
    
    print_success "System preparation completed"
}

# Install core services
install_core_services() {
    print_info "Phase 2: Installing core services..."
    
    # Install Ansible
    install_ansible
    
    # Install Nginx
    install_nginx
    
    # Install Tang server
    install_tang
    
    # Install CrowdSec
    install_crowdsec
    
    print_success "Core services installation completed"
}

# Install Ansible
install_ansible() {
    print_info "Installing Ansible..."
    
    # Install Ansible from EPEL
    dnf install -y ansible ansible-core python3-argcomplete
    
    # Create ansible user
    if ! id "$ANSIBLE_USER" &>/dev/null; then
        useradd -m -G wheel -s /bin/bash "$ANSIBLE_USER"
        print_info "Created ansible user: $ANSIBLE_USER"
    fi
    
    # Configure sudo for ansible user
    echo "$ANSIBLE_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$ANSIBLE_USER
    
    # Create SSH key for ansible user
    sudo -u "$ANSIBLE_USER" ssh-keygen -t ed25519 -f /home/$ANSIBLE_USER/.ssh/id_ed25519 -N ""
    
    # Configure Ansible
    mkdir -p /etc/ansible/{inventories,playbooks,roles,group_vars,host_vars}
    
    # Create optimized ansible.cfg
    cat > /etc/ansible/ansible.cfg << 'EOF'
[defaults]
inventory = /etc/ansible/inventories/hosts
host_key_checking = False
timeout = 30
gathering = smart
fact_caching = memory
stdout_callback = yaml
callback_whitelist = timer, profile_tasks
remote_user = ansible
private_key_file = /home/ansible/.ssh/id_ed25519

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=/dev/null
pipelining = True
EOF

    # Install useful Ansible collections
    sudo -u "$ANSIBLE_USER" ansible-galaxy collection install community.general ansible.posix
    
    # Create sample inventory
    cat > /etc/ansible/inventories/hosts << 'EOF'
[local]
localhost ansible_connection=local

[infrastructure_vms]
# Add your managed VMs here
# vm1.example.com
# vm2.example.com

[infrastructure_lxc]
# Add your managed LXC containers here
# lxc1.example.com
# lxc2.example.com

[all:vars]
ansible_user=ansible
ansible_ssh_private_key_file=/home/ansible/.ssh/id_ed25519
EOF

    # Set proper permissions
    chown -R "$ANSIBLE_USER:$ANSIBLE_USER" /home/$ANSIBLE_USER/.ssh
    chmod 700 /home/$ANSIBLE_USER/.ssh
    chmod 600 /home/$ANSIBLE_USER/.ssh/id_ed25519
    chmod 644 /home/$ANSIBLE_USER/.ssh/id_ed25519.pub
    
    print_success "Ansible installation completed"
}

# Install Nginx
install_nginx() {
    print_info "Installing Nginx web server..."
    
    dnf install -y nginx
    
    # Create directory structure for hosting files
    mkdir -p /var/www/kickstart/{kickstart,ignition}
    mkdir -p /var/www/html/infrastructure
    
    # Create Nginx configuration
    cat > /etc/nginx/conf.d/infrastructure.conf << 'EOF'
server {
    listen 80;
    server_name _;
    root /var/www/html;
    index index.html index.htm;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    # Kickstart files
    location /kickstart/ {
        alias /var/www/kickstart/;
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
    }

    # Infrastructure management dashboard
    location /infrastructure/ {
        alias /var/www/html/infrastructure/;
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF

    # Create index page
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Infrastructure Management Platform</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .services { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 30px; }
        .service { padding: 20px; border: 1px solid #ddd; border-radius: 5px; text-align: center; }
        .service h3 { color: #007acc; margin: 0 0 10px 0; }
        .status { padding: 5px 10px; border-radius: 3px; color: white; font-size: 12px; }
        .status.running { background-color: #28a745; }
        .status.stopped { background-color: #dc3545; }
        a { color: #007acc; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Infrastructure Management Platform</h1>
        <p>Welcome to your Rocky Linux 9 Infrastructure Management VM. This platform provides automation, file hosting, and security services for your infrastructure.</p>
        
        <div class="services">
            <div class="service">
                <h3>📦 Ansible Automation</h3>
                <p>Infrastructure automation and configuration management</p>
                <div class="status running">RUNNING</div>
            </div>
            
            <div class="service">
                <h3>🌐 File Hosting</h3>
                <p><a href="/kickstart/">Kickstart Files</a> | <a href="/infrastructure/">Infrastructure Files</a></p>
                <div class="status running">RUNNING</div>
            </div>
            
            <div class="service">
                <h3>🔐 Tang NBDE Server</h3>
                <p>Network Bound Disk Encryption key server</p>
                <div class="status running">PORT 7500</div>
            </div>
            
            <div class="service">
                <h3>🛡️ CrowdSec Security</h3>
                <p>Collaborative security and threat protection</p>
                <div class="status running">MONITORING</div>
            </div>
        </div>
        
        <div style="margin-top: 30px; padding: 20px; background-color: #e9ecef; border-radius: 5px;">
            <h3>🔧 Quick Actions</h3>
            <ul>
                <li><strong>SSH Access:</strong> <code>ssh ansible@$(hostname -I | awk '{print $1}')</code></li>
                <li><strong>Upload Files:</strong> <code>scp file.ks ansible@$(hostname -I | awk '{print $1}'):/var/www/kickstart/kickstart/</code></li>
                <li><strong>Tang Thumbprint:</strong> <code>jose jwk thp -i /var/db/tang/*.jwk</code></li>
                <li><strong>System Status:</strong> <code>systemctl status ansible-management</code></li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF

    # Set proper permissions
    chown -R nginx:nginx /var/www/
    chmod -R 755 /var/www/
    
    # Configure firewall for HTTP
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
    
    # Enable and start Nginx
    systemctl enable --now nginx
    
    print_success "Nginx installation completed"
}

# Install Tang server
install_tang() {
    print_info "Installing Tang NBDE server..."
    
    dnf install -y tang jose clevis
    
    # Create Tang database directory
    mkdir -p /var/db/tang
    
    # Generate Tang keys
    /usr/libexec/tangd-keygen /var/db/tang
    
    # Configure Tang systemd service
    systemctl enable tangd.socket
    
    # Create Tang service for specific port
    cat > /etc/systemd/system/tangd@${TANG_PORT}.socket << EOF
[Unit]
Description=Tang Server socket on port ${TANG_PORT}
Documentation=man:tang(8)

[Socket]
ListenStream=${TANG_PORT}
Accept=yes

[Install]
WantedBy=sockets.target
EOF

    cat > /etc/systemd/system/tangd@${TANG_PORT}.service << 'EOF'
[Unit]
Description=Tang server
Documentation=man:tang(8)
After=network.target

[Service]
ExecStart=/usr/libexec/tangd /var/db/tang
User=tang
Group=tang
StandardInput=socket
EOF

    # Create tang user and set permissions
    useradd -r -s /sbin/nologin tang || true
    chown -R tang:tang /var/db/tang
    chmod 700 /var/db/tang
    
    # Configure SELinux for Tang
    setsebool -P tangd_can_network_connect 1
    
    # Configure firewall for Tang
    firewall-cmd --permanent --add-port=${TANG_PORT}/tcp
    firewall-cmd --reload
    
    # Start Tang service
    systemctl daemon-reload
    systemctl enable --now tangd@${TANG_PORT}.socket
    
    print_success "Tang server installation completed on port ${TANG_PORT}"
}

# Install CrowdSec
install_crowdsec() {
    print_info "Installing CrowdSec security platform..."
    
    # Install CrowdSec repository
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash
    
    # Install CrowdSec
    dnf install -y crowdsec crowdsec-firewall-bouncer-iptables
    
    # Configure CrowdSec
    systemctl enable --now crowdsec
    
    # Install common collections
    cscli collections install crowdsecurity/nginx
    cscli collections install crowdsecurity/sshd
    cscli collections install crowdsecurity/linux
    
    # Restart CrowdSec to apply collections
    systemctl restart crowdsec
    
    print_success "CrowdSec installation completed"
}

# Configure security
configure_security() {
    print_info "Phase 3: Configuring security..."
    
    # Download and run security hardening
    curl -fsSL https://raw.githubusercontent.com/tonysauce/ansible-lxc-deploy/main/security-hardening-2025.sh | bash
    
    print_success "Security configuration completed"
}

# Install management tools
install_management_tools() {
    print_info "Phase 4: Installing management tools..."
    
    # Create management script directory
    mkdir -p /opt/ansible-server/{scripts,backups,configs}
    
    # Create backup script
    create_backup_script
    
    # Create Tang key rotation script
    create_tang_rotation_script
    
    # Create system status script
    create_status_script
    
    # Create daily backup systemd timer
    create_backup_timer
    
    print_success "Management tools installation completed"
}

# Create backup script
create_backup_script() {
    cat > /opt/ansible-server/scripts/backup-config.sh << 'EOF'
#!/bin/bash
# System Configuration Backup Script

BACKUP_DIR="/opt/ansible-server/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/system-backup-$DATE.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "Creating system backup: $BACKUP_FILE"

# Create backup
tar -czf "$BACKUP_FILE" \
    /etc/ansible/ \
    /etc/nginx/ \
    /var/db/tang/ \
    /etc/crowdsec/ \
    /home/ansible/.ssh/ \
    /opt/ansible-server/scripts/ \
    2>/dev/null

# Keep only last 7 backups
find "$BACKUP_DIR" -name "system-backup-*.tar.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE"
ls -lh "$BACKUP_FILE"
EOF

    chmod +x /opt/ansible-server/scripts/backup-config.sh
}

# Create Tang key rotation script
create_tang_rotation_script() {
    cat > /opt/ansible-server/scripts/rotate-tang-keys.sh << EOF
#!/bin/bash
# Tang Key Rotation Script

TANG_DIR="/var/db/tang"
BACKUP_DIR="/opt/ansible-server/backups/tang-keys"
DATE=\$(date +%Y%m%d_%H%M%S)

mkdir -p "\$BACKUP_DIR"

echo "Rotating Tang keys..."

# Backup current keys
cp -r "\$TANG_DIR" "\$BACKUP_DIR/tang-backup-\$DATE"

# Generate new keys
/usr/libexec/tangd-keygen "\$TANG_DIR"

# Set proper permissions
chown -R tang:tang "\$TANG_DIR"
chmod 700 "\$TANG_DIR"

# Restart Tang service
systemctl restart tangd@${TANG_PORT}.socket

echo "Tang keys rotated successfully"
echo "New thumbprint:"
jose jwk thp -i \$TANG_DIR/*.jwk
EOF

    chmod +x /opt/ansible-server/scripts/rotate-tang-keys.sh
}

# Create system status script
create_status_script() {
    cat > /opt/ansible-server/scripts/system-status.sh << 'EOF'
#!/bin/bash
# System Status Check Script

echo "🚀 Infrastructure Management Platform Status"
echo "=============================================="
echo ""

# System info
echo "📊 System Information:"
echo "  Hostname: $(hostname)"
echo "  Uptime: $(uptime -p)"
echo "  Load: $(uptime | cut -d',' -f3-5)"
echo "  Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
echo "  Disk: $(df -h / | tail -1 | awk '{print $3"/"$2" ("$5" used)"}')"
echo ""

# Service status
echo "🔧 Service Status:"
services=("nginx" "tangd@7500.socket" "crowdsec" "firewalld" "sshd")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "  ✅ $service: Running"
    else
        echo "  ❌ $service: Stopped"
    fi
done
echo ""

# Network info
echo "🌐 Network Information:"
echo "  IP Address: $(hostname -I | awk '{print $1}')"
echo "  Open Ports: $(ss -tlnp | grep -E ':(22|80|443|7500)' | awk '{print $4}' | cut -d':' -f2 | sort -n | tr '\n' ' ')"
echo ""

# Security status
echo "🛡️ Security Status:"
echo "  SELinux: $(getenforce)"
echo "  Firewall: $(systemctl is-active firewalld)"
echo "  CrowdSec Alerts: $(cscli alerts list -o raw 2>/dev/null | wc -l) active"
echo ""

# Tang info
echo "🔐 Tang Server:"
if systemctl is-active --quiet tangd@7500.socket; then
    echo "  Status: Running on port 7500"
    echo "  Thumbprint: $(jose jwk thp -i /var/db/tang/*.jwk 2>/dev/null | head -1)"
else
    echo "  Status: Stopped"
fi
echo ""

# Ansible info
echo "📦 Ansible Information:"
echo "  Version: $(ansible --version | head -1)"
echo "  Collections: $(ansible-galaxy collection list | grep -c '^community\|^ansible')"
echo "  Managed Hosts: $(ansible all --list-hosts 2>/dev/null | grep -v 'hosts (' | wc -l)"
EOF

    chmod +x /opt/ansible-server/scripts/system-status.sh
}

# Create backup timer
create_backup_timer() {
    # Create systemd service
    cat > /etc/systemd/system/ansible-backup.service << 'EOF'
[Unit]
Description=Ansible Server Configuration Backup
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/ansible-server/scripts/backup-config.sh
User=root
EOF

    # Create systemd timer
    cat > /etc/systemd/system/ansible-backup.timer << 'EOF'
[Unit]
Description=Run Ansible backup daily
Requires=ansible-backup.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Enable timer
    systemctl daemon-reload
    systemctl enable --now ansible-backup.timer
}

# Finalize setup
finalize_setup() {
    print_info "Phase 5: Finalizing setup..."
    
    # Create management service
    cat > /etc/systemd/system/ansible-management.service << 'EOF'
[Unit]
Description=Ansible Infrastructure Management Platform
After=network.target nginx.service

[Service]
Type=oneshot
ExecStart=/opt/ansible-server/scripts/system-status.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ansible-management.service
    
    # Update motd
    cat > /etc/motd << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     🚀 Rocky Linux 9 Infrastructure Management Platform      ║
║                                                               ║
║  Services: Ansible • Nginx • Tang • CrowdSec                 ║
║  Web UI: http://this-server/                                  ║
║  Status: /opt/ansible-server/scripts/system-status.sh        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF

    # Set proper permissions on all scripts
    chmod +x /opt/ansible-server/scripts/*.sh
    
    # Run initial status check
    /opt/ansible-server/scripts/system-status.sh
    
    print_success "System finalization completed"
}

# Display summary
display_summary() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    🎉 SETUP COMPLETE! 🎉                     ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📋 Infrastructure Management Platform Summary:"
    echo ""
    echo "🌐 Web Interface:"
    echo "   URL: http://$(hostname -I | awk '{print $1}')/"
    echo ""
    echo "🔧 Services Installed:"
    echo "   ✅ Ansible $(ansible --version | head -1 | awk '{print $2}')"
    echo "   ✅ Nginx Web Server"
    echo "   ✅ Tang NBDE Server (Port $TANG_PORT)"
    echo "   ✅ CrowdSec Security Platform"
    echo ""
    echo "🛡️ Security Features:"
    echo "   ✅ SELinux Enforcing Mode"
    echo "   ✅ Firewall Configured"
    echo "   ✅ SSH Hardened"
    echo "   ✅ 2025 Security Standards Applied"
    echo ""
    echo "🔐 Tang Server Information:"
    if systemctl is-active --quiet tangd@${TANG_PORT}.socket; then
        echo "   Thumbprint: $(jose jwk thp -i /var/db/tang/*.jwk 2>/dev/null | head -1)"
    fi
    echo ""
    echo "📦 Quick Commands:"
    echo "   System Status: /opt/ansible-server/scripts/system-status.sh"
    echo "   Backup Config: /opt/ansible-server/scripts/backup-config.sh"
    echo "   Rotate Tang Keys: /opt/ansible-server/scripts/rotate-tang-keys.sh"
    echo ""
    echo "📁 Important Directories:"
    echo "   Ansible Config: /etc/ansible/"
    echo "   Web Files: /var/www/kickstart/"
    echo "   Scripts: /opt/ansible-server/scripts/"
    echo "   Backups: /opt/ansible-server/backups/"
    echo ""
    echo "🔑 SSH Access:"
    echo "   ssh $ANSIBLE_USER@$(hostname -I | awk '{print $1}')"
    echo "   ssh root@$(hostname -I | awk '{print $1}')"
    echo ""
    echo "Next: Add Cockpit for web-based management! 🚁"
    echo ""
}

# Error handling
trap 'print_error "Script failed at line $LINENO"' ERR

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

# Run main function
main "$@"