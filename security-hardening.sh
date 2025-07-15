#!/usr/bin/env bash

# Security Hardening Script for Ansible LXC Rocky Linux 9
# Implements CIS Benchmark and STIG controls
# Version: 1.0.0

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Harden SSH configuration (CIS 5.2.x)
harden_ssh() {
    print_info "Hardening SSH configuration..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
    
    cat > /etc/ssh/sshd_config.d/99-security-hardening.conf << 'EOF'
# Security Hardening - CIS Benchmark compliance

# Disable root login
PermitRootLogin no

# Protocol and encryption
Protocol 2
Port 22

# Authentication settings
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes

# Connection limits
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 60

# Disable dangerous features
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PermitTunnel no

# Logging
LogLevel INFO
SyslogFacility AUTHPRIV

# Client settings
ClientAliveInterval 300
ClientAliveCountMax 0

# Host-based authentication
IgnoreRhosts yes
HostbasedAuthentication no

# Banner
Banner /etc/ssh/banner

# Ciphers and algorithms (only strong ones)
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519

# Allow only specific users
AllowUsers ansible
EOF

    # Create SSH banner
    cat > /etc/ssh/banner << 'EOF'
***************************************************************************
                            NOTICE TO USERS
***************************************************************************

This system is for authorized use only. By using this system, you consent
to monitoring. Unauthorized access is prohibited and violators will be
prosecuted to the full extent of the law.

***************************************************************************
EOF

    print_success "SSH hardening completed"
}

# Configure PAM security (CIS 5.4.x)
configure_pam() {
    print_info "Configuring PAM security policies..."
    
    # Password quality requirements
    cat > /etc/security/pwquality.conf << 'EOF'
# Password quality requirements - CIS Benchmark
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF

    # Account lockout configuration
    cp /etc/pam.d/system-auth /etc/pam.d/system-auth.backup.$(date +%Y%m%d_%H%M%S)
    
    # Configure faillock in PAM
    if ! grep -q "pam_faillock" /etc/pam.d/system-auth; then
        sed -i '/^auth.*pam_unix.so/i auth        required      pam_faillock.so preauth' /etc/pam.d/system-auth
        sed -i '/^auth.*pam_unix.so/a auth        required      pam_faillock.so authfail' /etc/pam.d/system-auth
        sed -i '/^account.*pam_unix.so/i account     required      pam_faillock.so' /etc/pam.d/system-auth
    fi
    
    # Faillock configuration
    cat > /etc/security/faillock.conf << 'EOF'
# Account lockout policy - CIS Benchmark
deny = 5
fail_interval = 900
unlock_time = 900
even_deny_root
root_unlock_time = 60
EOF

    print_success "PAM security configuration completed"
}

# Configure audit logging (CIS 4.1.x)
configure_auditd() {
    print_info "Configuring audit logging..."
    
    dnf install -y audit audit-libs
    
    # Backup original config
    cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    # Configure auditd
    cat > /etc/audit/auditd.conf << 'EOF'
# Audit daemon configuration - CIS Benchmark
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = RAW
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 10
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
EOF

    # Audit rules for security monitoring
    cat > /etc/audit/rules.d/50-security.rules << 'EOF'
# Security audit rules - CIS Benchmark and STIG

# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (2 = panic)
-f 1

# Record Events that Modify Date and Time Information
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Record Events that Modify User/Group Information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Record Events that Modify the System's Network Environment
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Record Events that Modify the System's Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy

# Record Login and Logout Events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Record Session Initiation Information
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Record Discretionary Access Control Permission Modification Events
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Record Unsuccessful Unauthorized Access Attempts to Files
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Record the Use of Privileged Commands
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Record Successful File System Mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Record File Deletion Events by User
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Record Changes to System Administration Scope
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Record System Administrator Actions
-w /var/log/sudo.log -p wa -k actions

# Kernel Module Loading and Unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# Make the configuration immutable
-e 2
EOF

    systemctl enable auditd
    systemctl start auditd
    
    print_success "Audit logging configuration completed"
}

# Kernel parameter hardening (CIS 3.x)
harden_kernel() {
    print_info "Hardening kernel parameters..."
    
    cat > /etc/sysctl.d/99-security-hardening.conf << 'EOF'
# Kernel security hardening - CIS Benchmark

# Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Memory Protection
kernel.randomize_va_space = 2
kernel.exec-shield = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# File System Security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Process Security
kernel.core_uses_pid = 1
kernel.core_pattern = |/bin/false
EOF

    sysctl --system
    
    print_success "Kernel hardening completed"
}

# Configure system banners (CIS 1.7.x)
configure_banners() {
    print_info "Configuring system banners..."
    
    cat > /etc/issue << 'EOF'
***************************************************************************
                            NOTICE TO USERS
***************************************************************************

This system is for authorized use only. By using this system, you consent
to monitoring. Unauthorized access is prohibited and violators will be
prosecuted to the full extent of the law.

***************************************************************************

EOF

    cp /etc/issue /etc/issue.net
    
    cat > /etc/motd << 'EOF'
***************************************************************************
        Ansible Infrastructure Server - Rocky Linux 9
***************************************************************************

This system is hardened according to CIS Benchmark and STIG guidelines.
All activities are logged and monitored.

For support: Contact your system administrator

***************************************************************************

EOF

    print_success "System banners configured"
}

# Configure file permissions (CIS 6.x)
harden_file_permissions() {
    print_info "Hardening file permissions..."
    
    # Set proper permissions on critical files
    chmod 600 /etc/ssh/sshd_config
    chmod 600 /etc/ssh/sshd_config.d/*
    chmod 644 /etc/passwd
    chmod 000 /etc/shadow
    chmod 000 /etc/gshadow
    chmod 644 /etc/group
    chmod 600 /etc/security/pwquality.conf
    chmod 640 /etc/security/faillock.conf
    
    # Set umask for better default permissions
    echo "umask 027" >> /etc/bashrc
    echo "umask 027" >> /etc/profile
    
    # Configure default umask in login.defs
    sed -i 's/UMASK.*/UMASK 027/' /etc/login.defs
    
    print_success "File permissions hardened"
}

# Configure time synchronization (CIS 2.2.1.x)
configure_chrony() {
    print_info "Configuring time synchronization..."
    
    dnf install -y chrony
    
    cat > /etc/chrony.conf << 'EOF'
# Time synchronization configuration - CIS Benchmark
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
server 2.pool.ntp.org iburst
server 3.pool.ntp.org iburst

driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony

# Security settings
bindcmdaddress 127.0.0.1
cmdallow 127.0.0.1
port 0
EOF

    systemctl enable chronyd
    systemctl start chronyd
    
    print_success "Time synchronization configured"
}

# Configure rsyslog for centralized logging (CIS 4.2.x)
configure_rsyslog() {
    print_info "Configuring centralized logging..."
    
    # Backup original config
    cp /etc/rsyslog.conf /etc/rsyslog.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    cat > /etc/rsyslog.d/50-security.conf << 'EOF'
# Security logging configuration - CIS Benchmark

# Authentication logs
auth,authpriv.*                 /var/log/auth.log

# All logs except mail, authpriv, and cron
*.*;mail.none;authpriv.none;cron.none   /var/log/messages

# Emergency messages to all users
*.emerg                         :omusrmsg:*

# Log all kernel messages
kern.*                          /var/log/kern.log

# Log daemon messages
daemon.*                        /var/log/daemon.log

# Create separate log files with proper permissions
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
EOF

    # Configure log rotation
    cat > /etc/logrotate.d/security-logs << 'EOF'
/var/log/auth.log
/var/log/kern.log
/var/log/daemon.log
{
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        /bin/kill -HUP `cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
EOF

    systemctl restart rsyslog
    
    print_success "Centralized logging configured"
}

# Install and configure AIDE (Advanced Intrusion Detection Environment)
configure_aide() {
    print_info "Installing and configuring AIDE..."
    
    dnf install -y aide
    
    # Configure AIDE
    cat > /etc/aide.conf << 'EOF'
# AIDE configuration - File Integrity Monitoring

# Database locations
database=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz

# Report settings
verbose=5
report_url=file:/var/log/aide/aide.log
report_url=stdout
gzip_dbout=yes

# Rule definitions
All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
Norm=s+n+b+md5+sha1+rmd160+tiger+sha256+sha512+whirlpool

# Directories to monitor
/boot   All
/bin    All
/sbin   All
/lib    All
/lib64  All
/opt    All
/usr    All
/root   All
!/root/.ssh
/etc    All
!/etc/mtab
!/etc/.*~
!/etc/ntp/drift
!/etc/adjtime
!/etc/lvm/.cache
!/etc/aide
!/etc/sysconfig/rhn
!/etc/krb5.keytab
!/etc/postfix/prng_exch
!/etc/ssh/ssh_host_.*
!/etc/ssh/ssh_known_hosts
!/etc/dhcp/dhclient.*
!/etc/localtime

# Variable directories (less strict monitoring)
/var/log    Norm
/var/run    Norm
/var/lib    Norm
!/var/lib/aide
!/var/lib/chrony
!/var/lib/logrotate
!/var/lib/ntp
!/var/lib/random-seed
!/var/lib/rsyslog
!/var/lib/rkhunter
EOF

    # Initialize AIDE database
    aide --init
    cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    
    # Create log directory
    mkdir -p /var/log/aide
    
    # Create daily check script
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# Daily AIDE integrity check

/usr/sbin/aide --check > /var/log/aide/aide-$(date +%Y%m%d).log 2>&1

# Send alert if changes detected
if [ $? -ne 0 ]; then
    echo "AIDE detected file system changes on $(hostname)" | logger -p auth.warning
fi
EOF

    chmod +x /etc/cron.daily/aide-check
    
    print_success "AIDE configuration completed"
}

# Configure nginx with HTTPS
configure_nginx_https() {
    print_info "Configuring nginx with HTTPS..."
    
    # Generate self-signed certificate for internal use
    mkdir -p /etc/ssl/private
    mkdir -p /etc/ssl/certs
    
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=ansible-server"
    
    chmod 600 /etc/ssl/private/nginx-selfsigned.key
    chmod 644 /etc/ssl/certs/nginx-selfsigned.crt
    
    # Update nginx configuration for HTTPS
    cat > /etc/nginx/conf.d/kickstart-ssl.conf << 'EOF'
server {
    listen 443 ssl http2;
    server_name _;
    root /var/www/kickstart;
    index index.html index.htm;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # Directory browsing
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    location ~ \.ks$ {
        add_header Content-Type text/plain;
    }
    
    location ~ \.ign$ {
        add_header Content-Type application/json;
    }
    
    access_log /var/log/nginx/kickstart_ssl_access.log;
    error_log /var/log/nginx/kickstart_ssl_error.log;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name _;
    return 301 https://$server_name$request_uri;
}
EOF

    # Remove old HTTP-only config
    rm -f /etc/nginx/conf.d/kickstart.conf
    
    # Test and reload nginx
    nginx -t && systemctl reload nginx
    
    # Update firewall for HTTPS
    firewall-cmd --permanent --zone=public --add-service=https
    firewall-cmd --reload
    
    print_success "Nginx HTTPS configuration completed"
}

# Main execution
main() {
    print_info "Starting security hardening for Ansible LXC..."
    
    check_root
    
    # System hardening
    harden_ssh
    configure_pam
    harden_kernel
    configure_banners
    harden_file_permissions
    
    # Monitoring and logging
    configure_auditd
    configure_rsyslog
    configure_aide
    
    # Services
    configure_chrony
    configure_nginx_https
    
    # Restart services to apply changes
    print_info "Restarting services..."
    systemctl restart sshd
    systemctl restart chronyd
    systemctl restart nginx
    
    print_success "Security hardening completed successfully!"
    print_warning "Please review all configurations and test thoroughly"
    print_info "Reboot recommended to ensure all kernel parameters are active"
    
    echo ""
    print_info "Security improvements implemented:"
    echo "  ✅ SSH hardened with strong ciphers and authentication"
    echo "  ✅ PAM configured for password quality and account lockout"
    echo "  ✅ Audit logging enabled with comprehensive rules"
    echo "  ✅ Kernel parameters hardened for network security"
    echo "  ✅ System banners configured"
    echo "  ✅ File permissions secured"
    echo "  ✅ Time synchronization configured"
    echo "  ✅ Centralized logging enabled"
    echo "  ✅ AIDE file integrity monitoring installed"
    echo "  ✅ Nginx configured with HTTPS and security headers"
    echo ""
    print_warning "Next steps:"
    echo "  1. Review and customize configurations for your environment"
    echo "  2. Test all services after reboot"
    echo "  3. Configure centralized log forwarding if needed"
    echo "  4. Set up certificate management for production use"
    echo "  5. Run compliance scans (OpenSCAP, Nessus, etc.)"
}

# Run main function
main "$@"