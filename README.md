# ANVIL - Ansible Navigator & Virtual Infrastructure Lab

🚀 **ANVIL Infrastructure Management Platform - Complete automation suite for ProxMox deployments**

ANVIL automates the deployment of enterprise-grade infrastructure management platforms with comprehensive security hardening, featuring Ansible automation, web management interfaces, and advanced encryption capabilities for modern data centers.

## Features

### 🏗️ **ANVIL Stack Components**
- **Cockpit** - Web-based server management interface (port 9090)
- **Ansible** - Infrastructure automation and orchestration platform
- **Tang** - Network-bound disk encryption server (port 7500)
- **Nginx** - Reverse proxy with SSL termination and load balancing
- **CrowdSec** - Modern collective security (replaces fail2ban)
- **Rocky Linux 9** - Enterprise-grade foundation with STIG compliance
- **Firewalld** - Zone-based firewall with enterprise features
- **SELinux** - Mandatory access controls in enforcing mode

### 🔒 **Security Features (2025 Standards)**
- **NIST CSF 2.0 Compliance** - Includes new "Govern" function
- **CIS Controls v8.1** - Enhanced governance and asset classification
- **Zero Trust Architecture** - Identity-centric security model
- **SLSA Framework** - Supply chain security Level 2+ compliance
- **AI-Enhanced Monitoring** - Machine learning threat detection
- **Comprehensive Audit Logging** - Full auditd implementation
- **File Integrity Monitoring** - AIDE for tampering detection
- **Automated Compliance Reporting** - 90%+ compliance achievement

### 🛠️ **Management Tools**
- Configuration backup scripts
- Tang key rotation utilities
- CrowdSec status monitoring
- Firewall management helpers
- AI-powered anomaly detection
- SLSA build provenance generation
- Zero Trust continuous verification
- Automated compliance assessments

### 🎣 **Code Quality & Security (Husky Git Hooks)**
- **Pre-commit security scanning** - Blocks secrets, validates scripts
- **Commit message validation** - Enforces quality standards
- **Pre-push final validation** - Comprehensive security checks
- **Infrastructure validation** - Configuration and permissions
- **Automated code quality** - Shellcheck integration
- **Security best practices** - Prevents common vulnerabilities

## Quick Start

### Prerequisites
- ProxMox VE host (version 8.0 or higher)
- Network access for package downloads
- Rocky Linux 9 LXC template (automatically downloaded)

### 🚀 One-Liner Installation

Choose your ANVIL deployment method:

#### **ANVIL LXC Container (Lightweight)**
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/tonysauce/anvil-infrastructure-lab/main/anvil-lxc-deploy.sh)"
```

#### **ANVIL Infrastructure VM (Recommended)**
```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/tonysauce/anvil-infrastructure-lab/main/anvil-vm-deploy.sh)"
```

Both ANVIL deployment options provide enterprise-grade infrastructure management with interactive setup, security hardening, and 2025 compliance standards.

### Alternative: Manual Installation

```bash
# Clone repository
git clone https://github.com/tonysauce/anvil-infrastructure-lab.git
cd anvil-infrastructure-lab

# For LXC Container
./anvil-lxc-deploy.sh

# For Virtual Machine
./anvil-vm-deploy.sh
```

### Custom Deployment

```bash
# Deploy LXC with custom settings
CONTAINER_ID=201 \
CONTAINER_IP=192.168.1.100/24 \
CONTAINER_MEMORY=4096 \
./anvil-lxc-deploy.sh

# Deploy VM with custom settings  
VM_ID=301 \
VM_IP=192.168.1.100/24 \
VM_MEMORY=8192 \
VM_DISK=64 \
./anvil-vm-deploy.sh
```

## Configuration Options

### LXC Container Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAINER_ID` | 200 | ProxMox container ID |
| `CONTAINER_NAME` | ansible-server | Container name |
| `CONTAINER_HOSTNAME` | ansible-srv | Container hostname |
| `CONTAINER_PASSWORD` | *random* | Root password |
| `CONTAINER_MEMORY` | 2048 | Memory in MB |
| `CONTAINER_CORES` | 2 | CPU cores |
| `CONTAINER_DISK` | 20 | Disk size in GB |
| `CONTAINER_IP` | dhcp | IP address configuration |
| `TANG_PORT` | 7500 | Tang server port |

### Virtual Machine Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VM_ID` | 300 | ProxMox VM ID |
| `VM_HOSTNAME` | ansible-vm | VM hostname |
| `VM_MEMORY` | 4096 | Memory in MB |
| `VM_CORES` | 4 | CPU cores |
| `VM_DISK` | 32 | Disk size in GB |
| `VM_IP` | dhcp | IP address configuration |
| `VM_STORAGE` | local-lvm | Storage location |
| `TANG_PORT` | 7500 | Tang server port |

### Network Configuration

The script supports both DHCP and static IP configurations:

```bash
# DHCP (default)
CONTAINER_IP=dhcp ./ansible-rocky-lxc-deploy.sh

# Static IP
CONTAINER_IP=192.168.1.100/24 \
CONTAINER_GATEWAY=192.168.1.1 \
./ansible-rocky-lxc-deploy.sh
```

## Usage

### Accessing Services

After deployment, access your services:

- **Web Interface**: `http://<container-ip>`
- **SSH Access**: `ssh root@<container-ip>` or `ssh ansible@<container-ip>`
- **Tang Server**: `http://<container-ip>:7500`

### File Locations

| Service | Configuration | Data |
|---------|---------------|------|
| Ansible | `/etc/ansible/` | `/home/ansible/` |
| Nginx | `/etc/nginx/` | `/var/www/kickstart/` |
| Tang | `/etc/systemd/system/tangd.*` | `/var/db/tang/` |
| CrowdSec | `/etc/crowdsec/` | `/var/log/crowdsec/` |
| Scripts | `/opt/ansible-server/scripts/` | `/opt/ansible-server/backups/` |

### Management Commands

```bash
# Enter container
pct enter <container-id>

# Rotate Tang keys
/opt/ansible-server/scripts/rotate-tang-keys.sh

# Backup configurations
/opt/ansible-server/scripts/backup-config.sh

# Check CrowdSec status
/opt/ansible-server/scripts/crowdsec-status.sh

# Firewall management
firewall-cmd --list-all
firewall-cmd --zone=public --add-port=8080/tcp --permanent
firewall-cmd --reload
```

## Ansible Configuration

### Default Setup

The script creates a fully configured Ansible environment:

- **User**: `ansible` with sudo privileges
- **SSH Key**: ED25519 key pair generated
- **Configuration**: Optimized `ansible.cfg`
- **Collections**: `community.general` and `ansible.posix` pre-installed

### Directory Structure

```
/etc/ansible/
├── ansible.cfg
├── inventories/
│   └── hosts
├── playbooks/
├── roles/
├── group_vars/
└── host_vars/
```

### Sample Inventory

Create your inventory in `/etc/ansible/inventories/hosts`:

```ini
[webservers]
web1.example.com
web2.example.com

[databases]
db1.example.com
db2.example.com

[all:vars]
ansible_user=ansible
ansible_ssh_private_key_file=/home/ansible/.ssh/id_ed25519
```

## Tang Server (NBDE)

### Using Tang for LUKS Encryption

The Tang server enables automatic disk decryption using Network Bound Disk Encryption:

```bash
# Bind LUKS device to Tang server
clevis luks bind -d /dev/sdX tang '{"url":"http://<container-ip>:7500","thp":"<tang-thumbprint>"}'

# Test binding
clevis luks unlock -d /dev/sdX
```

### Key Management

```bash
# Rotate Tang keys
/opt/ansible-server/scripts/rotate-tang-keys.sh

# View current thumbprint
jose jwk thp -i /var/db/tang/*.jwk
```

## Web Server Configuration

### Hosting Kickstart Files

Place your kickstart files in `/var/www/kickstart/kickstart/`:

```bash
# Example kickstart file
cat > /var/www/kickstart/kickstart/rhel9-minimal.ks << 'EOF'
#version=RHEL9
ignoredisk --only-use=sda
autopart
clearpart --none --initlabel
text
keyboard --vckeymap=us --xlayouts='us'
lang en_US.UTF-8
network --bootproto=dhcp --device=ens192 --onboot=on
rootpw --iscrypted $6$...
timezone America/New_York --isUtc
user --groups=wheel --name=admin --password=$6$... --iscrypted --gecos="admin"
EOF
```

### Hosting Ignition Files

Place CoreOS ignition files in `/var/www/kickstart/ignition/`:

```bash
# Example ignition file
cat > /var/www/kickstart/ignition/worker.ign << 'EOF'
{
  "ignition": {
    "version": "3.4.0"
  },
  "passwd": {
    "users": [
      {
        "name": "core",
        "sshAuthorizedKeys": [
          "ssh-rsa AAAAB3..."
        ]
      }
    ]
  }
}
EOF
```

## Security

### CrowdSec Protection

Monitor and manage CrowdSec security:

```bash
# View active bans
crowdsec-cli decisions list

# Check metrics
crowdsec-cli metrics

# View detected scenarios
crowdsec-cli alerts list
```

### Firewall Management

```bash
# View current rules
firewall-cmd --list-all

# Add new service
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --reload

# Add custom port
firewall-cmd --permanent --zone=public --add-port=8080/tcp
firewall-cmd --reload
```

## Troubleshooting

### Common Issues

1. **Container won't start**
   ```bash
   pct start <container-id>
   pct console <container-id>
   ```

2. **Service not responding**
   ```bash
   pct exec <container-id> -- systemctl status <service>
   pct exec <container-id> -- journalctl -u <service>
   ```

3. **Network connectivity issues**
   ```bash
   pct exec <container-id> -- ip addr show
   pct exec <container-id> -- ping 8.8.8.8
   ```

### Log Locations

- **System**: `journalctl`
- **Nginx**: `/var/log/nginx/`
- **CrowdSec**: `/var/log/crowdsec/`
- **Firewall**: `journalctl -u firewalld`

## Backup and Recovery

### Automated Backups

Daily backups are automatically configured:

- **Schedule**: Daily via systemd timer
- **Location**: `/opt/ansible-server/backups/`
- **Contents**: All configurations and keys

### Manual Backup

```bash
# Run backup script
/opt/ansible-server/scripts/backup-config.sh

# Container-level backup
vzdump <container-id> --mode stop --compress gzip
```

## Development Workflow

### 🔧 **Setting Up Development Environment**

```bash
# Clone the repository
git clone https://github.com/tonysauce/ansible-lxc-deploy.git
cd ansible-lxc-deploy

# Install dependencies (sets up Husky Git hooks)
npm install

# Validate your setup
npm run validate
```

### 🎣 **Git Hooks (Husky)**

This repository uses automated Git hooks for code quality and security:

- **Pre-commit**: Scans for secrets, validates shell scripts, checks permissions
- **Commit-msg**: Validates commit message format and quality
- **Pre-push**: Final security validation and infrastructure checks

```bash
# Run security checks manually
npm run security-check

# Test all scripts
npm run test

# Lint shell scripts (requires shellcheck)
npm run lint
```

**See [HUSKY-HOOKS.md](HUSKY-HOOKS.md) for detailed documentation.**

### 📝 **Commit Message Format**

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Examples:**
- `feat(security): add Zero Trust architecture`
- `fix(ansible): resolve container timeout issue`
- `docs(readme): update installation guide`

## Contributing

Contributions are welcome! Please follow the development workflow above and ensure all Git hooks pass before submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Open an issue in this repository
- Check ProxMox and Rocky Linux documentation
- Review CrowdSec community resources

---

**Infrastructure as Code** - Automating enterprise infrastructure deployment with security best practices.