# 🧪 Testing Checklist for ANVIL Infrastructure Lab

## Pre-Deployment Validation

### Prerequisites ✅
- [ ] ProxMox VE 8.0+ host available
- [ ] Sufficient resources: 
  - **LXC**: 2GB RAM, 20GB disk minimum
  - **VM**: 4GB RAM, 32GB disk minimum (recommended for management platform)
- [ ] Network connectivity for package downloads
- [ ] SSH access to ProxMox host
- [ ] Container/VM ID not already in use (LXC: 200, VM: 300)
- [ ] Storage available for VM disk images (if using VM deployment)

### Repository Setup ✅
- [ ] Repository cloned: `git clone https://github.com/tonysauce/ANVIL.git`
- [ ] All files present (check with `ls -la`)
- [ ] Scripts have execute permissions (`chmod +x *.sh`)
- [ ] Husky hooks installed (`npm install` if doing development)

## 🚀 Deployment Testing

### Phase 1: Choose Deployment Type

#### Option A: LXC Container (Lightweight)
```bash
# Test the LXC one-liner installer
bash -c "$(wget -qLO - https://raw.githubusercontent.com/tonysauce/ANVIL/main/anvil-lxc-deploy.sh)"
```

**LXC Validation Points:**
- [ ] Script downloads successfully
- [ ] Interactive dialog appears
- [ ] Container creation completes without errors
- [ ] Container starts successfully: `pct status <container-id>`
- [ ] Container responds: `pct exec <container-id> -- echo "Hello World"`

#### Option B: Virtual Machine (Recommended for Management Platform)
```bash
# Test the VM one-liner installer
bash -c "$(wget -qLO - https://raw.githubusercontent.com/tonysauce/ANVIL/main/anvil-vm-deploy.sh)"
```

**VM Validation Points:**
- [ ] Script downloads successfully
- [ ] Rocky Linux 9 ISO downloads (may take several minutes)
- [ ] VM creation completes without errors
- [ ] VM starts successfully: `qm status <vm-id>`
- [ ] Can connect to VM console: `qm terminal <vm-id>`
- [ ] OS installation completes (automated via kickstart)
- [ ] Post-installation script runs automatically
- [ ] SSH access works: `ssh root@<vm-ip>` or `ssh ansible@<vm-ip>`

### Phase 2: Network Connectivity
```bash
# Check network configuration
pct exec <container-id> -- ip addr show
pct exec <container-id> -- ping -c 3 8.8.8.8
pct exec <container-id> -- curl -s http://example.com
```

**Validation Points:**
- [ ] Container has IP address assigned
- [ ] Can reach external internet
- [ ] DNS resolution working
- [ ] SSH access works: `ssh root@<container-ip>`

### Phase 3: Service Validation

#### Ansible Service ✅
```bash
pct exec <container-id> -- ansible --version
pct exec <container-id> -- ansible-galaxy collection list
pct exec <container-id> -- su - ansible -c "ssh-keygen -l -f ~/.ssh/id_ed25519.pub"
```

**Validation Points:**
- [ ] Ansible installed and working
- [ ] Collections installed (community.general, ansible.posix)
- [ ] Ansible user exists with SSH key
- [ ] Ansible can run: `ansible localhost -m ping`

#### Nginx Web Server ✅
```bash
# Test nginx service
pct exec <container-id> -- systemctl status nginx
curl http://<container-ip>
curl http://<container-ip>/kickstart/
curl http://<container-ip>/ignition/
```

**Validation Points:**
- [ ] Nginx running and enabled
- [ ] Web interface accessible
- [ ] Kickstart directory browsable
- [ ] Ignition directory browsable
- [ ] SSL/TLS working (if configured)

#### Tang Server (NBDE) ✅
```bash
# Test Tang service
pct exec <container-id> -- systemctl status tangd@7500
curl http://<container-ip>:7500/adv
```

**Validation Points:**
- [ ] Tang service running on port 7500
- [ ] Tang advertisement endpoint responds
- [ ] Keys generated in `/var/db/tang/`
- [ ] Firewall allows Tang port: `pct exec <container-id> -- firewall-cmd --list-ports`

#### CrowdSec Security ✅
```bash
# Test CrowdSec
pct exec <container-id> -- systemctl status crowdsec
pct exec <container-id> -- crowdsec-cli metrics
pct exec <container-id> -- crowdsec-cli collections list
```

**Validation Points:**
- [ ] CrowdSec service running
- [ ] Metrics showing activity
- [ ] Collections installed and updated
- [ ] No critical alerts: `crowdsec-cli alerts list`

#### Firewall (firewalld) ✅
```bash
# Test firewall configuration
pct exec <container-id> -- systemctl status firewalld
pct exec <container-id> -- firewall-cmd --list-all
pct exec <container-id> -- firewall-cmd --get-active-zones
```

**Validation Points:**
- [ ] Firewalld running and enabled
- [ ] Required ports open (22, 80, 443, 7500)
- [ ] Correct zone configuration
- [ ] Services properly configured

## 🔒 Security Testing

### Phase 4: Security Hardening Validation
```bash
# Run security validation scripts
pct exec <container-id> -- /opt/ansible-server/scripts/security-validation.sh
pct exec <container-id> -- /opt/ansible-server/scripts/compliance-check.sh
```

**Security Validation Points:**
- [ ] SELinux in enforcing mode: `getenforce`
- [ ] SSH hardened (no root login, key-based auth)
- [ ] Auditd logging enabled: `systemctl status auditd`
- [ ] AIDE file integrity monitoring configured
- [ ] Fail2ban alternative (CrowdSec) working
- [ ] System accounts properly configured
- [ ] File permissions secure (no world-writable files)

### Phase 5: 2025 Compliance Testing
```bash
# Check 2025 security standards
pct exec <container-id> -- /opt/ansible-server/scripts/nist-csf-check.sh
pct exec <container-id> -- /opt/ansible-server/scripts/zero-trust-validation.sh
pct exec <container-id> -- /opt/ansible-server/scripts/slsa-compliance.sh
```

**2025 Standards Validation:**
- [ ] NIST CSF 2.0 controls implemented
- [ ] Zero Trust architecture elements present
- [ ] SLSA supply chain security measures
- [ ] AI-enhanced security monitoring active
- [ ] Automated compliance reporting working

## 🎯 Functional Testing

### Phase 6: End-to-End Workflows

#### Kickstart File Hosting ✅
```bash
# Create test kickstart file
pct exec <container-id> -- tee /var/www/kickstart/kickstart/test.ks << 'EOF'
#version=RHEL9
text
keyboard --vckeymap=us --xlayouts='us'
lang en_US.UTF-8
network --bootproto=dhcp --device=ens192 --onboot=on
rootpw --plaintext testpassword
timezone America/New_York --isUtc
EOF

# Test access
curl http://<container-ip>/kickstart/test.ks
```

**Validation Points:**
- [ ] File uploads successfully
- [ ] File accessible via HTTP
- [ ] Proper MIME type served
- [ ] Directory listing works

#### Tang NBDE Integration ✅
```bash
# Test Tang key operations
pct exec <container-id> -- /opt/ansible-server/scripts/rotate-tang-keys.sh
pct exec <container-id> -- jose jwk thp -i /var/db/tang/*.jwk
```

**Validation Points:**
- [ ] Tang keys rotate successfully
- [ ] Thumbprint generation works
- [ ] NBDE clients can connect (if available)
- [ ] Key backup/restore functions

#### Ansible Operations ✅
```bash
# Test Ansible functionality
pct exec <container-id> -- su - ansible -c "ansible-playbook --version"
pct exec <container-id> -- su - ansible -c "ansible localhost -m setup"
```

**Validation Points:**
- [ ] Ansible playbooks can run
- [ ] Inventory management works
- [ ] SSH key distribution functional
- [ ] Role and collection usage

## 🔄 Management Testing

### Phase 7: Backup and Recovery
```bash
# Test backup scripts
pct exec <container-id> -- /opt/ansible-server/scripts/backup-config.sh
pct exec <container-id> -- ls -la /opt/ansible-server/backups/
```

**Validation Points:**
- [ ] Backup script runs without errors
- [ ] All configurations backed up
- [ ] Tang keys included in backup
- [ ] Restore procedure documented and tested

### Phase 8: Monitoring and Logs
```bash
# Check logging and monitoring
pct exec <container-id> -- journalctl --since "1 hour ago" --no-pager
pct exec <container-id> -- tail -f /var/log/nginx/access.log
pct exec <container-id> -- crowdsec-cli decisions list
```

**Validation Points:**
- [ ] System logs healthy
- [ ] Service logs accessible
- [ ] Security events logged
- [ ] Monitoring alerts functional

## 🚨 Stress Testing

### Phase 9: Load and Edge Cases
```bash
# Test multiple concurrent connections
for i in {1..10}; do curl http://<container-ip>/ & done

# Test service restarts
pct exec <container-id> -- systemctl restart nginx tang@7500 crowdsec
```

**Validation Points:**
- [ ] Services handle concurrent requests
- [ ] Services restart cleanly
- [ ] No memory leaks or resource issues
- [ ] Performance acceptable under load

### Phase 10: Error Scenarios
```bash
# Test error handling
pct stop <container-id>
pct start <container-id>
# Wait for startup and test all services
```

**Validation Points:**
- [ ] Container stops/starts cleanly
- [ ] All services auto-start after reboot
- [ ] No data loss during restart
- [ ] Error recovery mechanisms work

## 📊 Performance Baseline

### Resource Usage ✅
```bash
# Monitor resource consumption
pct exec <container-id> -- top -b -n 1
pct exec <container-id> -- free -h
pct exec <container-id> -- df -h
```

**Performance Metrics:**
- [ ] Memory usage < 80% of allocated
- [ ] CPU usage reasonable under normal load
- [ ] Disk space sufficient
- [ ] Network performance acceptable

## ✅ Acceptance Criteria

### Minimum Viable Deployment
- [ ] Container creates and starts successfully
- [ ] All four main services running (Ansible, Nginx, Tang, CrowdSec)
- [ ] Network connectivity functional
- [ ] Basic security hardening applied
- [ ] SSH access working

### Production Ready Deployment
- [ ] All security controls implemented and verified
- [ ] 2025 compliance standards met (90%+ score)
- [ ] Backup and monitoring functional
- [ ] Documentation complete and accurate
- [ ] Performance meets requirements
- [ ] All edge cases handled gracefully

## 🐛 Issue Tracking

### Common Issues and Solutions

#### Container Won't Start
```bash
# Debug steps
pct status <container-id>
pct console <container-id>
cat /var/log/pve/lxc/<container-id>.log
```

#### Service Failures
```bash
# Service debugging
pct exec <container-id> -- systemctl status <service>
pct exec <container-id> -- journalctl -u <service> -f
```

#### Network Issues
```bash
# Network debugging
pct exec <container-id> -- ip route show
pct exec <container-id> -- iptables -L
pct exec <container-id> -- firewall-cmd --list-all
```

#### Security Issues
```bash
# Security debugging
pct exec <container-id> -- /opt/ansible-server/scripts/security-validation.sh
pct exec <container-id> -- crowdsec-cli alerts list
```

## 📝 Testing Log Template

```
Date: ___________
Tester: ___________
ProxMox Version: ___________
Container ID: ___________

Phase 1 - Basic Creation: ✅ ❌
Phase 2 - Network: ✅ ❌  
Phase 3 - Services: ✅ ❌
Phase 4 - Security: ✅ ❌
Phase 5 - Compliance: ✅ ❌
Phase 6 - Functional: ✅ ❌
Phase 7 - Backup: ✅ ❌
Phase 8 - Monitoring: ✅ ❌
Phase 9 - Stress: ✅ ❌
Phase 10 - Error Handling: ✅ ❌

Issues Found:
_________________________________
_________________________________

Overall Result: ✅ PASS ❌ FAIL
```

---

**Remember**: This is enterprise infrastructure - take time to test thoroughly! Start with the basic phases and work your way up to production validation. 🚀

Happy testing! 🧪