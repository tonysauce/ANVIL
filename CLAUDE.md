# Claude Code Memory

## Project Overview
Ansible LXC deployment project for automating container and VM deployments with security hardening.

## Recent Work (from git history)
- Improved ISO handling for air-gapped environments
- Updated to Rocky Linux 9.6 (2025 latest release) 
- Added standalone VM deployment script for private repo compatibility
- Implemented VM deployment options for infrastructure platform
- Fixed bash compatibility issues and Git hooks
- Added comprehensive security hardening and 2025 compliance standards

## Key Files
- `ansible-lxc.sh` - Main LXC deployment script
- `ansible-rocky-lxc-deploy.sh` - Rocky Linux specific deployment
- `ansible-vm-standalone.sh` - Standalone VM deployment
- `ansible-vm.sh` - VM deployment script
- `security-hardening-2025.sh` - 2025 security standards
- `vm-post-install.sh` - Post-installation configuration

## Current Session Context
- User mentioned VM boot loop issue with SeaBIOS vs UEFI/vTPM
- Working directory: /home/tony/ansible-lxc-deploy
- Git repo with recent commits on ISO handling and Rocky Linux updates

## VM Boot Loop Issue Resolution
- **Problem**: ansible-vm.sh was using SeaBIOS causing boot loops
- **Solution**: Updated to UEFI firmware with vTPM support
- **Changes Made**:
  - Changed BIOS="seabios" to BIOS="ovmf" in ansible-vm.sh:55
  - Added EFI disk configuration: --efidisk0 $STORAGE:1,efitype=4m,pre-enrolled-keys=1
  - Added vTPM state: --tpmstate0 $STORAGE:1,version=v2.0
  - Updated disk allocation to use proper format
- **Status**: ansible-vm-standalone.sh already had correct UEFI/vTPM configuration

## Next Steps
- Test updated ansible-vm.sh script
- Verify VMs boot properly with UEFI/vTPM
- Continue improving deployment automation
- Maintain security compliance standards

## Commands to Remember
- Check git status before making changes
- Run security validation after modifications\n\n## 2025 Security Standards Implementation\n\n### Security Enhancements Completed\n- **Modern Bash Practices**: Implemented strict error handling, input validation, secure logging\n- **Input Validation**: Comprehensive validation for all VM parameters (VMID, hostname, IP, etc.)\n- **Security Audit Trail**: All operations logged with security context and timestamps\n- **Zero Trust Architecture**: UEFI enforcement, TPM requirements, secure defaults\n- **Network Hardening**: Advanced firewall rules, kernel hardening, intrusion prevention\n- **Automated Testing**: Complete security test suite for validation\n\n### New Security Scripts\n1. **security-test-suite.sh**: Comprehensive security testing framework\n   - Tests script security, ProxMox integration, VM configuration\n   - Validates compliance with NIST CSF 2.0, CIS 8.1, Zero Trust, SLSA\n   - Generates detailed security reports\n\n2. **network-security-hardening.sh**: Advanced network security implementation\n   - Zero Trust firewall zones (management, internal, DMZ, quarantine)\n   - Kernel network hardening parameters\n   - Real-time network monitoring and alerting\n   - Fail2ban intrusion prevention\n   - Secure DNS configuration\n\n### Security Features in ansible-vm.sh\n- **Error Handling**: Comprehensive error trapping with security context\n- **Input Validation**: All user inputs validated and sanitized\n- **Logging**: Security audit trail with syslog integration\n- **Resource Checks**: Pre-deployment validation of system resources\n- **Secure Defaults**: UEFI + vTPM enforced, secure configurations\n- **PID Management**: Prevents concurrent execution\n- **Cleanup**: Secure cleanup of temporary files and sensitive data\n\n### Compliance Frameworks Implemented\n- **NIST CSF 2.0**: Governance function with risk management\n- **CIS Controls v8.1**: Enhanced asset management and configuration\n- **Zero Trust Architecture**: Never trust, always verify principles\n- **SLSA Framework**: Supply chain security level 2 readiness\n\n### Security Testing Commands\n```bash\n# Run comprehensive security tests\n./security-test-suite.sh\n\n# Apply network hardening\n./network-security-hardening.sh\n\n# Run 2025 security hardening\n./security-hardening-2025.sh\n```\n\n### Enhanced Deployment Commands\n```bash\n# Deploy VM with enhanced security\n./ansible-vm.sh\n\n# Deploy standalone VM\n./ansible-vm-standalone.sh\n\n# Check compliance status\n/opt/compliance/compliance-assessment.sh\n```\n\n### Monitoring and Maintenance\n```bash\n# Check security logs\njournalctl -f | grep SECURITY_AUDIT\n\n# Monitor network security\ntail -f /opt/network-monitoring/logs/network-activity.log\n\n# Check firewall status\nfirewall-cmd --list-all-zones\n\n# Review fail2ban status\nfail2ban-client status\n```"