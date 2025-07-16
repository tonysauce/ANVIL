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
- Run security validation after modifications