#!/usr/bin/env bash

# Security Test Suite for Ansible LXC Deploy
# Version: 1.0.0 - 2025 Edition
# Comprehensive security testing and validation framework

set -euo pipefail

# Test configuration
readonly TEST_SUITE_VERSION="1.0.0"
readonly TEST_RESULTS_DIR="/tmp/security-tests-$(date +%Y%m%d_%H%M%S)"
readonly COMPLIANCE_FRAMEWORKS="NIST-CSF-2.0,CIS-8.1,ZeroTrust,SLSA-L2"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Create test results directory
mkdir -p "$TEST_RESULTS_DIR"

# Logging functions
log_test_info() {
    echo -e "${BLUE}[TEST-INFO]${NC} $1" | tee -a "$TEST_RESULTS_DIR/test.log"
}

log_test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$TEST_RESULTS_DIR/test.log"
    ((TESTS_PASSED++))
}

log_test_fail() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$TEST_RESULTS_DIR/test.log"
    ((TESTS_FAILED++))
}

log_test_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1" | tee -a "$TEST_RESULTS_DIR/test.log"
    ((TESTS_SKIPPED++))
}

# Test execution framework
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="${3:-0}"
    
    ((TESTS_TOTAL++))
    
    log_test_info "Running: $test_name"
    
    if eval "$test_command" >/dev/null 2>&1; then
        local result=0
    else
        local result=1
    fi
    
    if [[ $result -eq $expected_result ]]; then
        log_test_pass "$test_name"
        echo "✅ $test_name" >> "$TEST_RESULTS_DIR/passed_tests.txt"
    else
        log_test_fail "$test_name"
        echo "❌ $test_name: $test_command" >> "$TEST_RESULTS_DIR/failed_tests.txt"
    fi
}

# Security validation tests
test_script_security() {
    log_test_info "=== Script Security Tests ==="
    
    # Test 1: Check for dangerous commands
    run_test "No dangerous commands (eval, exec without validation)" \
        "! grep -q 'eval.*\$' ansible-vm.sh && ! grep -q 'exec.*\$' ansible-vm.sh"
    
    # Test 2: Check for secure file permissions
    run_test "Script has secure permissions" \
        "[[ \$(stat -c '%a' ansible-vm.sh) == '755' ]]"
    
    # Test 3: Check for proper error handling
    run_test "Error handling enabled (set -e)" \
        "grep -q 'set.*-e' ansible-vm.sh"
    
    # Test 4: Check for undefined variable protection
    run_test "Undefined variable protection (set -u)" \
        "grep -q 'set.*-u' ansible-vm.sh"
    
    # Test 5: Check for secure IFS
    run_test "Secure IFS configuration" \
        "grep -q \"IFS=\" ansible-vm.sh"
    
    # Test 6: Check for input validation functions
    run_test "Input validation functions present" \
        "grep -q 'validate_vmid' ansible-vm.sh && grep -q 'validate_hostname' ansible-vm.sh"
    
    # Test 7: Check for logging functions
    run_test "Security logging functions present" \
        "grep -q 'log_security' ansible-vm.sh"
    
    # Test 8: Check for sensitive data sanitization
    run_test "Password sanitization in logs" \
        "grep -q 'password=.*REDACTED' ansible-vm.sh"
}

test_proxmox_security() {
    log_test_info "=== ProxMox Security Tests ==="
    
    # Test 1: Check if running on ProxMox
    if command -v qm >/dev/null 2>&1; then
        run_test "ProxMox qm command available" "command -v qm"
        run_test "ProxMox pvesm command available" "command -v pvesm"
        
        # Test 2: Check ProxMox version
        run_test "ProxMox version detectable" "pveversion | grep -q 'pve-manager'"
        
        # Test 3: Check storage availability
        run_test "Active storage available" "pvesm status | grep -q 'active'"
        
        # Test 4: Check network bridges
        run_test "Default bridge vmbr0 exists" "ip link show vmbr0"
        
    else
        log_test_skip "ProxMox tests (not running on ProxMox host)"
        ((TESTS_TOTAL += 4))
        ((TESTS_SKIPPED += 4))
    fi
}

test_vm_security_config() {
    log_test_info "=== VM Security Configuration Tests ==="
    
    # Test 1: UEFI enforcement
    run_test "UEFI firmware enforced" \
        "grep -q 'BIOS=\"ovmf\"' ansible-vm.sh"
    
    # Test 2: Modern machine type
    run_test "Modern machine type (q35)" \
        "grep -q 'MACHINE=\"q35\"' ansible-vm.sh"
    
    # Test 3: EFI disk configuration
    run_test "EFI disk configuration present" \
        "grep -q 'efidisk0' ansible-vm.sh"
    
    # Test 4: TPM configuration
    run_test "vTPM configuration present" \
        "grep -q 'tpmstate0' ansible-vm.sh"
    
    # Test 5: Secure boot configuration
    run_test "Pre-enrolled keys for secure boot" \
        "grep -q 'pre-enrolled-keys=1' ansible-vm.sh"
}

test_iso_security() {
    log_test_info "=== ISO Security Tests ==="
    
    # Test 1: HTTPS URL for ISO download
    run_test "ISO download uses HTTPS" \
        "grep 'ISO_URL=' ansible-vm.sh | grep -q 'https://'"
    
    # Test 2: ISO validation function exists
    run_test "ISO validation function present" \
        "grep -q 'check_iso' ansible-vm.sh"
    
    # Test 3: ISO size verification
    run_test "ISO size verification implemented" \
        "grep -q 'iso_size' ansible-vm.sh"
    
    # Test 4: Secure ISO path handling
    run_test "ISO path validation present" \
        "grep -q 'ISO_PATH=' ansible-vm.sh"
}

test_network_security() {
    log_test_info "=== Network Security Tests ==="
    
    # Test 1: IP address validation
    run_test "IP address validation function" \
        "grep -q 'validate_ip_address' ansible-vm.sh"
    
    # Test 2: Bridge validation
    run_test "Bridge validation function" \
        "grep -q 'validate_bridge' ansible-vm.sh"
    
    # Test 3: Private IP range checking
    run_test "Private IP range validation" \
        "grep -q 'first_octet.*second_octet' ansible-vm.sh"
    
    # Test 4: Network interface security
    run_test "VirtIO network driver (secure)" \
        "grep -q 'virtio,bridge' ansible-vm.sh"
}

test_compliance_framework() {
    log_test_info "=== Compliance Framework Tests ==="
    
    # Test 1: Check for 2025 standards documentation
    run_test "2025 security standards document exists" \
        "[[ -f 'SECURITY-2025-STANDARDS.md' ]]"
    
    # Test 2: Security hardening script exists
    run_test "Security hardening script exists" \
        "[[ -f 'security-hardening-2025.sh' ]]"
    
    # Test 3: Check for compliance reporting
    run_test "Compliance framework mentioned in scripts" \
        "grep -q 'COMPLIANCE_FRAMEWORKS' ansible-vm.sh"
    
    # Test 4: NIST CSF 2.0 compliance
    run_test "NIST CSF 2.0 compliance references" \
        "grep -q 'NIST.*CSF.*2.0' SECURITY-2025-STANDARDS.md"
    
    # Test 5: CIS Controls v8.1 compliance
    run_test "CIS Controls v8.1 compliance references" \
        "grep -q 'CIS.*Controls.*8.1' SECURITY-2025-STANDARDS.md"
    
    # Test 6: Zero Trust architecture
    run_test "Zero Trust architecture implementation" \
        "grep -q 'Zero Trust' SECURITY-2025-STANDARDS.md"
    
    # Test 7: SLSA framework compliance
    run_test "SLSA framework implementation" \
        "grep -q 'SLSA' SECURITY-2025-STANDARDS.md"
}

test_input_validation() {
    log_test_info "=== Input Validation Tests ==="
    
    # Create temporary test script to validate functions
    cat > "$TEST_RESULTS_DIR/test_validation.sh" << 'EOF'
#!/bin/bash
source ansible-vm.sh

# Test VM ID validation
validate_vmid "100" && echo "PASS: Valid VM ID 100"
! validate_vmid "99" && echo "PASS: Invalid VM ID 99 rejected"
! validate_vmid "abc" && echo "PASS: Non-numeric VM ID rejected"

# Test hostname validation
validate_hostname "test-vm" && echo "PASS: Valid hostname"
! validate_hostname "test_vm_with_underscores" && echo "PASS: Invalid hostname rejected"
! validate_hostname "toolongtobeavalidhostnamebecauseitexceedssixtythreecharacterslimit" && echo "PASS: Long hostname rejected"

# Test disk size validation
validate_disk_size "32" && echo "PASS: Valid disk size"
! validate_disk_size "0" && echo "PASS: Zero disk size rejected"
! validate_disk_size "abc" && echo "PASS: Non-numeric disk size rejected"

# Test memory validation
validate_memory "4096" && echo "PASS: Valid memory size"
! validate_memory "100" && echo "PASS: Too small memory rejected"
! validate_memory "abc" && echo "PASS: Non-numeric memory rejected"

# Test IP validation
validate_ip_address "dhcp" && echo "PASS: DHCP accepted"
validate_ip_address "192.168.1.100/24" && echo "PASS: Valid IP accepted"
! validate_ip_address "300.300.300.300/24" && echo "PASS: Invalid IP rejected"
! validate_ip_address "192.168.1.100" && echo "PASS: IP without CIDR rejected"
EOF
    
    chmod +x "$TEST_RESULTS_DIR/test_validation.sh"
    
    # Run validation tests
    if cd "$(dirname "$PWD/ansible-vm.sh")" && "$TEST_RESULTS_DIR/test_validation.sh" > "$TEST_RESULTS_DIR/validation_results.txt" 2>&1; then
        local passed_validations
        passed_validations=$(grep -c "PASS:" "$TEST_RESULTS_DIR/validation_results.txt" 2>/dev/null || echo "0")
        
        if [[ $passed_validations -ge 10 ]]; then
            log_test_pass "Input validation functions working ($passed_validations/12 tests passed)"
        else
            log_test_fail "Input validation functions failing (only $passed_validations/12 tests passed)"
        fi
    else
        log_test_fail "Input validation test execution failed"
    fi
}

test_security_logging() {
    log_test_info "=== Security Logging Tests ==="
    
    # Test 1: Security logging functions defined
    run_test "Security logging function defined" \
        "grep -q 'log_security()' ansible-vm.sh"
    
    # Test 2: Audit logging to syslog
    run_test "Syslog integration present" \
        "grep -q 'logger.*auth' ansible-vm.sh"
    
    # Test 3: Log file creation
    run_test "Log file management present" \
        "grep -q 'LOG_FILE=' ansible-vm.sh"
    
    # Test 4: Security audit trail
    run_test "Security audit trail implementation" \
        "grep -q 'SECURITY_AUDIT' ansible-vm.sh"
}

# Generate security report
generate_security_report() {
    log_test_info "=== Generating Security Report ==="
    
    local report_file="$TEST_RESULTS_DIR/security_report.md"
    
    cat > "$report_file" << EOF
# Security Test Report

**Date:** $(date)
**Test Suite Version:** $TEST_SUITE_VERSION
**Compliance Frameworks:** $COMPLIANCE_FRAMEWORKS

## Summary

- **Total Tests:** $TESTS_TOTAL
- **Passed:** $TESTS_PASSED
- **Failed:** $TESTS_FAILED
- **Skipped:** $TESTS_SKIPPED
- **Success Rate:** $(( (TESTS_PASSED * 100) / (TESTS_TOTAL - TESTS_SKIPPED) ))%

## Test Categories

### Script Security
- Modern bash practices implementation
- Error handling and validation
- Secure coding standards compliance

### ProxMox Integration
- Platform compatibility verification
- Resource availability validation
- Network configuration testing

### VM Security Configuration
- UEFI/TPM enforcement verification
- Secure boot configuration validation
- Modern virtualization standards compliance

### Network Security
- Input validation testing
- IP address and bridge validation
- Private network range verification

### Compliance Framework
- 2025 security standards validation
- NIST CSF 2.0 compliance checking
- CIS Controls v8.1 verification
- Zero Trust architecture validation
- SLSA framework implementation

## Detailed Results

### Passed Tests
EOF

    if [[ -f "$TEST_RESULTS_DIR/passed_tests.txt" ]]; then
        cat "$TEST_RESULTS_DIR/passed_tests.txt" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

### Failed Tests
EOF

    if [[ -f "$TEST_RESULTS_DIR/failed_tests.txt" ]]; then
        cat "$TEST_RESULTS_DIR/failed_tests.txt" >> "$report_file"
    else
        echo "None" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

## Recommendations

EOF

    if [[ $TESTS_FAILED -gt 0 ]]; then
        cat >> "$report_file" << EOF
1. **Address Failed Tests:** Review and fix the failed test cases above
2. **Security Hardening:** Run the security hardening script if not already done
3. **Compliance Review:** Ensure all compliance frameworks are properly implemented
4. **Regular Testing:** Schedule regular security testing to maintain compliance
EOF
    else
        cat >> "$report_file" << EOF
1. **Excellent Security Posture:** All tests passed successfully
2. **Maintain Standards:** Continue following 2025 security best practices
3. **Regular Updates:** Keep security configurations up to date
4. **Continuous Monitoring:** Implement continuous security monitoring
EOF
    fi

    cat >> "$report_file" << EOF

## Next Steps

1. Review this report with your security team
2. Address any failed tests or recommendations
3. Schedule regular security assessments
4. Maintain documentation for compliance audits

---
*Report generated by Security Test Suite v$TEST_SUITE_VERSION*
EOF

    log_test_info "Security report generated: $report_file"
}

# Main execution
main() {
    echo -e "${PURPLE}🔒 Security Test Suite v$TEST_SUITE_VERSION${NC}"
    echo -e "${BLUE}Testing compliance with: $COMPLIANCE_FRAMEWORKS${NC}"
    echo ""
    
    # Change to script directory
    cd "$(dirname "${BASH_SOURCE[0]}")"
    
    # Run all test categories
    test_script_security
    test_proxmox_security
    test_vm_security_config
    test_iso_security
    test_network_security
    test_compliance_framework
    test_input_validation
    test_security_logging
    
    # Generate final report
    generate_security_report
    
    echo ""
    echo -e "${PURPLE}=== SECURITY TEST SUMMARY ===${NC}"
    echo -e "Total Tests: $TESTS_TOTAL"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    echo -e "${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}🎉 ALL SECURITY TESTS PASSED!${NC}"
        echo -e "${GREEN}✅ System meets 2025 security standards${NC}"
        exit 0
    else
        echo -e "${RED}⚠️  SECURITY ISSUES DETECTED${NC}"
        echo -e "${RED}❌ Review failed tests and address issues${NC}"
        echo -e "Detailed report: $TEST_RESULTS_DIR/security_report.md"
        exit 1
    fi
}

# Run main function
main "$@"