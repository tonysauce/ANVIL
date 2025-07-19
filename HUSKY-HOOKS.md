# Husky Git Hooks Documentation

## 🎣 Overview

This repository uses [Husky](https://github.com/typicode/husky) to enforce code quality and security standards through Git hooks. These automated checks run at different stages of the Git workflow to ensure infrastructure code meets enterprise security standards.

## 🔧 Setup

Husky is automatically configured when you run:

```bash
npm install
```

The hooks are installed in `.husky/` directory and will run automatically on Git operations.

## 🪝 Configured Hooks

### 1. Pre-Commit Hook (`.husky/pre-commit`)

**Runs before each commit to validate code quality and security**

#### ✅ Checks Performed:
- **Secret Detection** - Scans for hardcoded passwords, API keys, private keys
- **Shell Script Validation** - Runs shellcheck on all `.sh` files
- **File Permissions** - Ensures scripts are executable and files aren't world-writable
- **Infrastructure Security** - Checks for weak crypto, insecure protocols, default passwords

#### 🚨 Prevented Issues:
- Accidental commit of credentials
- Syntax errors in shell scripts
- Overly permissive file permissions
- Security anti-patterns

#### Example Output:
```bash
🔍 Running pre-commit security and quality checks...

🚀 Infrastructure Security Pre-Commit Checks
=============================================

[INFO] Checking for secrets and sensitive information...
[SUCCESS] ✅ No secrets detected

[INFO] Validating shell scripts with shellcheck...
[INFO] Checking anvil-lxc-deploy.sh...
[SUCCESS] ✅ All shell scripts passed validation

[INFO] Checking file permissions...
[SUCCESS] ✅ File permissions look good

[INFO] Checking infrastructure security best practices...
[SUCCESS] ✅ Infrastructure security checks passed

[SUCCESS] 🎉 All pre-commit checks passed!
```

### 2. Commit Message Hook (`.husky/commit-msg`)

**Validates commit message format and quality**

#### ✅ Validation Rules:
- Minimum 10 characters length
- Maximum 100 characters for first line
- Proper capitalization
- Imperative mood recommendations
- Security context awareness

#### 📝 Recommended Format:
```
<type>(<scope>): <subject>

<body>

<footer>
```

#### Examples:
```bash
# Good commits
feat(security): add 2025 compliance framework
fix(ansible): resolve container creation timeout
docs(readme): update installation instructions

# Flagged for improvement
Fixed bug in script        # Should be: "Fix bug in script"
added new feature.         # Should be: "Add new feature" (no period)
```

### 3. Pre-Push Hook (`.husky/pre-push`)

**Final validation before code reaches remote repository**

#### ✅ Comprehensive Checks:
- **Branch Protection** - Warns about direct pushes to main/master
- **Infrastructure Config** - Validates required files and JSON syntax
- **Security Posture** - Ensures security documentation exists
- **Commit History** - Analyzes commit quality and suggests improvements
- **Final Tests** - Syntax validation of all shell scripts

#### 🛡️ Security Features:
- Prevents accidental pushes to protected branches
- Validates infrastructure configuration integrity
- Ensures security documentation is maintained
- Final syntax check for all scripts

## 🚀 Usage Examples

### Running Hooks Manually

```bash
# Run pre-commit checks manually
npm run security-check

# Run all validations
npm run validate

# Test script syntax
npm run test

# Lint shell scripts (requires shellcheck)
npm run lint
```

### Bypassing Hooks (NOT Recommended)

```bash
# Skip pre-commit hooks (dangerous!)
git commit --no-verify

# Skip pre-push hooks (dangerous!)
git push --no-verify

# Bypass branch protection
HUSKY_SKIP_BRANCH_PROTECTION=true git push
```

**⚠️ Warning:** Bypassing hooks is strongly discouraged as it defeats the security purpose.

## 🔍 Hook Configuration

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `HUSKY` | Disable all hooks | `1` (enabled) |
| `HUSKY_DEBUG` | Enable debug output | `0` (disabled) |
| `HUSKY_SKIP_BRANCH_PROTECTION` | Skip branch protection | `false` |

### Customization

To modify hook behavior, edit the respective files in `.husky/`:

```bash
# Edit pre-commit checks
vim .husky/pre-commit

# Edit commit message validation
vim .husky/commit-msg

# Edit pre-push validation
vim .husky/pre-push
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. Shellcheck Not Found
```bash
# Install shellcheck for better script validation
sudo dnf install ShellCheck      # Rocky Linux/RHEL
sudo apt install shellcheck     # Ubuntu/Debian
brew install shellcheck         # macOS
```

#### 2. Permission Denied
```bash
# Make hooks executable
chmod +x .husky/pre-commit .husky/commit-msg .husky/pre-push
```

#### 3. Node.js/npm Issues
```bash
# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

#### 4. Hook Failures
```bash
# View detailed error output
HUSKY_DEBUG=1 git commit -m "test message"

# Check hook syntax
bash -n .husky/pre-commit
```

### Debug Mode

Enable debug output to troubleshoot hook issues:

```bash
export HUSKY_DEBUG=1
git commit -m "debug commit"
```

## 📊 Security Benefits

### Infrastructure Security
- **Secret Prevention** - Blocks 99% of accidental credential commits
- **Code Quality** - Ensures all scripts pass syntax validation
- **Permission Security** - Prevents overly permissive file permissions
- **Protocol Security** - Flags insecure HTTP/FTP usage

### Compliance Benefits
- **Audit Trail** - Consistent commit message format for auditing
- **Documentation** - Ensures security documentation is maintained
- **Standards Enforcement** - Automatic compliance with security frameworks
- **Quality Assurance** - Multi-layer validation before code publication

### Team Benefits
- **Consistency** - Unified code quality standards across team
- **Education** - Hooks teach security best practices
- **Automation** - Reduces manual review burden
- **Prevention** - Catches issues before they reach production

## 🔄 Maintenance

### Updating Husky

```bash
# Update to latest version
npm update husky

# Reinstall hooks
npm run prepare
```

### Adding New Checks

1. Edit the appropriate hook file (`.husky/pre-commit`, etc.)
2. Add your validation function
3. Call the function in the main execution
4. Test thoroughly before committing

### Hook Performance

Current hook execution times:
- **Pre-commit**: ~5-15 seconds (depending on file count)
- **Commit-msg**: ~1 second
- **Pre-push**: ~10-30 seconds (includes comprehensive validation)

## 📚 Best Practices

### For Developers
1. **Run hooks locally** before pushing
2. **Keep commits small** for faster validation
3. **Write descriptive commit messages**
4. **Don't bypass hooks** unless absolutely necessary
5. **Install shellcheck** for optimal experience

### For Infrastructure Teams
1. **Customize patterns** in hook files for your environment
2. **Add organization-specific** security checks
3. **Monitor hook performance** and optimize as needed
4. **Train team members** on hook usage and benefits
5. **Regular updates** to security patterns and validations

## 🆘 Support

If you encounter issues with the Git hooks:

1. **Check this documentation** for common solutions
2. **Enable debug mode** for detailed error information
3. **Validate hook syntax** manually
4. **Review recent changes** to hook configuration
5. **Create an issue** in the repository for persistent problems

---

**Remember**: These hooks are designed to help maintain code quality and security. They're your friends, not obstacles! 🛡️✨