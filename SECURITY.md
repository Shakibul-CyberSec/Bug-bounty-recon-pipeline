# Security Policy

## Supported Versions

Currently supported versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

### Where to Report

**DO NOT** create public GitHub issues for security vulnerabilities.

Instead, please report security vulnerabilities via:

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/security)
   - Click "Report a vulnerability"
   - Fill in the details

2. **Email** (Alternative)
   - Contact: contact@shakibul.com
   - Include "SECURITY" in the subject line
   - Provide detailed information about the vulnerability

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear explanation of the vulnerability
- **Impact**: Potential security impact and severity
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Affected Versions**: Which versions are affected
- **Proof of Concept**: If available (code, screenshots, logs)
- **Suggested Fix**: If you have recommendations

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Every 72 hours until resolved
- **Fix Timeline**: 
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 60 days

### Disclosure Policy

- We follow **coordinated disclosure**
- Vulnerabilities will be disclosed after a fix is available
- Credit will be given to reporters (if desired)
- We request 90 days before public disclosure

## Security Best Practices

### For Users

1. **Always update** to the latest version
2. **Review code** before running on production systems
3. **Use isolated environments** for testing
4. **Limit permissions** to what's necessary
5. **Monitor logs** for suspicious activity
6. **Use Tor mode** for sensitive operations
7. **Don't scan** unauthorized targets

### For Developers

1. **No `eval` or dangerous constructs**
2. **Validate all inputs** from users and files
3. **Quote variables** properly
4. **Use safe temp files** with cleanup
5. **Implement timeouts** for all operations
6. **Handle errors** gracefully
7. **Log security events**
8. **Review dependencies** regularly

## Known Security Considerations

### 1. Privilege Escalation
- Installation requires sudo access
- Scripts should be run with minimum necessary privileges
- Never run reconnaissance as root unless required

### 2. Network Exposure
- Tool generates significant network traffic
- May trigger IDS/IPS systems
- Use rate limiting to avoid detection

### 3. Data Exposure
- Results may contain sensitive information
- Secure output directories appropriately
- Clean up temporary files after scans

### 4. Third-Party Tools
- We integrate 34 external security tools
- Each tool has its own security considerations
- Keep tools updated to latest versions

### 5. API Keys & Credentials
- Never commit API keys to the repository
- Use environment variables for secrets
- Don't log sensitive credentials

## Security Features

### Current Implementation

✅ **Input Validation**
- Domain name validation
- File path sanitization
- Parameter checking

✅ **Safe Execution**
- No use of `eval`
- Proper variable quoting
- Secure temp file handling
- Manual parsing instead of `source` command

✅ **Resource Management**
- Timeout controls (45min general, 90min nmap, 120min nuclei)
- Job concurrency limits (max 5 concurrent)
- Memory threshold monitoring (4GB)

✅ **Error Handling**
- Graceful failure handling
- Cleanup on exit via trap
- Detailed logging (recon.log, errors.log)

✅ **Rate Limiting**
- Exponential backoff
- Configurable delays
- Tool-specific rate limits (naabu: 2000 pkt/s, nuclei: 150 req/s)

✅ **Anonymization**
- Optional Tor integration (SOCKS5 proxy on port 9050)
- Proxy support via proxychains
- Rate limiting to avoid detection

## Compliance

### Responsible Use

This tool is intended for:
- ✅ Authorized penetration testing
- ✅ Bug bounty programs (with permission)
- ✅ Security research (ethical)
- ✅ Educational purposes

This tool is NOT for:
- ❌ Unauthorized scanning
- ❌ Malicious activities
- ❌ Privacy violations
- ❌ Illegal purposes

### Legal Disclaimer

**IMPORTANT**: You are solely responsible for your use of this tool.

- Obtain proper authorization before scanning any target
- Follow all applicable laws and regulations
- Respect terms of service and scope boundaries
- Do not use for unauthorized access or data theft

The authors and contributors are not liable for misuse of this tool.

## Bug Bounty

We currently don't have a formal bug bounty program, but we appreciate security researchers who responsibly disclose vulnerabilities.

### Recognition

Security researchers who help improve this project will be:
- Acknowledged in the CHANGELOG
- Credited in security advisories

### Scope

**In Scope:**
- Security vulnerabilities in recon.sh
- Security issues in install.sh
- Configuration weaknesses
- Dangerous default settings
- Input validation bypasses
- Command injection vulnerabilities
- Path traversal issues

**Out of Scope:**
- Issues in third-party tools
- Social engineering attacks
- Denial of Service (DoS)
- Physical access scenarios
- Known limitations

## Security Updates

### Subscribe to Updates

Stay informed about security updates:

1. **Watch** the repository on GitHub
2. **Enable notifications** for security advisories
3. **Check CHANGELOG.md** regularly

### Update Procedure

When a security update is released:

```bash
# Pull latest changes
cd Bug-bounty-recon-pipeline
git pull origin main

# Review changes
git log -p

# Update tools
sudo ./install.sh
```

## Contact

For security-related inquiries:
- GitHub Security Advisories (Preferred)
- GitHub Issues (Non-sensitive matters)
- Email: contact@shakibul.com

---

**Thank you for helping keep this project secure!** 🔒
