# Usage Examples

Practical examples for using the Bug Bounty Recon Pipeline.

## Basic Usage

### Single Domain Scan
```bash
./recon.sh target.com
```

### Verbose Mode
```bash
./recon.sh target.com --verbose
```

## Multiple Targets

### Create Target File
```bash
# targets.txt
example.com
test.com
demo.com
```

### Scan Multiple Targets
```bash
./recon.sh targets.txt
```

## Resume Interrupted Scan

If a scan is interrupted, resume it:
```bash
./recon.sh
# Select the incomplete scan directory when prompted
```

## Advanced Configurations

### Custom Wordlist
```bash
wordlist="/path/to/custom/wordlist.txt"
```

### Custom Resolvers
```bash
resolvers="/path/to/custom/resolvers.txt"
```

### Adjust Concurrency
```bash
MAX_CONCURRENT_JOBS=10  # Increase parallel jobs
HTTPX_THREADS=200       # Increase HTTP probe threads
```

### Sample Workflow

#### 1. Subdomain Discovery
```bash
# Output: subdomains/all_subdomains.txt
api.example.com
admin.example.com
dev.example.com
staging.example.com
```

#### 2. Live Domains
```bash
# Output: subdomains/live_subdomains.txt
api.example.com (200)
admin.example.com (403)
```

#### 3. Port Scan Results
```bash
# Output: ports/open_ports.txt
api.example.com:80
api.example.com:443
admin.example.com:22
admin.example.com:443
```

#### 4. Vulnerabilities
```bash
# Output: vulnerabilities/nuclei_results.txt
[CVE-2021-12345] XSS on api.example.com
[CVE-2022-67890] SQL Injection on admin.example.com
```

## Use Cases

### Bug Bounty Hunting
```bash
# Full comprehensive scan
./recon.sh bugcrowd-target.com --verbose

# Review findings in output directory
cd recon*/bugcrowd-target.com/vulnerabilities/
```

### Penetration Testing
```bash
# Target list for engagement
cat > targets.txt << EOF
client-app.com
client-api.com
client-admin.com
EOF

./recon.sh targets.txt
```

### Security Assessment
```bash
# Quick assessment of web application
./recon.sh webapp.internal.company.com

# Focus on vulnerabilities directory
cat recon_*/webapp.internal.company.com/vulnerabilities/*
```

#### Custom Post-Processing
```bash
# Extract high-severity findings
grep -i "critical\|high" recon*/target.com/vulnerabilities/nuclei_results.txt
```

## Troubleshooting Common Scenarios

### Low Subdomain Count
```bash
# Use custom wordlist with more entries
wget https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/subdomains-top1million-110000.txt
```

### Slow Scanning
```bash
# Increase concurrency (requires more resources)
# Edit recon.sh:
MAX_CONCURRENT_JOBS=15
NAABU_RATE=5000
```

### Missing Tools
```bash
# Reinstall specific tool
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## Tips and Best Practices

1. **Always use verbose mode** for debugging: `--verbose`
2. **Start with small targets** to test configuration
3. **Monitor system resources** during scans
4. **Regularly update** Nuclei templates
5. **Review logs** in `recon.log` for errors
6. **Backup results** regularly
7. **Use Tor** for sensitive engagements
8. **Document findings** immediately

## Performance Tips

### For Large Scopes
```bash
# Reduce timeout values
TIMEOUT_SECONDS=1800
NMAP_TIMEOUT=3600
```

### For Fast Networks
```bash
# Increase rate limits
NAABU_RATE=5000
HTTPX_THREADS=200
NUCLEI_RATE_LIMIT=300
```

### For Limited Resources
```bash
# Decrease concurrency
MAX_CONCURRENT_JOBS=3
HTTPX_THREADS=50
```

## Real-World Examples

### Example 1: E-commerce Platform
```bash
./recon.sh shop.example.com --verbose

# Findings:
# - 247 subdomains discovered
# - 89 live domains
# - 234 open ports
# - 12 vulnerabilities (3 critical)
```

### Example 2: Corporate Infrastructure
```bash
# Create target list
cat > corp-targets.txt << EOF
corp.example.com
intranet.example.com
vpn.example.com
EOF

./recon.sh corp-targets.txt

# Comprehensive scan across 3 domains
# Total time: ~4 hours
```

---

For more examples and updates, visit the [GitHub repository](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline).
