# Usage Guide - Bug Bounty Recon Pipeline

This comprehensive guide covers all aspects of using the Bug Bounty Recon Pipeline effectively.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Usage](#basic-usage)
3. [Advanced Usage](#advanced-usage)
4. [Tool-Specific Guides](#tool-specific-guides)
5. [Workflow Examples](#workflow-examples)
6. [Tips and Tricks](#tips-and-tricks)
7. [FAQ](#faq)

---

## Quick Start

### First-Time Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/recon-pipeline.git
cd recon-pipeline

# Run the installer
chmod +x install.sh
sudo ./install.sh

# Verify installation
./install.sh --check
```

### Your First Scan

```bash
# Basic scan (requires permission!)
./recon.sh -d yourdomain.com

# The script will automatically:
# 1. Enumerate subdomains
# 2. Resolve DNS
# 3. Scan for live hosts
# 4. Scan ports
# 5. Take screenshots
# 6. Discover URLs
# 7. Analyze JavaScript
# 8. Find parameters
# 9. Scan for vulnerabilities
# 10. Find sensitive files
```

---

## Basic Usage

### Command Syntax

```bash
./recon.sh -d DOMAIN [OPTIONS]
```

### Essential Options

#### Domain (Required)

```bash
# Single domain
./recon.sh -d example.com

# Multiple subdomains will be discovered automatically
```

#### Custom Wordlist

```bash
# Use custom subdomain wordlist
./recon.sh -d example.com -w /path/to/wordlist.txt

# Recommended wordlists:
# - /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
# - https://wordlists.assetnote.io/
```

#### Custom Resolvers

```bash
# Use custom DNS resolvers
./recon.sh -d example.com -r /path/to/resolvers.txt

# Get fresh resolvers:
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
./recon.sh -d example.com -r resolvers.txt
```

#### Output Directory

```bash
# Specify custom output location
./recon.sh -d example.com -o /path/to/output

# Default: recon_example.com_TIMESTAMP
```

### Example Commands

```bash
# Minimal scan (default settings)
./recon.sh -d example.com

# Full custom configuration
./recon.sh -d example.com \
  -w ~/wordlists/subdomains-large.txt \
  -r ~/resolvers/fast-resolvers.txt \
  -o ~/recon_results/example

# Scan with default resources
./recon.sh -d example.com
# Uses: /usr/share/default-recon-resources/
```

---

## Advanced Usage

### Resume Feature

The pipeline saves progress automatically. If interrupted, you can resume:

```bash
# Automatic detection and resume
./recon.sh -d example.com

# Force resume
./recon.sh -d example.com --resume

# Start fresh (ignore previous state)
./recon.sh -d example.com --clean-resume
```

**Resume Behavior:**
- Skips completed phases
- Resumes from last checkpoint
- Validates existing data
- Appends to existing results

### Proxy Configuration

#### Using Tor (Recommended for Anonymity)

```bash
# Ensure Tor is running
sudo systemctl start tor
sudo systemctl status tor

# Run scan with proxy (automatic if Tor is detected)
./recon.sh -d example.com

# Disable proxy explicitly
./recon.sh -d example.com --no-proxy
```

#### Custom Proxy Setup

Edit `recon.sh` and modify:
```bash
# Line ~165-180
proxy_url="socks5://your-proxy:port"
proxy_cmd="proxychains -q"
```

### Performance Tuning

#### Adjust Concurrency

Edit `recon.sh` configuration:
```bash
# Line 22-32
MAX_PARALLEL_JOBS=10      # Reduce for low-memory systems
NAABU_RATE=2000           # Packets per second
HTTPX_THREADS=100         # Concurrent HTTP requests
KATANA_CONCURRENCY=50     # Crawler threads
```

#### For Low-Resource Systems

```bash
# Reduce parallelism
MAX_PARALLEL_JOBS=5
HTTPX_THREADS=50
KATANA_CONCURRENCY=25

# Increase timeouts
TIMEOUT_SECONDS=3600
NMAP_TIMEOUT=7200
```

#### For High-Resource Systems

```bash
# Increase parallelism
MAX_PARALLEL_JOBS=20
HTTPX_THREADS=200
KATANA_CONCURRENCY=100
NAABU_RATE=5000
```

### Selective Phase Execution

To run only specific phases, modify the script or comment out phases:

```bash
# Edit recon.sh around line 1800-1900
# Comment out phases you don't want:

# Phase 1: Subdomain Enumeration
# run_phase 1 "subdomain_enumeration"

# Phase 2: DNS Bruteforce
run_phase 2 "dns_bruteforce"

# Phase 3: DNS Resolution
run_phase 3 "dns_resolution"
```

---

## Tool-Specific Guides

### JSScan - JavaScript Secret Scanner

#### Basic Usage

```bash
# Scan directory of JS files
jsscan -d /path/to/js_files

# Scan single file
jsscan -f script.js

# Aggressive mode (more patterns, more false positives)
jsscan -d /path/to/js_files --aggressive
```

#### Output Formats

```bash
# Console output (default)
jsscan -d ./js_files

# JSON output
jsscan -d ./js_files -o results.json

# Both console and JSON
jsscan -d ./js_files -o results.json --verbose
```

#### Understanding Results

```
[HIGH] AWS Access Key: AKIAIOSFODNN7EXAMPLE
  File: main.js:45
  Context: const key = "AKIAIOSFODNN7EXAMPLE"
  
[MEDIUM] API Endpoint with Token: https://api.example.com?token=abc123
  File: api.js:120
  Context: fetch('https://api.example.com?token=abc123')
```

**Confidence Levels:**
- **HIGH**: Very likely to be real (specific patterns)
- **MEDIUM**: Needs manual verification
- **LOW**: Aggressive mode only, high false positive rate

#### Common Secrets Detected

- AWS Keys (Access Key ID, Secret Key)
- Google API Keys
- Stripe Keys (Secret, Publishable)
- GitHub Tokens
- Slack Tokens
- JWT Tokens
- Database URLs (MongoDB, PostgreSQL, MySQL)
- API Keys (generic patterns)
- Private Keys
- Authentication Tokens

### Down - JavaScript Downloader

#### Basic Usage

```bash
# Download from URL list
down -u js_urls.txt

# Specify output directory
down -u js_urls.txt -o downloaded_js

# Adjust performance
down -u js_urls.txt -o js_files -p 50 -t 20 -r 3
```

#### Options Explained

```bash
-u    Input file with URLs (required)
-o    Output directory (default: js_file)
-p    Parallel downloads (default: 30)
-t    Timeout per download (default: 15s)
-r    Retry count (default: 2)
```

#### Example Commands

```bash
# Fast download (high concurrency)
down -u urls.txt -p 100 -t 10

# Careful download (low concurrency, more retries)
down -u urls.txt -p 10 -t 30 -r 5

# Balanced (default)
down -u urls.txt
```

#### Output Structure

```
js_file/
├── success/         # Successfully downloaded
├── archive/         # Retrieved from archive.org
├── failed/          # Empty or failed
├── download.log     # Detailed log
├── failed_urls.txt  # List of failed URLs
└── stats.txt        # Statistics
```

### URL-Extension - File Filter

#### Basic Usage

```bash
# Filter by sensitive extensions
url-extension -f urls.txt

# Custom output
url-extension -f urls.txt -o filtered_results
```

#### Filtered Extensions

```
Documents:  xls, xlsx, doc, docx, pdf, ppt, pptx
Archives:   zip, tar, gz, 7z, rar, bak
Configs:    xml, json, yml, yaml, ini, config
Code:       sql, db, log, md, sh, bat
Security:   key, pem, crt, pub, asc
Backups:    bak, backup, old, tmp
Binaries:   exe, dll, bin, apk, deb, rpm
```

#### Output Files

```
filtered-urls/
├── pdf.txt          # All PDF URLs
├── xls.txt          # All Excel files
├── config.txt       # Configuration files
├── backup.txt       # Backup files
├── sql.txt          # SQL files
└── ...              # One file per extension
```

---

## Workflow Examples

### Scenario 1: Initial Reconnaissance

**Goal**: Discover all assets for a new target

```bash
# Step 1: Run full reconnaissance
./recon.sh -d target.com \
  -w ~/wordlists/comprehensive.txt \
  -r ~/resolvers/fresh.txt

# Step 2: Review subdomain list
cat recon_target.com_*/01_subdomain_enum/all_subdomains.txt

# Step 3: Check live hosts
cat recon_target.com_*/04_live_hosts/live_hosts.txt

# Step 4: Review open ports
cat recon_target.com_*/05_port_scan/open_ports_summary.txt

# Step 5: Browse screenshots
xdg-open recon_target.com_*/06_screenshots/screenshots/
```

### Scenario 2: Deep JavaScript Analysis

**Goal**: Find secrets in JavaScript files

```bash
# Step 1: Run recon to discover JS files
./recon.sh -d target.com

# Step 2: Manual JS analysis
cd recon_target.com_*/08_js_files
jsscan -d success/ --aggressive > secrets.txt

# Step 3: Review findings
cat secrets.txt | grep -i "HIGH\|MEDIUM"

# Step 4: Extract unique secret types
cat secrets.txt | grep -oP '\[.*?\]' | sort -u
```

### Scenario 3: Parameter Discovery for XSS

**Goal**: Find XSS-vulnerable parameters

```bash
# Step 1: Run recon
./recon.sh -d target.com

# Step 2: Extract parameters
cd recon_target.com_*
cat 09_parameters/parameters.txt > all_params.txt

# Step 3: Test with XSS payload
cat all_params.txt | qsreplace '"><script>alert(1)</script>' > xss_test.txt

# Step 4: Check for reflections
cat xss_test.txt | while read url; do
  curl -s "$url" | grep -q 'alert(1)' && echo "[+] Possible XSS: $url"
done
```

### Scenario 4: Subdomain Takeover Hunt

**Goal**: Find vulnerable subdomains

```bash
# Step 1: Run recon
./recon.sh -d target.com

# Step 2: Check takeover results
cd recon_target.com_*
cat 10_vulnerabilities/takeover_results.txt

# Step 3: Manual verification
# Visit flagged domains and check:
# - CNAME points to unclaimed service
# - 404 errors on cloud platforms
# - "Project not found" messages

# Step 4: Attempt claim on detected services
```

### Scenario 5: Continuous Monitoring

**Goal**: Regular scans to detect new assets

```bash
# Create monitoring script
cat > monitor.sh << 'EOF'
#!/bin/bash
DOMAIN="target.com"
NOTIFY_EMAIL="your@email.com"

# Run scan
./recon.sh -d $DOMAIN -o monitor_$DOMAIN

# Compare with previous scan
if [ -f previous_subdomains.txt ]; then
  diff previous_subdomains.txt monitor_$DOMAIN/01_subdomain_enum/all_subdomains.txt > new_subdomains.txt
  
  if [ -s new_subdomains.txt ]; then
    mail -s "New subdomains found for $DOMAIN" $NOTIFY_EMAIL < new_subdomains.txt
  fi
fi

# Save current as previous
cp monitor_$DOMAIN/01_subdomain_enum/all_subdomains.txt previous_subdomains.txt
EOF

chmod +x monitor.sh

# Run weekly via cron
crontab -e
# Add: 0 0 * * 0 /path/to/monitor.sh
```

---

## Tips and Tricks

### Speed Optimization

1. **Use Fast Resolvers**:
   ```bash
   # Test resolver speed
   dnsvalidator -tL resolvers.txt -threads 100 -o fast-resolvers.txt
   ```

2. **Reduce Wordlist Size**:
   ```bash
   # Use targeted wordlist
   head -50000 large-wordlist.txt > medium-wordlist.txt
   ```

3. **Skip Heavy Phases**:
   ```bash
   # Comment out Nmap in recon.sh if not needed
   # Nmap is the slowest phase
   ```

### Result Organization

1. **Create Summary**:
   ```bash
   cd recon_target.com_*
   echo "Subdomains: $(wc -l < 01_subdomain_enum/all_subdomains.txt)"
   echo "Live Hosts: $(wc -l < 04_live_hosts/live_hosts.txt)"
   echo "Open Ports: $(wc -l < 05_port_scan/open_ports_summary.txt)"
   echo "URLs Found: $(wc -l < 07_url_discovery/all_urls.txt)"
   ```

2. **Export for Collaboration**:
   ```bash
   # Create sharable archive
   tar -czf recon_target_summary.tar.gz \
     01_subdomain_enum/all_subdomains.txt \
     04_live_hosts/live_hosts.txt \
     05_port_scan/open_ports_summary.txt \
     07_url_discovery/all_urls.txt \
     08_js_files/secrets/
   ```

### Integration with Other Tools

1. **Export to Burp Suite**:
   ```bash
   # Create Burp target scope
   cat 04_live_hosts/live_hosts.txt | sed 's/^/https:\/\//' > burp_scope.txt
   ```

2. **Feed to Nuclei**:
   ```bash
   cat 04_live_hosts/live_hosts.txt | nuclei -t ~/nuclei-templates/
   ```

3. **Use with SQLMap**:
   ```bash
   cat 09_parameters/parameters.txt | grep '=' | while read url; do
     sqlmap -u "$url" --batch --risk 3 --level 5
   done
   ```

### Debugging

1. **Enable Verbose Logging**:
   ```bash
   # Edit recon.sh, add at top:
   set -x  # Print commands as executed
   ```

2. **Check Individual Tool**:
   ```bash
   # Test tool directly
   subfinder -d example.com -silent
   ```

3. **Monitor Resources**:
   ```bash
   # In another terminal
   watch -n 1 'free -h && echo && ps aux | grep -E "recon|subfinder|httpx" | grep -v grep'
   ```

---

## FAQ

### General Questions

**Q: How long does a typical scan take?**
A: Depends on target size and settings. Small targets (< 100 subdomains): 30-60 minutes. Medium targets (100-1000 subdomains): 2-4 hours. Large targets (1000+ subdomains): 6-12 hours.

**Q: Can I run multiple scans simultaneously?**
A: Yes, but ensure adequate system resources. Use different output directories.

**Q: What if a phase fails?**
A: The script continues with other phases. Check logs/ directory for details. You can re-run with --resume.

**Q: Is it safe to interrupt the scan?**
A: Yes! Use Ctrl+C. Resume with --resume flag.

### Technical Questions

**Q: Why are some tools timing out?**
A: Increase timeout values in recon.sh or reduce concurrency. Check internet connection.

**Q: How do I scan multiple domains?**
A: Create a wrapper script:
```bash
for domain in $(cat domains.txt); do
  ./recon.sh -d $domain
done
```

**Q: Can I use this in Docker?**
A: Yes, but some tools (like nmap) may need --privileged flag.

**Q: How do I update tools?**
A: Re-run install.sh or update individual tools:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Results Questions

**Q: How do I know which findings are real?**
A: Always manually verify:
- Check HTTP responses
- Test parameters manually
- Validate secrets in context
- Confirm vulnerabilities

**Q: What should I focus on first?**
A: Priority order:
1. Subdomain takeovers
2. Exposed secrets/keys
3. Interesting parameters
4. Open administrative ports
5. Sensitive files

**Q: How often should I rescan?**
A: Depends on program:
- New targets: Weekly
- Active targets: Daily/Weekly
- Maintenance: Monthly

### Troubleshooting

**Q: "Command not found" errors?**
A: Ensure PATH includes Go bin:
```bash
export PATH=$PATH:$HOME/go/bin
source ~/.bashrc
```

**Q: Out of memory errors?**
A: Reduce parallelism:
```bash
MAX_PARALLEL_JOBS=5
HTTPX_THREADS=50
```

**Q: DNS resolution fails?**
A: Use fresh resolvers:
```bash
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
./recon.sh -d example.com -r resolvers.txt
```

**Q: Nmap taking forever?**
A: Reduce port range or skip nmap:
```bash
# Edit recon.sh, comment out nmap phase
```

---

## Getting Help

- **Documentation**: Check README.md and CONTRIBUTING.md
- **Issues**: [GitHub Issues](https://github.com/yourusername/recon-pipeline/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/recon-pipeline/discussions)
- **Twitter**: @yourtwitter

---

**Happy Hacking! 🚀**

*Remember: Always get permission before testing!*
