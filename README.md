# 🛡️ Bug Bounty Recon Pipeline v5.1

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-5.0+-blue.svg)](https://www.gnu.org/software/bash/)
[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-brightgreen.svg)](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline)
[![Version](https://img.shields.io/badge/version-5.1-orange.svg)](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/releases)

> **Ultra-Fast Bug Bounty Reconnaissance & Vulnerability Discovery Pipeline**  
> A production-ready, security-hardened automation framework for bug bounty hunters and penetration testers.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Reconnaissance Phases](#-reconnaissance-phases)
- [Configuration](#-configuration)
- [Security Hardening](#-security-hardening)
- [Resume Capability](#-resume-capability)
- [Output Structure](#-output-structure)
- [Tool Requirements](#-tool-requirements)
- [Performance Tuning](#-performance-tuning)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)
- [Credits & Acknowledgments](#-credits--acknowledgments)

---

## 🎯 Overview

The **Bug Bounty Recon Pipeline v5.1** is a comprehensive, automated reconnaissance framework designed for security researchers, bug bounty hunters, and penetration testers. It orchestrates **14 distinct reconnaissance phases**, integrating **40+ industry-standard security tools** into a streamlined, efficient workflow.

### Key Highlights

- **14-Phase Pipeline**: From subdomain enumeration to vulnerability scanning
- **Security Hardened**: v5.1 features proper variable quoting, centralized job control, and no dangerous constructs
- **Resume Capability**: Checkpoint system allows seamless recovery from interruptions
- **Performance Optimized**: Parallel execution with configurable concurrency and smart rate limiting
- **Comprehensive Reporting**: Automated markdown reports with detailed findings
- **One-Command Installation**: Fully automated tool installation via `install_v5.sh`

---

## ✨ Features

### 🔒 Security Hardening (v5.1)

- ✅ All variables properly quoted (prevents word splitting/globbing)
- ✅ No `eval` usage or dangerous constructs
- ✅ Centralized job control with configurable limits
- ✅ Enhanced input sanitization and validation
- ✅ Exponential backoff for API rate limiting
- ✅ Proper error handling and cleanup
- ✅ Secure checkpoint system with input validation

### ⚡ Performance Features

- **Parallel Execution**: Configurable concurrent job limits
- **Smart Rate Limiting**: Exponential backoff to prevent API throttling
- **Timeout Management**: Graceful handling of long-running operations
- **Resource Optimization**: Memory and disk space monitoring
- **Job Tracking**: Background process management with PID tracking

### 🎛️ Operational Features

- **Multiple Scan Modes**: Quick and Full scan profiles
- **Flexible Configuration**: Custom wordlists, resolvers, and exclusions
- **Resume from Checkpoint**: Never lose progress on interrupted scans
- **Proxy Support**: Tor integration for anonymous reconnaissance
- **Verbose Logging**: Detailed debugging information on demand (`--verbose` flag)

---

## 📦 Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline.git

# Navigate to directory
cd Bug-bounty-recon-pipeline

# Run automated installation (installs ALL 40+ tools)
sudo bash install_v5.sh

# Make script executable
chmod +x recon_v5.sh
```

**Note**: The `install_v5.sh` script will:
- Install all 40+ required tools automatically
- Set up Go environment and PATH variables
- Download default wordlists and DNS resolvers
- Configure Tor proxy (optional)
- Verify all installations

### System Requirements

- **OS**: Ubuntu 20.04+, Debian 10+, Kali Linux 2020.1+
- **RAM**: 8 GB minimum (16 GB recommended for full scans)
- **Disk Space**: 5 GB for tools + 10-50 GB for scan results
- **Internet**: Required for tool downloads and passive enumeration

---

## 🚀 Usage

### Basic Usage

```bash
# Single domain scan
./recon_v5.sh example.com

# Multiple domains from file
./recon_v5.sh targets.txt

# Verbose mode for debugging
./recon_v5.sh example.com --verbose
```

### Interactive Configuration

When you run the script, you'll be prompted for:

1. **Scan Type**
   - `quick`: Fast subdomain enumeration and basic port scan (~30 min)
   - `full`: Complete reconnaissance with all phases (~2-4 hours)

2. **Nuclei Scanning**
   - Enable/disable vulnerability scanning with Nuclei templates
   - Recommended: Enable for bug bounty, disable for quick recon

3. **Custom Wordlists** (optional)
   - Provide path to custom subdomain wordlist
   - Default: `/usr/share/default-recon-resources/subdomains-top1million-5000.txt`

4. **Custom Resolvers** (optional)
   - Provide path to custom DNS resolvers file
   - Default: `/usr/share/default-recon-resources/resolvers.txt`

5. **Exclusion List** (optional)
   - Domains/subdomains to exclude from scanning
   - Format: One domain per line

### Advanced Usage

```bash
# Resume interrupted scan
./recon_v5.sh
# (Script automatically detects incomplete scans and offers resume option)

# Multiple targets with verbose logging
./recon_v5.sh targets.txt --verbose

# Quick scan without Nuclei (faster)
./recon_v5.sh example.com
# Select "quick" when prompted, disable Nuclei
```

---

## 🔄 Reconnaissance Phases

The pipeline executes 14 sequential phases, each building upon the previous:

### Phase 1: Subdomain Enumeration
**Tools**: subfinder, assetfinder, amass (passive), puredns (DNS bruteforce)  
**Techniques**:
- Passive subdomain discovery from multiple sources
- DNS bruteforce with custom wordlist
- Subdomain permutation generation (dnsgen)
- DNS resolution validation (dnsx)

**Output**: `subdomains/all_subdomains.txt` (resolved and validated)

---

### Phase 2: Intelligent Port Scanning
**Tools**: naabu, nmap  
**Techniques**:
- Fast initial port discovery (naabu)
- Detailed service detection (nmap)
- CDN/Cloud IP filtering (intelligent exclusion)
- Top ports + custom port ranges

**Output**: `ports/open_ports.txt`, `ports/nmap_detailed.{xml,nmap,gnmap}`

---

### Phase 3: Web Service Discovery
**Tools**: httpx, gowitness  
**Techniques**:
- HTTP/HTTPS probing on all discovered hosts
- Title extraction and technology detection
- Web server fingerprinting
- Status code analysis
- CDN detection

**Output**: `http/live_urls.txt`, `http/httpx_results.txt`

---

### Phase 4: URL Discovery
**Tools**: gau, katana  
**Techniques**:
- Historical URL collection (Wayback Machine, AlienVault OTX)
- Active web crawling and spidering
- URL parameter extraction
- Endpoint discovery
- URL deduplication (uro)

**Output**: `crawling/all_urls.txt`, `crawling/urls_params.txt`

---

### Phase 5: JavaScript File Analysis
**Tools**: httpx (JS extraction), jsscan, gf patterns  
**Techniques**:
- JavaScript file discovery and download
- Sensitive information extraction (API keys, tokens, endpoints)
- Pattern matching for secrets (gf)
- Endpoint extraction from JS files

**Output**: `javascript/js_files/`, `javascript/secrets.txt`, `javascript/endpoints.txt`

---

### Phase 6: Nuclei Vulnerability Scanning
**Tools**: nuclei (with latest templates)  
**Techniques**:
- Template-based vulnerability detection
- CVE scanning
- Misconfiguration detection
- Exposure checks
- Severity-based reporting (Critical, High, Medium)

**Output**: `vulnerabilities/nuclei_results.txt`, `vulnerabilities/nuclei.json`

**Note**: This phase is optional and can be disabled for faster scans.

---

### Phase 7: Vulnerability Pattern Matching
**Tools**: gf (pattern matching), qsreplace  
**Techniques**:
- XSS pattern detection
- SQL injection parameter identification
- SSRF vulnerable endpoints
- Open redirect candidates
- LFI/RFI pattern matching

**Output**: `patterns/xss.txt`, `patterns/sqli.txt`, `patterns/ssrf.txt`

---

### Phase 8: DNS & Network Intelligence
**Tools**: dnsrecon, whois, dnsx  
**Techniques**:
- DNS record enumeration (A, AAAA, MX, NS, TXT, SOA)
- Zone transfer attempts
- WHOIS information gathering
- Mail server discovery
- Name server enumeration

**Output**: `dns/dns_records.txt`, `dns/whois.txt`, `dns/mail_servers.txt`

---

### Phase 9: Screenshot Capture
**Tools**: gowitness  
**Techniques**:
- Visual capture of all live web services
- Automatic thumbnail generation
- Report generation with screenshots

**Output**: `screenshots/*.png`

---

### Phase 10: Technology Detection & Fingerprinting
**Tools**: httpx (tech-detect), wafw00f  
**Techniques**:
- CMS detection (WordPress, Joomla, Drupal, etc.)
- Framework identification
- Server technology fingerprinting
- WAF/Security solution detection

**Output**: `technology/tech_stack.txt`, `technology/waf_detection.txt`

---

### Phase 11: Parameter Discovery
**Tools**: arjun  
**Techniques**:
- HTTP parameter bruteforcing
- Hidden parameter discovery
- Method-based parameter testing (GET, POST)

**Output**: `parameters/discovered_params.txt`

---

### Phase 12: Enhanced Parameter Fuzzing
**Tools**: gf, qsreplace  
**Techniques**:
- Parameter value fuzzing
- Reflection point identification
- Input validation testing
- Edge case discovery

**Output**: `fuzzing/parameter_fuzzing.txt`

---

### Phase 13: CORS Misconfiguration Testing
**Tools**: Custom curl-based testing  
**Techniques**:
- CORS header analysis
- Origin validation testing
- Credential flag testing
- Wildcard misconfiguration detection

**Output**: `cors/cors_results.txt`

---

### Phase 14: Quick Bug Hunting Checks
**Tools**: subjack, custom scripts  
**Techniques**:
- Subdomain takeover detection
- Common vulnerability checks
- Security header analysis
- Exposed sensitive files

**Output**: `quick_checks/takeover.txt`, `quick_checks/exposed_files.txt`

---

## ⚙️ Configuration

### Default Configuration

The script includes optimized default settings in `recon_v5.sh` (lines 156-181):

```bash
# Performance tuning
MAX_PARALLEL_JOBS=10          # Maximum background jobs
MAX_CONCURRENT_JOBS=5         # Concurrent tool executions
MAX_RETRIES=3                 # Retry failed operations
TIMEOUT_SECONDS=2700          # General timeout (45 min)
NMAP_TIMEOUT=5400             # Nmap timeout (90 min)
NUCLEI_TIMEOUT=7200           # Nuclei timeout (2 hours)

# Tool-specific rate limiting
NAABU_RATE=2000               # Packets per second
HTTPX_THREADS=100             # HTTP probe threads
KATANA_CONCURRENCY=50         # Crawler concurrency
NUCLEI_RATE_LIMIT=150         # Nuclei requests/second
NUCLEI_CONCURRENCY=25         # Nuclei parallel templates

# Resource thresholds
MEMORY_THRESHOLD=2048         # MB - minimum available RAM
```

### Custom Configuration

Edit these values in `recon_v5.sh` to suit your needs:

**For Slower/Stealthier Scans:**
```bash
NAABU_RATE=500
HTTPX_THREADS=25
KATANA_CONCURRENCY=10
NUCLEI_RATE_LIMIT=50
```

**For Faster/Aggressive Scans:**
```bash
NAABU_RATE=5000
HTTPX_THREADS=200
KATANA_CONCURRENCY=100
NUCLEI_RATE_LIMIT=300
```

---

## 🔐 Security Hardening

Version 5.1 introduces comprehensive security improvements to prevent common bash vulnerabilities:

### 1. Proper Variable Quoting
**Prevents**: Word splitting and globbing attacks

```bash
# ❌ Before (v5.0 - vulnerable)
for file in $dir/*; do
    cat $file
done

# ✅ After (v5.1 - secure)
for file in "$dir"/*; do
    cat "$file"
done
```

### 2. No Dangerous Constructs
**Eliminates**: Code injection vulnerabilities

- ❌ **No `eval` usage** - Prevents arbitrary code execution
- ❌ **No unquoted command substitution** - Prevents injection
- ❌ **No user input in commands** without validation

### 3. Centralized Job Control
**Prevents**: Resource exhaustion and race conditions

```bash
# Job management functions
wait_for_job_slot()      # Enforces MAX_CONCURRENT_JOBS limit
register_job()           # Tracks background processes
wait_for_all_jobs()      # Graceful job completion with timeout
```

### 4. Input Validation
**Prevents**: Path traversal and injection attacks

```bash
# Domain validation regex
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 1
    fi
    return 0
}
```

### 5. Rate Limiting with Exponential Backoff
**Prevents**: API throttling and bans

```bash
rate_limit_sleep() {
    # Base delay: 1 second
    # Max delay: 60 seconds
    # Multiplier: 2x per retry
}
```

### 6. Secure Cleanup
**Prevents**: Leftover temporary files and sensitive data exposure

```bash
cleanup_trap() {
    # Removes all temporary files on exit
    # Cleans up orphaned processes
    # Logs cleanup actions
}
```

---

## 💾 Resume Capability

The script automatically saves checkpoints after each phase, enabling seamless recovery from interruptions.

### How It Works

1. **Automatic Checkpoint Creation**
   - After each phase completes successfully
   - Stores: Phase number, domain, timestamp, status
   - Location: `<output_dir>/.recon_state/checkpoint.txt`

2. **Resume Detection on Startup**
   ```bash
   $ ./recon_v5.sh
   
   [!] Found incomplete scan(s):
     1) recon_v5_20250205_143022
        Domain: example.com
        Phase: 7 (Vulnerability Pattern Matching)
        Status: RUNNING
        Last Update: 2025-02-05 14:45:32
   
   Resume a scan? (Enter number or 'n' to start new): 1
   ```

3. **Seamless Continuation**
   - Loads previous configuration (wordlists, resolvers, scan type)
   - Skips completed phases
   - Resumes from last incomplete phase
   - Preserves all previous results

### Resume State Files

```
<output_dir>/.recon_state/
├── checkpoint.txt    # Current phase and status
└── progress.log      # Detailed phase history
```

**Checkpoint Format:**
```
PHASE=7
DOMAIN=example.com
TIMESTAMP=1738767932
STATUS=RUNNING
LAST_UPDATE=2025-02-05 14:45:32
```

### Manual Resume Management

```bash
# View checkpoint status
cat recon_v5_*/. recon_state/checkpoint.txt

# Force restart (ignore checkpoint)
rm -rf recon_v5_*/.recon_state/
./recon_v5.sh example.com

# Resume specific scan
# Enter scan number when prompted
```

---

## 📂 Output Structure

Each scan creates a timestamped directory with organized results:

```
recon_v5_YYYYMMDD_HHMMSS/
├── <domain>/
│   ├── subdomains/
│   │   ├── all_subdomains.txt          # Final resolved subdomains
│   │   ├── subfinder.txt               # Subfinder results
│   │   ├── assetfinder.txt             # Assetfinder results
│   │   ├── amass_passive.txt           # Amass passive results
│   │   ├── puredns.txt                 # DNS bruteforce results
│   │   ├── dnsgen.txt                  # Permutations
│   │   └── dnsgen_resolved.txt         # Resolved permutations
│   │
│   ├── ports/
│   │   ├── open_ports.txt              # All open ports
│   │   ├── naabu_results.txt           # Fast scan results
│   │   ├── nmap_detailed.xml           # Nmap XML output
│   │   ├── nmap_detailed.nmap          # Nmap normal output
│   │   └── nmap_detailed.gnmap         # Nmap grepable output
│   │
│   ├── http/
│   │   ├── live_urls.txt               # All HTTP/HTTPS URLs
│   │   ├── httpx_results.txt           # Detailed HTTP info
│   │   └── httpx.json                  # JSON output
│   │
│   ├── crawling/
│   │   ├── all_urls.txt                # All discovered URLs
│   │   ├── gau_results.txt             # GAU output
│   │   ├── katana_results.txt          # Katana crawl results
│   │   ├── urls_params.txt             # URLs with parameters
│   │   └── unique_urls.txt             # Deduplicated URLs
│   │
│   ├── javascript/
│   │   ├── js_files/                   # Downloaded JS files
│   │   │   ├── success/                # Successfully downloaded
│   │   │   └── failed/                 # Failed downloads
│   │   ├── js_urls.txt                 # JavaScript URLs
│   │   ├── secrets.txt                 # Found secrets/keys
│   │   └── endpoints.txt               # Extracted endpoints
│   │
│   ├── vulnerabilities/
│   │   ├── nuclei_results.txt          # Nuclei findings (text)
│   │   └── nuclei.json                 # Nuclei findings (JSON)
│   │
│   ├── patterns/
│   │   ├── xss.txt                     # XSS candidates
│   │   ├── sqli.txt                    # SQLi candidates
│   │   ├── ssrf.txt                    # SSRF candidates
│   │   ├── redirect.txt                # Open redirect candidates
│   │   └── lfi.txt                     # LFI candidates
│   │
│   ├── dns/
│   │   ├── dns_records.txt             # All DNS records
│   │   ├── whois.txt                   # WHOIS information
│   │   ├── mail_servers.txt            # MX records
│   │   ├── name_servers.txt            # NS records
│   │   └── zone_transfer.txt           # Zone transfer attempts
│   │
│   ├── screenshots/
│   │   └── *.png                       # Web screenshots
│   │
│   ├── technology/
│   │   ├── tech_stack.txt              # Detected technologies
│   │   └── waf_detection.txt           # WAF findings
│   │
│   ├── parameters/
│   │   └── discovered_params.txt       # Arjun results
│   │
│   ├── fuzzing/
│   │   └── parameter_fuzzing.txt       # Fuzzing results
│   │
│   ├── cors/
│   │   └── cors_results.txt            # CORS testing results
│   │
│   ├── quick_checks/
│   │   ├── takeover.txt                # Subdomain takeover
│   │   └── exposed_files.txt           # Sensitive files
│   │
│   ├── REPORT.md                       # Final markdown report
│   ├── errors.log                      # Error messages
│   └── .recon_state/                   # Resume checkpoint
│       ├── checkpoint.txt
│       └── progress.log
│
└── recon.log                           # Global execution log
```

---

## 🛠️ Tool Requirements

The pipeline requires **40+ tools** that are automatically installed by `install_v5.sh`.

### Complete Tool List

#### System & Language Tools (6)
1. **python3** - Python 3 runtime
2. **pip3** - Python package manager
3. **go** - Go programming language (v1.19+)
4. **git** - Version control
5. **curl** - Data transfer tool
6. **wget** - Network downloader

#### Proxy & Anonymity (2)
7. **proxychains** - Proxy chains
8. **tor** - The Onion Router

#### Web Browser (1)
9. **chromium** - Headless browser (for screenshots)

#### Subdomain Enumeration (6)
10. **subfinder** - Passive subdomain discovery
11. **assetfinder** - Asset discovery
12. **amass** - OWASP DNS enumeration
13. **puredns** - DNS bruteforcing
14. **dnsx** - DNS toolkit
15. **dnsgen** - Subdomain permutation

#### Port Scanning (2)
16. **naabu** - Fast port scanner
17. **nmap** - Network mapper

#### HTTP Tools (3)
18. **httpx** - HTTP toolkit
19. **gowitness** - Screenshot utility
20. **katana** - Web crawler

#### URL Processing (5)
21. **gau** - URL collection from archives
22. **uro** - URL deduplication
23. **gf** - Pattern matching
24. **qsreplace** - Query parameter replacer
25. **url-extension** - URL extension tool (custom)

#### Vulnerability Scanning (2)
26. **nuclei** - Template-based vulnerability scanner
27. **arjun** - Parameter discovery

#### DNS & WHOIS (2)
28. **dnsrecon** - DNS reconnaissance
29. **whois** - WHOIS lookup

#### Security Testing (2)
30. **subjack** - Subdomain takeover detection
31. **wafw00f** - WAF detection

#### Cloud Enumeration (1)
32. **cloud_enum** - Cloud asset discovery (AWS, Azure, GCP)

#### JavaScript Analysis (2)
33. **jsscan** - JavaScript secret scanner (custom)
34. **down** - Download utility (custom)

#### JSON Processing (1)
35. **jq** - JSON processor

#### Standard Linux Utilities (Pre-installed)
36. awk, sed, grep, find, sort, uniq, cat, tr, xargs, wc

### Installation Methods

| Method | Tools Count |
|--------|-------------|
| **APT** (Debian/Ubuntu) | python3, git, curl, wget, jq, nmap, dnsrecon, whois, tor, proxychains4, chromium |
| **Go Install** | subfinder, assetfinder, amass, puredns, dnsx, naabu, httpx, nuclei, gowitness, gau, katana, gf, qsreplace, subjack |
| **pip3** | dnsgen, uro, arjun, wafw00f |
| **Git Clone** | cloud_enum, jsscan, down, url-extension |

### Resource Files (Auto-Downloaded)

- **Wordlist**: `subdomains-top1million-5000.txt` (5000 common subdomains)
- **Resolvers**: `resolvers.txt` (trusted DNS resolvers)
- **Fingerprint**: `fingerprint.json` (technology fingerprints)
- **Nuclei Templates**: Latest vulnerability templates
- **GF Patterns**: Bug bounty pattern files

### Optional Tools

- **grepcidr** - CIDR matching (for CDN detection)
- **sudo** - Privilege escalation (for some installations)
- **libpcap-dev** - Required for naabu compilation

---

## ⚡ Performance Tuning

### Resource Recommendations

| Scan Type | RAM | CPU | Disk | Duration |
|-----------|-----|-----|------|----------|
| **Quick** | 4 GB | 2 cores | 10 GB | 20-40 min |
| **Full** | 8 GB | 4 cores | 30 GB | 2-4 hours |
| **Full + Nuclei** | 16 GB | 8 cores | 50 GB | 4-8 hours |
| **Multiple Targets** | 32 GB | 16 cores | 100 GB | Varies |

### Configuration Presets

#### Fast & Aggressive (High Resources)
```bash
# Edit lines 164-176 in recon_v5.sh
MAX_CONCURRENT_JOBS=10
NAABU_RATE=5000
HTTPX_THREADS=200
KATANA_CONCURRENCY=100
NUCLEI_RATE_LIMIT=300
NUCLEI_CONCURRENCY=50
```

#### Balanced (Recommended)
```bash
MAX_CONCURRENT_JOBS=5
NAABU_RATE=2000
HTTPX_THREADS=100
KATANA_CONCURRENCY=50
NUCLEI_RATE_LIMIT=150
NUCLEI_CONCURRENCY=25
```

#### Slow & Stealthy (Low Resources)
```bash
MAX_CONCURRENT_JOBS=3
NAABU_RATE=500
HTTPX_THREADS=25
KATANA_CONCURRENCY=10
NUCLEI_RATE_LIMIT=50
NUCLEI_CONCURRENCY=10
```

### Performance Tips

1. **Disable Nuclei for faster scans** (saves 1-2 hours)
2. **Use Quick scan mode** for initial reconnaissance
3. **Filter CDN/Cloud IPs** to focus on real infrastructure
4. **Exclude out-of-scope domains** early to save time
5. **Increase timeouts** if you have slow internet connection

---

## 🐛 Troubleshooting

### Common Issues & Solutions

#### Issue: Tool Not Found

```bash
# Symptom
[✗] subfinder (required)
[!] Missing required tools

# Solution 1: Re-run installation
sudo bash install_v5.sh

# Solution 2: Check Go PATH
echo $GOPATH
export PATH=$PATH:$GOPATH/bin:$HOME/go/bin

# Solution 3: Manually install missing tool
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### Issue: Permission Denied

```bash
# Symptom
bash: ./recon_v5.sh: Permission denied

# Solution
chmod +x recon_v5.sh
./recon_v5.sh
```

#### Issue: Out of Memory

```bash
# Symptom
Killed
[FATAL] Script exited unexpectedly with code 137

# Solution 1: Reduce concurrency
# Edit recon_v5.sh:
MAX_CONCURRENT_JOBS=2
HTTPX_THREADS=25

# Solution 2: Disable Nuclei (most memory-intensive)
# Select "n" when prompted for Nuclei scanning

# Solution 3: Monitor memory
watch -n 1 free -h
```

#### Issue: Nuclei Template Update Fails

```bash
# Symptom
[!] Failed to update Nuclei templates

# Solution
nuclei -update-templates
# Or manually:
cd ~/nuclei-templates && git pull
```

#### Issue: DNS Resolution Fails

```bash
# Symptom
[!] No subdomains resolved

# Solution: Use different resolvers
# Download fresh resolvers:
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
# Specify when prompted for custom resolvers
```

#### Issue: Script Hangs

```bash
# Symptom
Script stops responding (no output for 10+ minutes)

# Solution 1: Enable verbose mode
./recon_v5.sh example.com --verbose

# Solution 2: Check running processes
ps aux | grep -E 'nmap|nuclei|katana|httpx'

# Solution 3: Increase timeouts
# Edit recon_v5.sh:
TIMEOUT_SECONDS=5400
NMAP_TIMEOUT=7200
NUCLEI_TIMEOUT=10800
```

#### Issue: Resume Not Working

```bash
# Symptom
[!] No incomplete scans found

# Solution 1: Check for .recon_state directory
ls -la recon_v5_*/.recon_state/

# Solution 2: Verify checkpoint file
cat recon_v5_*/.recon_state/checkpoint.txt

# Solution 3: If corrupted, remove and restart
rm -rf recon_v5_*/.recon_state/
./recon_v5.sh example.com
```

### Debug Mode

For advanced troubleshooting, enable bash debug mode:

```bash
bash -x recon_v5.sh example.com --verbose 2>&1 | tee debug.log
```

This shows every command executed and helps identify where the script fails.

---

## 🤝 Contributing

Contributions are highly encouraged! Here's how you can help improve the Bug Bounty Recon Pipeline:

### Ways to Contribute

- 🐛 **Report bugs** - Found an issue? Open a detailed bug report
- ✨ **Suggest features** - Have an idea? Share it in discussions
- 📝 **Improve documentation** - Fix typos, add examples, clarify instructions
- 🔧 **Submit code** - Fix bugs, add tools, optimize performance
- 🧪 **Test & review** - Try the script on different systems and provide feedback

### Reporting Issues

When reporting bugs, please include:

1. **System Information**
   ```bash
   uname -a
   bash --version
   cat /etc/os-release
   ```

2. **Tool Versions**
   ```bash
   subfinder -version
   nuclei -version
   go version
   ```

3. **Error Output**
   ```bash
   # Relevant sections from:
   recon_v5_*/recon.log
   recon_v5_*/errors.log
   ```

4. **Steps to Reproduce**
   - Exact commands run
   - Target domain (if not sensitive)
   - Configuration changes made

### Submitting Pull Requests

1. **Fork** the repository
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-improvement
   ```

3. **Make your changes**
   - Follow existing code style
   - Add comments for complex logic
   - Test thoroughly on Ubuntu/Debian

4. **Test the script**
   ```bash
   # Run on test domain
   ./recon_v5.sh example.com
   
   # Verify no errors
   grep -i "error\|fatal" recon_v5_*/recon.log
   ```

5. **Commit with clear message**
   ```bash
   git commit -m "Add feature: Integrate new tool X for Phase Y"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/amazing-improvement
   ```

7. **Open Pull Request**
   - Describe what changed and why
   - Reference related issues
   - Include testing results

### Development Guidelines

#### Code Style

- **Bash best practices**: Proper quoting, error handling, functions
- **Security first**: No `eval`, validate all inputs, secure temp files
- **Readability**: Clear variable names, helpful comments
- **Modularity**: Keep functions focused and reusable

#### Testing Checklist

- [ ] Script runs without errors on clean system
- [ ] All phases complete successfully
- [ ] Resume functionality works
- [ ] Verbose mode provides useful output
- [ ] Error handling works correctly
- [ ] No security vulnerabilities introduced

#### Adding New Tools

When integrating new reconnaissance tools:

1. **Update `install_v5.sh`** with installation instructions
2. **Add to `check_tools()` function** in `recon_v5.sh`
3. **Create or modify phase function** to use the new tool
4. **Update output structure** in this README
5. **Add example output** to help users understand results
6. **Test integration** with existing pipeline

---

## 📜 License

This project is licensed under the **MIT License**.

### MIT License Summary

**Permissions:**
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use

**Conditions:**
- ℹ️ License and copyright notice required

**Limitations:**
- ⚠️ Liability
- ⚠️ Warranty

See the [LICENSE](LICENSE) file for the full legal text.

---

## 🙏 Credits & Acknowledgments

### Original Author

**Shakibul Bokthiar** (Shakibul_Cybersec)
- Primary developer and maintainer
- Bug bounty hunter and security researcher

### AI Assistance & Documentation

This project's documentation, testing, and validation was enhanced with assistance from:

- **Claude (Anthropic)** - README accuracy verification, tool list validation, code review, security hardening suggestions
- **ChatGPT (OpenAI)** - Initial documentation drafting, examples, troubleshooting guides
- **DeepSeek** - Code optimization suggestions, performance tuning recommendations

*Note: AI tools were used for documentation and analysis only. All reconnaissance code and security logic was written and reviewed by human security researchers.*

### Tool Authors & Projects

Massive thanks to the amazing security tool developers:

#### ProjectDiscovery Team
- **subfinder**, **httpx**, **nuclei**, **naabu**, **dnsx**, **katana** - Exceptional reconnaissance tools that power this pipeline

#### OWASP
- **amass** - Comprehensive DNS enumeration framework

#### Independent Developers
- **tomnomnom** - assetfinder, gf, qsreplace, anew, unfurl
- **d3mondev** - puredns
- **lc** - gau, subjs
- **sensepost** - gowitness
- **haccer** - subjack
- **EnableSecurity** - wafw00f
- **s0md3v** - Arjun
- **initstring** - cloud_enum

#### Essential Tools
- **nmap** (Gordon Lyon / Fyodor) - The legendary network scanner
- **dnsgen** (ProjectAnte) - Subdomain permutation
- **jq** (Stephen Dolan) - JSON processing
- **chromium** (Google) - Headless browser engine

### Community Resources

- **SecLists** (Daniel Miessler) - Wordlists and patterns
- **Trickest** - DNS resolver lists
- **Bug Bounty Community** - Testing methodologies and techniques
- **InfoSec Twitter** - Continuous inspiration and knowledge sharing

### Special Thanks

- All bug bounty hunters who test and improve this tool
- Security researchers who report issues and suggest improvements
- Open-source community for making these amazing tools freely available

---

## ⚠️ Disclaimer

### Legal and Ethical Use

**This tool is intended ONLY for:**

✅ **Authorized penetration testing** with written permission  
✅ **Bug bounty programs** with explicit scope definitions  
✅ **Security research** in controlled, legal environments  
✅ **Educational purposes** in lab/testing setups  
✅ **Personal infrastructure** that you own or have authorization to test  

### Prohibited Uses

**DO NOT use this tool for:**

❌ **Unauthorized access** to systems you don't own or have permission to test  
❌ **Malicious activities** including DoS, data theft, or system compromise  
❌ **Violating laws** - including CFAA (Computer Fraud and Abuse Act) and similar legislation  
❌ **Violating terms of service** of websites or platforms  
❌ **Testing without consent** - Always obtain written authorization first  

### Legal Responsibilities

- **Users are solely responsible** for complying with all applicable laws and regulations
- **Always obtain explicit written permission** before testing any system
- **Respect bug bounty program rules** including scope, disclosure timelines, and restrictions
- **The author assumes NO LIABILITY** for misuse, damages, or legal consequences
- **This tool generates significant traffic** - ensure you have permission for the load

### Security Warning

- This tool performs **active reconnaissance** and **vulnerability scanning**
- Operations **will be logged** by target systems and may trigger alerts
- Use **responsibly** and **ethically** at all times
- Consider using **VPN/proxy** for privacy (where legally allowed)

### Bug Bounty Guidelines

When using this tool for bug bounties:

1. **Read the program rules** completely before starting
2. **Respect the scope** - Don't test out-of-scope domains
3. **Be mindful of rate limits** - Don't DoS the targets
4. **Follow responsible disclosure** - Report findings properly
5. **Don't weaponize** - Never exploit vulnerabilities beyond PoC

**By using this tool, you agree to use it legally, ethically, and responsibly. The author and contributors are not responsible for any misuse or damage caused by this tool.**

---

## 📊 Project Stats

![GitHub stars](https://img.shields.io/github/stars/Shakibul-CyberSec/Bug-bounty-recon-pipeline?style=social)
![GitHub forks](https://img.shields.io/github/forks/Shakibul-CyberSec/Bug-bounty-recon-pipeline?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/Shakibul-CyberSec/Bug-bounty-recon-pipeline?style=social)
![GitHub issues](https://img.shields.io/github/issues/Shakibul-CyberSec/Bug-bounty-recon-pipeline)
![GitHub pull requests](https://img.shields.io/github/issues-pr/Shakibul-CyberSec/Bug-bounty-recon-pipeline)

---

## 🗺️ Roadmap

Future enhancements planned for the pipeline:

### v5.2 (Next Release)
- [ ] Web-based dashboard for results visualization
- [ ] Integration with notification services (Slack, Discord, Telegram)
- [ ] Enhanced report generation with charts and graphs
- [ ] Cloud storage integration (S3, Google Drive) for results

### v6.0 (Major Update)
- [ ] Docker containerization for easy deployment
- [ ] Kubernetes deployment for distributed scanning
- [ ] Custom plugin system for additional tools
- [ ] API for programmatic access

### Future Considerations
- [ ] Machine learning for false positive reduction
- [ ] Automatic vulnerability validation
- [ ] Integration with SIEM systems
- [ ] CI/CD pipeline templates
- [ ] Cloud deployment templates (AWS, GCP, Azure)
- [ ] Multi-threading optimization
- [ ] Real-time progress dashboard

### Community Requests
- Suggest features in [GitHub Discussions](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/discussions)

---

<div align="center">

### ⭐ If this project helps you find bugs, consider giving it a star!

**Made with ❤️ by Security Researchers, for Security Researchers**

[Report Bug](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/issues) · [Request Feature](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/issues) · [Contribute](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/pulls)

---

**🔒 Hack Legally. Research Ethically. Disclose Responsibly.**

</div>
