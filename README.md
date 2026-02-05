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
- [Author](#-author)

---

## 🎯 Overview

The **Bug Bounty Recon Pipeline v5.1** is a comprehensive, automated reconnaissance framework designed for security researchers, bug bounty hunters, and penetration testers. It orchestrates 14 distinct reconnaissance phases, integrating over 50 industry-standard security tools into a streamlined, efficient workflow.

### Key Highlights

- **14-Phase Pipeline**: From subdomain enumeration to vulnerability scanning
- **Security Hardened**: v5.1 features proper variable quoting, centralized job control, and no dangerous constructs
- **Resume Capability**: Checkpoint system allows seamless recovery from interruptions
- **Performance Optimized**: Parallel execution with configurable concurrency and smart rate limiting
- **Comprehensive Reporting**: Automated markdown reports with detailed findings

---

## ✨ Features

### 🔒 Security Hardening (v5.1)

- ✅ All variables properly quoted (prevents word splitting/globbing)
- ✅ No `eval` usage or dangerous constructs
- ✅ Centralized job control with configurable limits
- ✅ Enhanced input sanitization and validation
- ✅ Exponential backoff for API rate limiting
- ✅ Proper error handling and cleanup

### ⚡ Performance Features

- **Parallel Execution**: Configurable concurrent job limits
- **Smart Rate Limiting**: Exponential backoff to prevent API throttling
- **Timeout Management**: Graceful handling of long-running operations
- **Resource Optimization**: Memory and disk space monitoring

### 🎛️ Operational Features

- **Multiple Scan Modes**: Quick, Full, and Stealth profiles
- **Flexible Configuration**: Custom wordlists, resolvers, and exclusions
- **Resume from Checkpoint**: Never lose progress on interrupted scans
- **Proxy Support**: HTTP/HTTPS proxy configuration
- **Verbose Logging**: Detailed debugging information on demand

---

## 📦 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline.git

# Navigate to directory
cd Bug-bounty-recon-pipeline

# Run automated installation
sudo bash install_v5.sh

# Make script executable
chmod +x recon_v5.sh
```

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

#### 1. Install Required Tools

The script requires the following tools. Install them manually or use the provided installation script.

**Subdomain Enumeration:**
```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# Findomain
# Download from: https://github.com/Findomain/Findomain/releases

# Chaos
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# GitHub Subdomains
go install github.com/gwen001/github-subdomains@latest
```

**DNS Resolution:**
```bash
# ShuffleDNS
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# DNSGen
pip3 install dnsgen

# Alterx
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

# Gotator
go install github.com/Josue87/gotator@latest

# PureDNS
go install github.com/d3mondev/puredns/v2@latest

# MassDNS
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make && sudo make install

# DNSX
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

**Port Scanning:**
```bash
# Naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Nmap
sudo apt-get install nmap
```

**HTTP Probing:**
```bash
# HTTPX
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**Web Crawling:**
```bash
# Waybackurls
go install github.com/tomnomnom/waybackurls@latest

# GAU
go install github.com/lc/gau/v2/cmd/gau@latest

# Gauplus
go install github.com/bp0lr/gauplus@latest

# Hakrawler
go install github.com/hakluke/hakrawler@latest

# Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Gospider
go install github.com/jaeles-project/gospider@latest

# xnLinkFinder
python3 -m pip install xnLinkFinder
```

**URL Processing:**
```bash
# Unfurl
go install github.com/tomnomnom/unfurl@latest

# Anew
go install github.com/tomnomnom/anew@latest

# URO
pip3 install uro
```

**Content Discovery:**
```bash
# Meg
go install github.com/tomnomnom/meg@latest

# Feroxbuster
# Download from: https://github.com/epi052/feroxbuster/releases

# Dirsearch
git clone https://github.com/maurosoria/dirsearch.git
```

**Vulnerability Scanning:**
```bash
# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# SQLMap
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

**Parameter Discovery:**
```bash
# Arjun
pip3 install arjun

# x8
cargo install x8

# GF (Patterns)
go install github.com/tomnomnom/gf@latest

# Qsreplace
go install github.com/tomnomnom/qsreplace@latest
```

**Fuzzing Tools:**
```bash
# Dalfox
go install github.com/hahwul/dalfox/v2@latest

# FFUF
go install github.com/ffuf/ffuf/v2@latest

# CRLFuzz
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# GXSS
go install github.com/KathanP19/Gxss@latest
```

**Screenshots:**
```bash
# GoWitness
go install github.com/sensepost/gowitness@latest
```

**Technology Detection:**
```bash
# Webanalyze
go install github.com/rverton/webanalyze/cmd/webanalyze@latest
```

**Security Checks:**
```bash
# Subjs
go install github.com/lc/subjs@latest

# S3Scanner
pip3 install s3scanner

# TruffleHog
pip3 install truffleHog
```

**Utilities:**
```bash
# JQ
sudo apt-get install jq

# Parallel
sudo apt-get install parallel
```

</details>

---

## 🚀 Usage

### Basic Usage

```bash
# Single domain scan
./recon_v5.sh example.com

# Multiple domains from file
./recon_v5.sh targets.txt

# Verbose mode
./recon_v5.sh example.com --verbose
```

### Interactive Configuration

When you run the script, you'll be prompted for:

1. **Scan Type**
   - Quick: Fast enumeration only
   - Full: Complete reconnaissance (default)
   - Stealth: Slower, more careful

2. **Nuclei Scanning**
   - Enable/disable vulnerability scanning with Nuclei

3. **Custom Wordlists** (optional)
   - Provide path to custom subdomain wordlist

4. **Custom Resolvers** (optional)
   - Provide path to custom DNS resolvers file

5. **Exclusion List** (optional)
   - Domains/subdomains to exclude from scanning

### Advanced Usage

```bash
# Resume interrupted scan
./recon_v5.sh
# (Script will detect incomplete scans and offer resume option)

# With proxy
# Configure interactively when prompted or export:
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
./recon_v5.sh example.com
```

---

## 🔄 Reconnaissance Phases

### Phase 1: Subdomain Enumeration
- **Passive Sources**: subfinder, amass, assetfinder, findomain, chaos, github-subdomains
- **Active Bruteforce**: shuffledns with custom wordlists
- **Permutation Generation**: dnsgen, alterx, gotator
- **Output**: `subdomains/all_subdomains.txt`

### Phase 2: DNS Resolution & Validation
- **Tools**: dnsx, massdns, puredns
- **Records**: A, AAAA, CNAME, NS, MX, PTR, SOA, TXT
- **Output**: `dns/live_domains.txt`, `dns/dns_records.json`

### Phase 3: Port Scanning
- **Fast Scan**: naabu (top 1000 ports)
- **Detailed Scan**: nmap with service detection
- **Output**: `ports/open_ports.txt`, `ports/nmap_detailed.xml`

### Phase 4: HTTP Probing
- **Tool**: httpx
- **Detection**: Title, tech stack, status codes, web servers, CDN
- **Output**: `http/live_urls.txt`, `http/httpx.json`

### Phase 5: Web Crawling & URL Discovery
- **Archive Sources**: waybackurls, gau, gauplus
- **Active Crawlers**: hakrawler, katana, gospider
- **JS Analysis**: xnLinkFinder for endpoint extraction
- **Output**: `crawling/unique_urls.txt`, `crawling/urls_with_params.txt`

### Phase 6: Content Discovery
- **Tools**: meg, feroxbuster, dirsearch
- **Output**: `content_discovery/discovered_paths.txt`

### Phase 7: Vulnerability Scanning
- **Tool**: Nuclei (optional, can be disabled)
- **Severity**: Critical, High, Medium
- **Output**: `vulnerabilities/nuclei.json`, `vulnerabilities/nuclei_report.md`

### Phase 8: Advanced DNS Reconnaissance
- **Techniques**: Zone transfers, ANY records, mail servers, name servers
- **Output**: `advanced_dns/zone_transfer.txt`

### Phase 9: Screenshots
- **Tool**: GoWitness
- **Output**: `screenshots/*.png`

### Phase 10: Technology Detection
- **Tools**: webanalyze, httpx tech-detect
- **Output**: `technology/technologies.txt`

### Phase 11: Parameter Discovery
- **Tools**: arjun, x8
- **Output**: `parameters/all_parameters.txt`

### Phase 12: Enhanced Parameter Fuzzing
- **XSS Testing**: dalfox, gxss
- **SQLi Testing**: sqlmap (limited quick scan)
- **CRLF Testing**: crlfuzz
- **Pattern Matching**: gf patterns
- **Output**: `fuzzing/xss_results.txt`, `fuzzing/sqli_candidates.txt`

### Phase 13: CORS Testing
- **Tool**: corstest / manual curl testing
- **Output**: `cors/cors_results.txt`

### Phase 14: Quick Security Checks
- **Subdomain Takeover**: subjs
- **S3 Buckets**: s3scanner
- **Git Exposure**: curl-based detection
- **Secret Scanning**: trufflehog (if git repos found)
- **Output**: `quick_checks/*`

---

## ⚙️ Configuration

### Default Configuration

```bash
# Performance tuning
MAX_PARALLEL_JOBS=10
MAX_CONCURRENT_JOBS=5
MAX_RETRIES=3
TIMEOUT_SECONDS=2700
NMAP_TIMEOUT=5400
NUCLEI_TIMEOUT=7200

# Tool configurations
NAABU_RATE=2000
HTTPX_THREADS=100
KATANA_CONCURRENCY=50
NUCLEI_RATE_LIMIT=150
NUCLEI_CONCURRENCY=25

# Resource thresholds
MEMORY_THRESHOLD=2048  # MB
```

### Custom Configuration

Edit the configuration section in `recon_v5.sh`:

```bash
# Performance tuning (lines 164-169)
MAX_PARALLEL_JOBS=15        # Increase for more parallelism
TIMEOUT_SECONDS=3600        # Adjust timeout as needed

# Tool configurations (lines 172-176)
NAABU_RATE=3000            # Increase port scan speed
HTTPX_THREADS=150          # More HTTP probing threads
```

---

## 🔐 Security Hardening

Version 5.1 introduces comprehensive security improvements:

### Variable Quoting
```bash
# Before (v5.0)
for file in $dir/*; do

# After (v5.1)
for file in "$dir"/*; do
```

### No Dangerous Constructs
- ❌ No `eval` usage
- ❌ No command substitution in variables without quotes
- ❌ No unvalidated user input in commands

### Centralized Job Control
```bash
# Configurable parallel execution
wait_for_job_slot()           # Limits concurrent jobs
register_job()                # Tracks background processes
wait_for_all_jobs()           # Graceful job completion
```

### Rate Limiting
```bash
# Exponential backoff for API calls
rate_limit_sleep()
  Base delay: 1 second
  Max delay: 60 seconds
  Multiplier: 2x per retry
```

### Input Sanitization
```bash
# Domain validation
validate_domain() {
    [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}
```

---

## 💾 Resume Capability

The script automatically saves checkpoints after each phase:

### How It Works

1. **Checkpoint Creation**: After each phase completes
   ```bash
   save_checkpoint "$output_dir" "$phase" "$domain" "COMPLETE"
   ```

2. **Resume Detection**: On script startup, incomplete scans are detected
   ```bash
   $ ./recon_v5.sh
   [!] Found 1 incomplete scan(s):
     1) recon_v5_20250205_143022 - Domain: example.com, Phase: 7, Status: RUNNING
   Resume a scan? (Enter number or 'n' to start new):
   ```

3. **Seamless Recovery**: Resumes from the last completed phase
   ```bash
   [*] Resuming from Phase 7 (Status: RUNNING)
   ```

### Resume State Location
```
<output_dir>/.recon_state/
  └── checkpoint.txt    # Phase tracking
  └── progress.log      # Detailed progress
```

---

## 📂 Output Structure

Each scan creates a timestamped directory:

```
recon_v5_YYYYMMDD_HHMMSS/
├── <domain>/
│   ├── subdomains/
│   │   ├── all_subdomains.txt
│   │   ├── passive_subs.txt
│   │   ├── shuffledns.txt
│   │   └── permutations_resolved.txt
│   ├── dns/
│   │   ├── live_domains.txt
│   │   └── dns_records.json
│   ├── ports/
│   │   ├── open_ports.txt
│   │   └── nmap_detailed.{xml,nmap,gnmap}
│   ├── http/
│   │   ├── live_urls.txt
│   │   └── httpx.json
│   ├── crawling/
│   │   ├── unique_urls.txt
│   │   ├── urls_with_params.txt
│   │   └── js_files.txt
│   ├── content_discovery/
│   │   └── discovered_paths.txt
│   ├── vulnerabilities/
│   │   ├── nuclei.json
│   │   └── nuclei_report.md
│   ├── advanced_dns/
│   │   ├── zone_transfer.txt
│   │   └── mail_servers.txt
│   ├── screenshots/
│   │   └── *.png
│   ├── technology/
│   │   └── technologies.txt
│   ├── parameters/
│   │   └── all_parameters.txt
│   ├── fuzzing/
│   │   ├── xss_results.txt
│   │   ├── sqli_candidates.txt
│   │   └── crlf_results.txt
│   ├── cors/
│   │   └── cors_results.txt
│   ├── quick_checks/
│   │   ├── subdomain_takeover.txt
│   │   ├── s3_buckets.txt
│   │   └── git_exposed.txt
│   ├── REPORT.md
│   └── .recon_state/
└── recon.log
```

---

## 🛠️ Tool Requirements

### Core Tools (Required)

| Tool | Purpose | Installation |
|------|---------|--------------|
| subfinder | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass | Subdomain enumeration | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| dnsx | DNS resolution | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | HTTP probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| naabu | Port scanning | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |

### Optional Tools

| Tool | Purpose | Impact if Missing |
|------|---------|-------------------|
| nuclei | Vulnerability scanning | Phase 7 will be skipped (can be disabled) |
| nmap | Detailed port scanning | Less detailed port information |
| gowitness | Screenshots | No visual captures |

**Total Tools**: 50+

See [Installation](#-installation) section for complete list.

---

## ⚡ Performance Tuning

### For Fast Scans (Fewer Resources)

```bash
# Edit recon_v5.sh configuration:
MAX_CONCURRENT_JOBS=3
NAABU_RATE=1000
HTTPX_THREADS=50
KATANA_CONCURRENCY=25
```

### For Maximum Speed (More Resources)

```bash
# Edit recon_v5.sh configuration:
MAX_CONCURRENT_JOBS=10
NAABU_RATE=5000
HTTPX_THREADS=200
KATANA_CONCURRENCY=100
```

### Resource Recommendations

| Scan Type | RAM | CPU Cores | Disk Space |
|-----------|-----|-----------|------------|
| Quick | 4 GB | 2+ | 10 GB |
| Full | 8 GB | 4+ | 50 GB |
| Multiple Targets | 16 GB | 8+ | 100 GB |

---

## 🐛 Troubleshooting

### Common Issues

<details>
<summary><b>Tool Not Found</b></summary>

```bash
# Verify tool installation
which subfinder
which httpx

# Check Go PATH
echo $GOPATH
export PATH=$PATH:$GOPATH/bin

# Reinstall specific tool
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```
</details>

<details>
<summary><b>Permission Denied</b></summary>

```bash
# Make script executable
chmod +x recon_v5.sh

# For tools requiring sudo (install_v5.sh)
sudo bash install_v5.sh
```
</details>

<details>
<summary><b>Out of Memory</b></summary>

```bash
# Reduce concurrent jobs
MAX_CONCURRENT_JOBS=3

# Skip resource-intensive phases
# Disable Nuclei when prompted

# Monitor memory usage
watch -n 1 free -h
```
</details>

<details>
<summary><b>Script Hangs or Times Out</b></summary>

```bash
# Increase timeouts in configuration
TIMEOUT_SECONDS=5400
NMAP_TIMEOUT=7200

# Run with verbose logging to identify issue
./recon_v5.sh example.com --verbose

# Check log file
tail -f recon_v5_*/recon.log
```
</details>

<details>
<summary><b>Resume Not Working</b></summary>

```bash
# Check checkpoint file exists
ls -la recon_v5_*/.recon_state/

# Manually inspect checkpoint
cat recon_v5_*/.recon_state/checkpoint.txt

# If corrupted, remove and restart
rm -rf recon_v5_*/.recon_state/
```
</details>

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Issues

1. **Search** existing issues first
2. **Provide details**: OS, tool versions, error messages
3. **Include logs**: Relevant portions of `recon.log`
4. **Minimal reproduction**: Steps to reproduce the issue

### Submitting Pull Requests

1. **Fork** the repository
2. **Create branch**: `git checkout -b feature/amazing-feature`
3. **Follow style**: Maintain bash script conventions
4. **Test thoroughly**: Ensure no regressions
5. **Document changes**: Update README if needed
6. **Commit**: `git commit -m 'Add amazing feature'`
7. **Push**: `git push origin feature/amazing-feature`
8. **Open PR**: Provide clear description of changes

### Development Guidelines

- **Security First**: No `eval`, proper quoting, input validation
- **Error Handling**: Graceful failures, informative messages
- **Performance**: Optimize for speed without sacrificing reliability
- **Compatibility**: Test on Ubuntu 20.04+, Debian 10+, Kali Linux

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use
- ⚠️ Liability limitation
- ⚠️ Warranty disclaimer

---

## 👤 Author

**Shakibul Bokthiar (Shakibul_Cybersec)**

- 🌐 Portfolio: [Coming Soon]
- 💼 LinkedIn: [Your LinkedIn]
- 🐦 Twitter: [@YourTwitter]
- 📧 Email: your.email@example.com
- 🐛 Bug Bounty Profile: [Your HackerOne/Bugcrowd]

---

## 🙏 Acknowledgments

- **Tool Authors**: Thanks to all the amazing tool developers in the security community
- **ProjectDiscovery Team**: For exceptional reconnaissance tools
- **OWASP**: For security testing methodologies
- **Bug Bounty Community**: For continuous inspiration and knowledge sharing

---

## ⚠️ Disclaimer

**For Educational and Authorized Testing Only**

This tool is intended for:
- ✅ Authorized penetration testing
- ✅ Bug bounty programs with permission
- ✅ Security research in controlled environments
- ✅ Educational purposes

**DO NOT:**
- ❌ Use against systems without explicit permission
- ❌ Perform unauthorized access attempts
- ❌ Violate any laws or regulations
- ❌ Use for malicious purposes

**The author assumes no liability for misuse of this tool. Users are responsible for complying with all applicable laws and obtaining proper authorization before testing.**

---

## 📊 Project Stats

![GitHub stars](https://img.shields.io/github/stars/Shakibul-CyberSec/Bug-bounty-recon-pipeline?style=social)
![GitHub forks](https://img.shields.io/github/forks/Shakibul-CyberSec/Bug-bounty-recon-pipeline?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/Shakibul-CyberSec/Bug-bounty-recon-pipeline?style=social)

---

## 🗺️ Roadmap

- [ ] Web-based dashboard for results visualization
- [ ] Docker containerization for easy deployment
- [ ] Integration with notification services (Slack, Discord, Telegram)
- [ ] Custom plugin system for additional tools
- [ ] Machine learning for false positive reduction
- [ ] CI/CD integration examples
- [ ] Cloud deployment templates (AWS, GCP, Azure)

---

<div align="center">

### ⭐ If this project helps you, consider giving it a star!

Made with ❤️ by [Shakibul_Cybersec](https://github.com/Shakibul-CyberSec)

</div>
