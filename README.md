# Bug Bounty Reconnaissance Pipeline

> **Professional-grade reconnaissance automation for security researchers and bug bounty hunters**

Ultra-fast, security-hardened reconnaissance pipeline with 17 specialized phases covering subdomain enumeration to vulnerability assessment. Built for reliability, scalability, and actionable intelligence gathering.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/releases)
[![Bash](https://img.shields.io/badge/bash-5.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Tools](https://img.shields.io/badge/tools-35%2B-brightgreen.svg)](#complete-tool-inventory)

---

## Key Features

- **17-Phase Pipeline Architecture**: From subdomain discovery to vulnerability assessment
- **35+ Security Tools**: Industry-standard tools working in concert
- **Resume Capability**: Intelligent checkpoint system for interrupted scans
- **Parallel Processing**: Configurable concurrency for optimal performance
- **Smart Rate Limiting**: Exponential backoff prevents API throttling
- **CDN Detection**: Intelligent IP classification to reduce scan noise
- **Tor Integration**: Optional anonymization via Tor network
- **Production Hardened**: Proper error handling, input sanitization, secure coding practices

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| **Operating System** | Linux/Unix (Ubuntu 24.04 recommended) |
| **Privileges** | Root/sudo access for installation |
| **Memory** | Minimum 2GB RAM |
| **Storage** | 10GB free disk space |
| **Network** | Stable internet connection |

---

## Installation

### Quick Start

```bash
# Clone repository
git clone https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline.git
cd Bug-bounty-recon-pipeline

# Set permissions
chmod +x install.sh recon.sh

# Run installer (requires sudo)
sudo ./install.sh
```

### What Gets Installed

The automated installer will:
- Install all 35 required security tools
- Configure Go environment and install Go-based tools
- Set up default wordlists (5000 subdomains)
- Configure DNS resolvers
- Download Nuclei templates
- Configure Tor proxy (optional)
- Install custom local tools (jsscan, down, url-extension)

**Installation Time**: ~10-15 minutes depending on internet speed

---

## Usage

### Basic Commands

```bash
# Single domain scan
./recon.sh target.com

# Verbose output mode
./recon.sh target.com --verbose

# Multiple targets from file
./recon.sh targets.txt

# Resume interrupted scan
./recon.sh
# (automatically detects incomplete scans)
```

### Target File Format

```text
# targets.txt (one domain per line)
example.com
test.com
demo.com
```

### Interactive Prompts

During execution, the pipeline will prompt for:
- **Tor Usage**: Enable/disable Tor anonymization
- **Port Scan Strategy**: Smart scan, full scan, quick scan, or skip
- **Nuclei Scan**: Run comprehensive vulnerability scan or skip

---

## Pipeline Architecture

### 17-Phase Reconnaissance Workflow

| Phase | Name | Tools | Output Files |
|-------|------|-------|--------------|
| **1** | **Subdomain Enumeration** | subfinder, assetfinder, crt.sh, amass, puredns, dnsx, dnsgen | `all_subdomains.txt`, `subfinder.txt`, `assetfinder.txt`, `crt.txt`, `amass_passive.txt`, `puredns.txt`, `dnsgen_resolved.txt` |
| **2** | **Port Scanning** | naabu, nmap, dig | `portscan/naabu_results.txt`, `portscan/nmap_scan.nmap`, `portscan/ip_analysis.txt`, `portscan/cdn_hosts.txt` |
| **3** | **HTTP Probing** | httpx | `alive_subdomains.txt`, `alive_subdomains_http.txt`, `alive_subdomains_https.txt` |
| **4** | **URL Collection** | gau, katana, url-extension | `urls/gau.txt`, `urls/katana.txt`, `all_urls.txt`, `filtered-url-extention/*` |
| **5** | **JavaScript Analysis** | down, jsscan, httpx | `javascript/js_urls.txt`, `javascript/filtered_js_urls.txt`, `javascript/secrets.txt`, `javascript/endpoints.txt`, `javascript/source_maps.txt` |
| **5.5** | **API Discovery** | gf, qsreplace | `api_discovery/api_endpoints.txt` |
| **5.6** | **Cloud Asset Discovery** | cloud_enum | `cloud_assets/cloud_resources.txt` |
| **5.7** | **WAF Detection** | wafw00f | `waf_detection/waf_results.txt` |
| **6** | **Nuclei Vulnerability Scan** | nuclei | `nuclei_scan/nuclei_results.txt` |
| **7** | **Vulnerability Pattern Matching** | gf | `vulnerability_scan/sqli.txt`, `vulnerability_scan/xss.txt`, `vulnerability_scan/ssrf.txt`, `vulnerability_scan/lfi.txt` |
| **8** | **DNS Reconnaissance** | dig, dnsrecon, whois | `network/dns_records.txt`, `network/whois_info.txt`, `network/subdomain_dig/*`, `network/subdomain_whois/*` |
| **9** | **Visual Screenshots** | gowitness | `gowitness_screenshots/*.png` |
| **10** | **Technology Fingerprinting** | curl, jq, custom fingerprints | `technology/tech_stack.json`, `technology/tech_summary.txt` |
| **11** | **Parameter Discovery** | grep, awk (custom) | `parameters/unique_params.txt`, `parameters/cat_redirect.txt`, `parameters/cat_file_path.txt`, `parameters/cat_idor.txt`, `parameters/cat_injection.txt`, `parameters/param_urls.txt` |
| **12** | **Parameter Fuzzing** | arjun | `param_fuzzing/arjun_params.txt`, `parameters/all_params_merged.txt` |
| **13** | **CORS Testing** | curl (custom) | `cors_testing/cors_results.txt` |
| **14** | **Quick Security Checks** | subjack, curl | `subdomain_takeover.txt`, `s3_buckets.txt`, `git_exposed.txt` |

---

## Output Structure

```
recon_v5_YYYYMMDD_HHMMSS/
  |
  +-- target.com/
       |
       +-- all_subdomains.txt              # All discovered subdomains
       +-- alive_subdomains.txt            # Live subdomains
       +-- alive_subdomains_http.txt       # HTTP endpoints
       +-- alive_subdomains_https.txt      # HTTPS endpoints
       +-- all_urls.txt                    # All collected URLs
       |
       +-- portscan/                       # Phase 2: Port scanning
       |    +-- ip_analysis.txt            # CDN vs Origin IP classification
       |    +-- cdn_hosts.txt              # Hosts behind CDN
       |    +-- likely_origin_hosts.txt    # Direct origin IPs
       |    +-- naabu_results.txt          # All open ports
       |    +-- nmap_scan.nmap             # Service detection results
       |    +-- cdn_summary.txt            # Port scan strategy summary
       |
       +-- urls/                           # Phase 4: URL collection
       |    +-- gau.txt                    # Archive URLs
       |    +-- katana.txt                 # Crawled URLs
       |
       +-- filtered-url-extention/         # URLs filtered by extension
       |    +-- php.txt
       |    +-- asp.txt
       |    +-- jsp.txt
       |    +-- ... (other extensions)
       |
       +-- javascript/                     # Phase 5: JS analysis
       |    +-- js_urls.txt                # All JS files found
       |    +-- filtered_js_urls.txt       # Interesting JS files
       |    +-- high_priority_js.txt       # High-value targets
       |    +-- secrets.txt                # Potential secrets/keys
       |    +-- endpoints.txt              # API endpoints from JS
       |    +-- source_maps.txt            # Source map files
       |    +-- js_files/                  # Downloaded JS files
       |    +-- summary.txt                # Analysis summary
       |
       +-- api_discovery/                  # Phase 5.5: API endpoints
       |    +-- api_endpoints.txt
       |
       +-- cloud_assets/                   # Phase 5.6: Cloud resources
       |    +-- cloud_resources.txt
       |
       +-- waf_detection/                  # Phase 5.7: WAF info
       |    +-- waf_results.txt
       |
       +-- nuclei_scan/                    # Phase 6: Nuclei results
       |    +-- nuclei_results.txt
       |
       +-- vulnerability_scan/             # Phase 7: Pattern matching
       |    +-- sqli.txt
       |    +-- xss.txt
       |    +-- ssrf.txt
       |    +-- lfi.txt
       |    +-- redirect.txt
       |    +-- rce.txt
       |
       +-- network/                        # Phase 8: DNS recon
       |    +-- dns_records.txt
       |    +-- whois_info.txt
       |    +-- subdomains/
       |    +-- subdomain_dig/
       |    +-- subdomain_whois/
       |
       +-- gowitness_screenshots/          # Phase 9: Screenshots
       |    +-- *.png
       |
       +-- technology/                     # Phase 10: Tech detection
       |    +-- tech_stack.json
       |    +-- tech_summary.txt
       |
       +-- parameters/                     # Phase 11: Parameters
       |    +-- unique_params.txt          # All unique parameters
       |    +-- url_params.txt             # From URLs
       |    +-- js_params.txt              # From JavaScript
       |    +-- cat_redirect.txt           # Redirect parameters
       |    +-- cat_file_path.txt          # File/path parameters
       |    +-- cat_idor.txt               # IDOR parameters
       |    +-- cat_injection.txt          # Injection-prone params
       |    +-- cat_api_debug.txt          # API/debug parameters
       |    +-- param_urls.txt             # Test URLs with params
       |
       +-- param_fuzzing/                  # Phase 12: Fuzzing
       |    +-- arjun_params.txt
       |    +-- all_params_merged.txt
       |
       +-- cors_testing/                   # Phase 13: CORS
       |    +-- cors_results.txt
       |
       +-- reports/                        # Final reports
       |    +-- final_report.html
       |
       +-- .recon_state/                   # Resume capability
       |    +-- checkpoint.txt
       |    +-- progress.log
       |
       +-- subdomain_takeover.txt          # Phase 14: Quick checks
       +-- s3_buckets.txt
       +-- git_exposed.txt
       +-- errors.log                      # Error tracking
       +-- recon.log                       # Detailed execution log

  +-- recon.log                            # Main log file
```

---

## Configuration

### Performance Tuning

Edit `recon.sh` to customize performance parameters:

```bash
# Parallel execution
MAX_CONCURRENT_JOBS=5          # Background job limit (default: 5)
MAX_PARALLEL_JOBS=10           # Tool-specific parallelization

# Timeouts
TIMEOUT_SECONDS=2700           # General phase timeout (45 min)
NMAP_TIMEOUT=5400              # Nmap timeout (90 min)
NUCLEI_TIMEOUT=7200            # Nuclei timeout (120 min)

# Tool-specific rates
NAABU_RATE=2000                # Port scan packets/sec
HTTPX_THREADS=100              # HTTP probing threads
KATANA_CONCURRENCY=50          # Crawler concurrency
NUCLEI_RATE_LIMIT=150          # Nuclei requests/sec
NUCLEI_CONCURRENCY=25          # Nuclei parallel templates
```

### Resource Paths

```bash
# Default resource locations
DEFAULT_RESOURCE_DIR="/usr/share/default-recon-resources"
DEFAULT_WORDLIST="$DEFAULT_RESOURCE_DIR/subdomains-top1million-5000.txt"
DEFAULT_RESOLVERS="$DEFAULT_RESOURCE_DIR/resolvers.txt"
DEFAULT_FINGERPRINT="$DEFAULT_RESOURCE_DIR/fingerprint.json"
```

---

## Complete Tool Inventory

### System Essentials (7)
- `python3` - Python runtime
- `go` - Go compiler & runtime
- `pip3` - Python package manager
- `git` - Version control
- `curl` - HTTP client
- `wget` - File downloader
- `jq` - JSON processor

### Network & Proxy (2)
- `proxychains` - Proxy chains
- `tor` - Tor network client

### Browser Automation (1)
- `chromium` - Headless browser for screenshots

### Reconnaissance Tools (18)
- `subfinder` - Subdomain enumeration (passive)
- `assetfinder` - Asset discovery
- `amass` - In-depth DNS enumeration
- `puredns` - DNS brute forcing & resolution
- `dnsx` - Fast DNS toolkit
- `dnsgen` - Subdomain permutation generator
- `naabu` - Port scanner
- `nmap` - Network mapper & service detection
- `httpx` - HTTP toolkit & probing
- `gowitness` - Web screenshot tool
- `gau` - Archive URL collector (GetAllUrls)
- `katana` - Web crawler
- `uro` - URL deduplicator
- `gf` - Grep with pattern matching
- `qsreplace` - Query string replacer
- `dnsrecon` - DNS reconnaissance
- `whois` - Domain WHOIS lookup
- `subjack` - Subdomain takeover checker

### Vulnerability & Security (4)
- `nuclei` - Vulnerability scanner
- `arjun` - HTTP parameter discovery
- `wafw00f` - WAF detection
- `cloud_enum` - Cloud asset discovery

### Custom Local Tools (3)
- `jsscan` - JavaScript secret scanner
- `down` - Parallel file downloader
- `url-extension` - URL extension filter

**Total: 35 Tools**

---

## Security Features

### Secure Coding Practices
- No use of `eval` or code injection vectors
- Proper variable quoting throughout
- Input validation and sanitization
- Secure temporary file handling
- Safe file parsing (no `source` on user data)

### Operational Security
- Centralized job control with timeout management
- Exponential backoff rate limiting
- Error isolation and logging
- Graceful failure handling
- Resource cleanup on exit

### Privacy & Anonymity
- Optional Tor integration
- Proxy support (HTTP/SOCKS)
- Configurable user agents
- Rate limiting to avoid detection

---

## Troubleshooting

### Common Issues & Solutions

#### Tool Not Found
```bash
# Issue: Command not found after installation
# Solution: Reload shell environment
source ~/.bashrc
# or restart terminal
```

#### Permission Denied
```bash
# Issue: Permission denied errors
# Solution: Ensure scripts are executable
chmod +x install.sh recon.sh
```

#### Out of Memory
```bash
# Issue: System running out of memory
# Solution: Reduce concurrent jobs
# Edit recon.sh:
MAX_CONCURRENT_JOBS=3  # Reduce from 5 to 3
```

#### Go Tools Not in PATH
```bash
# Issue: Go-based tools not found
# Solution: Add Go bin to PATH
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin
echo 'export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin' >> ~/.bashrc
```

#### Nuclei Templates Missing
```bash
# Issue: Nuclei templates not found
# Solution: Update templates manually
nuclei -update-templates
```

#### Tor Connection Failed
```bash
# Issue: Tor proxy not working
# Solution: Check and restart Tor service
sudo systemctl status tor
sudo systemctl restart tor
# Test connection:
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

#### Resume Not Working
```bash
# Issue: Unable to resume interrupted scan
# Solution: Check checkpoint file integrity
cat recon_v5_*/target.com/.recon_state/checkpoint.txt
# If corrupted, remove state and restart:
rm -rf recon_v5_*/target.com/.recon_state
```

---

## Contributing

Contributions are welcome! Here's how you can help:

### How to Contribute

1. **Fork the Repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/Bug-bounty-recon-pipeline.git
   cd Bug-bounty-recon-pipeline
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make Your Changes**
   - Follow existing code style
   - Add comments for complex logic
   - Test thoroughly

4. **Commit Changes**
   ```bash
   git commit -m 'Add amazing feature'
   ```

5. **Push to Branch**
   ```bash
   git push origin feature/amazing-feature
   ```

6. **Open Pull Request**
   - Describe your changes
   - Link any related issues

### Contribution Guidelines

- Test on Ubuntu 24.04 LTS
- Ensure backward compatibility
- Follow bash best practices
- Update documentation
- Add error handling

---

## License

This project is licensed under the **MIT License**.

**Key Points:**
- Free to use, modify, distribute
- Include original license in copies
- No warranty provided

See [LICENSE](LICENSE) file for full details.

---

## Acknowledgments

### Development Partners
- **Claude (Anthropic)** - Code development, optimization, and architecture
- **DeepSeek** - Problem-solving and algorithm design
- **ChatGPT (OpenAI)** - Documentation and testing assistance

### Open Source Community
Special thanks to the developers and maintainers of all 35 security tools integrated into this pipeline. Your tools make this project possible.

### Security Research Community
Thanks to the bug bounty hunters, penetration testers, and security researchers who continuously push the boundaries of web security.

---

## Author

**Shakibul**  
Security Researcher & Developer

- Twitter: [@Shakibul_Cybersec](https://twitter.com/Shakibul_Cybersec)
- GitHub: [@Shakibul-CyberSec](https://github.com/Shakibul-CyberSec)

---

## Show Your Support

If this project helped you in your bug bounty journey or security research, please consider:

- Star this repository
- Share on Twitter
- Spread the word

---

## Legal Disclaimer

### Important Notice

**This tool is intended for AUTHORIZED SECURITY TESTING ONLY.**

#### You Must:
- Obtain explicit written permission before scanning any target
- Stay within the scope of authorization
- Comply with applicable laws and regulations
- Respect target's terms of service and rate limits
- Report findings responsibly

#### You Must Not:
- Scan targets without proper authorization
- Use for malicious purposes
- Violate computer fraud laws
- Cause denial of service
- Access unauthorized systems

### Liability

**The authors and contributors of this tool:**
- Do NOT authorize illegal activity
- Do NOT condone unauthorized access
- Are NOT responsible for misuse
- Are NOT liable for damages caused by improper use

**By using this tool, you agree:**
- You are solely responsible for your actions
- You have proper authorization for all targets
- You will use the tool in compliance with all applicable laws
- The authors are held harmless from any consequences of your use

### Warning

**Unauthorized computer access is illegal in most jurisdictions and may result in:**
- Criminal prosecution
- Civil liability
- Fines and penalties
- Imprisonment

**Use at your own risk. Stay legal. Stay ethical.**

---

## Support

### Getting Help

- Read the documentation thoroughly before asking questions
- **Bug reports**: Open an issue on GitHub
- **Feature requests**: Open an issue with [Feature Request] tag
- **General discussion**: Use GitHub Discussions

### Response Time

- Critical bugs: 24-48 hours
- Feature requests: 1-2 weeks
- General questions: Best effort

---

<div align="center">

**Happy Hunting!**

*Built with care for the bug bounty and infosec community*

[Report Issues](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/issues) • [Request Features](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/issues/new) • [View Documentation](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline)

</div>
