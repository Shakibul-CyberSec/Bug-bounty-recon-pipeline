# 🎯 Bug Bounty Recon Pipeline v3.3

<div align="center">

![Version](https://img.shields.io/badge/version-3.3-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen.svg)

**Professional-Grade Reconnaissance & Vulnerability Discovery Pipeline**

*Fast • Comprehensive • Parallel • Reliable*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Tools](#-tools-included) • [Documentation](#-documentation)

</div>

---

## 📖 Overview

A complete, automated reconnaissance pipeline designed for bug bounty hunters and penetration testers. This toolkit combines multiple industry-standard tools into a streamlined workflow with intelligent resume capabilities, parallel processing, and comprehensive vulnerability scanning.

### 🎥 Demo

```bash
./recon.sh -d example.com -w wordlist.txt -r resolvers.txt
```

### ✨ Key Highlights

- 🚀 **Ultra-Fast**: Parallel processing with adaptive concurrency
- 🔄 **Resume Support**: Continue interrupted scans from checkpoints
- 🎯 **Comprehensive**: 15+ reconnaissance phases covering all attack surfaces
- 🛡️ **Proxy Support**: Built-in Tor integration for anonymous scanning
- 📊 **Smart Reporting**: Organized outputs with detailed statistics
- 🔧 **Customizable**: Flexible configuration for different scenarios
- 💾 **Resource-Aware**: Adaptive performance based on system resources

---

## 🚀 Features

### Core Capabilities

#### 🔍 **Subdomain Discovery**
- Multiple enumeration techniques (Subfinder, Assetfinder, Amass)
- DNS bruteforcing with custom wordlists
- Subdomain permutation and validation
- Historical subdomain discovery via Wayback Machine

#### 🌐 **Network Reconnaissance**
- Fast port scanning with Naabu
- Service detection with Nmap
- Banner grabbing and version identification
- SSL/TLS certificate analysis

#### 🔓 **Web Application Analysis**
- Live host detection with HttpX
- Technology fingerprinting
- Screenshot capture with Gowitness
- Favicon analysis

#### 🕷️ **URL Discovery**
- Web crawling with Katana
- Archive.org historical URLs (GAU, Waybackurls)
- JavaScript file discovery and analysis
- Parameter extraction and testing

#### 🔐 **Security Scanning**
- Sensitive file discovery (JS secrets, config files, backups)
- API key and token detection
- Subdomain takeover detection
- Directory bruteforcing

#### 📝 **Reporting**
- Organized directory structure
- Detailed logs for each phase
- Summary statistics
- Easy export and sharing

---

## 📋 Tools Included

### Subdomain Enumeration
- [Subfinder](https://github.com/projectdiscovery/subfinder) - Fast subdomain discovery
- [Assetfinder](https://github.com/tomnomnom/assetfinder) - Find related domains
- [Amass](https://github.com/OWASP/Amass) - In-depth DNS enumeration

### DNS & Network
- [PureDNS](https://github.com/d3mondev/puredns) - Fast domain resolver
- [DNSx](https://github.com/projectdiscovery/dnsx) - DNS toolkit
- [Naabu](https://github.com/projectdiscovery/naabu) - Fast port scanner
- [Nmap](https://nmap.org/) - Network exploration tool

### Web Analysis
- [HttpX](https://github.com/projectdiscovery/httpx) - HTTP toolkit
- [Gowitness](https://github.com/sensepost/gowitness) - Screenshot tool
- [Katana](https://github.com/projectdiscovery/katana) - Web crawler

### URL Discovery
- [GAU](https://github.com/lc/gau) - Fetch URLs from archives
- [Waybackurls](https://github.com/tomnomnom/waybackurls) - Wayback Machine URLs
- [Uro](https://github.com/s0md3v/uro) - URL deduplication

### Vulnerability Scanning
- [GF](https://github.com/tomnomnom/gf) - Pattern matching
- [Qsreplace](https://github.com/tomnomnom/qsreplace) - Query string manipulation
- [Subjack](https://github.com/haccer/subjack) - Subdomain takeover

### Custom Tools
- **JSScan** - Advanced JavaScript secret scanner
- **Down** - Parallel JavaScript downloader
- **URL-Extension** - Sensitive file filter

---

## 🛠️ Installation

### Prerequisites

- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Requirements**: 
  - Root/sudo access
  - 4GB+ RAM (recommended)
  - 10GB+ free disk space
  - Active internet connection

### Automated Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/recon-pipeline.git
cd recon-pipeline

# Make installation script executable
chmod +x install.sh

# Run the installer (requires sudo)
sudo ./install.sh
```

The installer will:
- ✅ Update system packages
- ✅ Install all required dependencies
- ✅ Install Go and Python tools
- ✅ Setup default wordlists and resolvers
- ✅ Configure Tor proxy
- ✅ Setup all custom tools

### Manual Installation

If you prefer manual installation:

```bash
# Install system dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget python3 python3-pip jq nmap chromium-browser tor

# Install Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install github.com/d3mondev/puredns/v2@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/sensepost/gowitness@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/haccer/subjack@latest

# Install Python tools
pip3 install uro --break-system-packages

# Install custom tools (from this repo)
sudo install -m 755 jsscan.sh /usr/local/bin/jsscan
sudo install -m 755 down.sh /usr/local/bin/down
sudo install -m 755 url-extension.sh /usr/local/bin/url-extension
```

### Verification

```bash
# Verify installation
./install.sh --check

# Or manually check key tools
subfinder -version
httpx -version
naabu -version
```

---

## 💻 Usage

### Basic Usage

```bash
# Simple scan with domain only
./recon.sh -d example.com

# Scan with custom wordlist
./recon.sh -d example.com -w /path/to/wordlist.txt

# Scan with custom resolvers
./recon.sh -d example.com -r /path/to/resolvers.txt

# Full custom configuration
./recon.sh -d example.com -w wordlist.txt -r resolvers.txt -f fingerprint.json
```

### Advanced Usage

```bash
# Resume interrupted scan
./recon.sh -d example.com --resume

# Clean resume and start fresh
./recon.sh -d example.com --clean-resume

# Specify custom output directory
./recon.sh -d example.com -o /path/to/output

# Dry run (check configuration without running)
./recon.sh -d example.com --dry-run
```

### Command-Line Options

```
Options:
  -d, --domain DOMAIN         Target domain (required)
  -w, --wordlist FILE         Custom subdomain wordlist
  -r, --resolvers FILE        Custom DNS resolvers file
  -f, --fingerprint FILE      Custom technology fingerprint file
  -o, --output DIR            Output directory (default: recon_DOMAIN_TIMESTAMP)
  --resume                    Resume from last checkpoint
  --clean-resume              Delete resume state and start fresh
  --no-proxy                  Disable proxy usage
  -h, --help                  Show help message
```

### Using Custom Tools

#### JSScan - JavaScript Secret Scanner

```bash
# Scan a directory of JS files
jsscan -d /path/to/js/files

# Scan with aggressive mode (more patterns)
jsscan -d /path/to/js/files --aggressive

# Scan single file
jsscan -f script.js

# Export results to JSON
jsscan -d /path/to/js/files -o results.json
```

#### Down - JavaScript Downloader

```bash
# Download JS files from URL list
down -u js_urls.txt -o js_files

# Custom parallel jobs and timeout
down -u js_urls.txt -o js_files -p 50 -t 30

# With retry count
down -u js_urls.txt -o js_files -r 3
```

#### URL-Extension - File Filter

```bash
# Filter sensitive file extensions
url-extension -f urls.txt -o filtered

# Custom output directory
url-extension -f urls.txt -o /path/to/output
```

---

## 📁 Directory Structure

After running a scan, the output directory will be organized as follows:

```
recon_example.com_20240215_120000/
├── .recon_state/                  # Resume system files
│   ├── checkpoint.txt             # Last completed phase
│   └── progress.log               # Detailed progress log
│
├── 01_subdomain_enum/             # Subdomain enumeration
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── amass.txt
│   └── all_subdomains.txt
│
├── 02_dns_bruteforce/             # DNS bruteforcing
│   ├── bruteforced.txt
│   └── permutations.txt
│
├── 03_dns_resolution/             # DNS resolution
│   ├── resolved.txt
│   └── dns_records.txt
│
├── 04_live_hosts/                 # Live host detection
│   ├── live_hosts.txt
│   └── technologies.json
│
├── 05_port_scan/                  # Port scanning
│   ├── naabu_results.txt
│   ├── nmap/
│   │   ├── scan_results.xml
│   │   └── scan_results.txt
│   └── open_ports_summary.txt
│
├── 06_screenshots/                # Visual recon
│   ├── screenshots/
│   └── gowitness.db
│
├── 07_url_discovery/              # URL collection
│   ├── katana_urls.txt
│   ├── gau_urls.txt
│   ├── wayback_urls.txt
│   └── all_urls.txt
│
├── 08_js_files/                   # JavaScript analysis
│   ├── success/                   # Downloaded JS files
│   ├── archive/                   # Archive.org files
│   └── secrets/                   # Found secrets
│
├── 09_parameters/                 # Parameter discovery
│   ├── parameters.txt
│   └── interesting_params.txt
│
├── 10_vulnerabilities/            # Vulnerability scanning
│   ├── xss_params.txt
│   ├── sqli_params.txt
│   ├── ssrf_params.txt
│   └── takeover_results.txt
│
├── 11_sensitive_files/            # Sensitive file discovery
│   ├── xls.txt
│   ├── pdf.txt
│   ├── config.txt
│   └── backups.txt
│
└── logs/                          # Execution logs
    ├── main.log
    ├── errors.log
    └── phase_*.log
```

---

## 🔄 Resume Feature

The pipeline includes an intelligent resume system that saves progress at each phase.

### How It Works

1. **Automatic Checkpointing**: After each phase completes, progress is saved
2. **Smart Recovery**: If interrupted, resume from the last checkpoint
3. **State Validation**: Ensures data integrity before resuming
4. **Clean Restart**: Option to clear state and start fresh

### Resume Commands

```bash
# Automatically resume if previous scan exists
./recon.sh -d example.com

# Force resume (recommended)
./recon.sh -d example.com --resume

# Clear resume state and start fresh
./recon.sh -d example.com --clean-resume
```

### Resume States

The system tracks these phases:
- Phase 1: Subdomain Enumeration
- Phase 2: DNS Bruteforcing
- Phase 3: DNS Resolution
- Phase 4: Live Host Detection
- Phase 5: Port Scanning
- Phase 6: Screenshots
- Phase 7: URL Discovery
- Phase 8: JavaScript Analysis
- Phase 9: Parameter Extraction
- Phase 10: Vulnerability Scanning
- Phase 11: Sensitive Files
- Phase 12: Final Report

---

## ⚙️ Configuration

### Default Resources

Default resources are stored in `/usr/share/default-recon-resources/`:

```
/usr/share/default-recon-resources/
├── subdomains-top1million-5000.txt  # Default wordlist
├── resolvers.txt                     # Default resolvers
└── fingerprint.json                  # Technology fingerprints
```

### Custom Wordlists

You can use custom wordlists for better results:

```bash
# Use SecLists wordlist
./recon.sh -d example.com -w /path/to/SecLists/Discovery/DNS/subdomains-top1million-110000.txt

# Use Assetnote wordlist
./recon.sh -d example.com -w /path/to/assetnote-wordlist.txt
```

Recommended wordlists:
- [SecLists](https://github.com/danielmiessler/SecLists)
- [Assetnote Wordlists](https://wordlists.assetnote.io/)
- [jhaddix all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)

### Custom Resolvers

For better DNS resolution:

```bash
# Use Trickest resolvers
./recon.sh -d example.com -r /path/to/resolvers.txt
```

Recommended resolver lists:
- [Trickest Resolvers](https://github.com/trickest/resolvers)
- [Public DNS Servers](https://public-dns.info/nameservers.txt)

### Performance Tuning

Edit these variables in `recon.sh`:

```bash
# Maximum parallel jobs
MAX_PARALLEL_JOBS=10

# Command timeout (seconds)
TIMEOUT_SECONDS=2700

# Nmap timeout (seconds)
NMAP_TIMEOUT=5400

# Naabu rate (packets per second)
NAABU_RATE=2000

# HttpX threads
HTTPX_THREADS=100

# Katana concurrency
KATANA_CONCURRENCY=50
```

---

## 🔒 Proxy Configuration

The pipeline supports Tor proxy for anonymous scanning.

### Setup Tor

```bash
# Install Tor
sudo apt install tor

# Start Tor service
sudo systemctl start tor
sudo systemctl enable tor

# Verify Tor is running
curl --socks5 127.0.0.1:9050 -Is https://check.torproject.org | grep -i "congratulations"
```

### Using Proxy

```bash
# Proxy is used by default if Tor is running
./recon.sh -d example.com

# Disable proxy
./recon.sh -d example.com --no-proxy
```

---

## 📊 Output Examples

### Subdomain Enumeration
```
[*] Phase 1: Subdomain Enumeration
[+] Subfinder found: 245 subdomains
[+] Assetfinder found: 189 subdomains
[+] Amass found: 312 subdomains
[✓] Total unique subdomains: 521
```

### Live Host Detection
```
[*] Phase 4: Live Host Detection
[+] Checking 521 subdomains...
[✓] Found 178 live hosts
[+] Technologies detected:
    • Cloudflare: 45 hosts
    • nginx: 67 hosts
    • Apache: 23 hosts
```

### JavaScript Secrets
```
[*] Phase 8: JavaScript Analysis
[+] Downloaded 423 JavaScript files
[+] Scanning for secrets...
[✓] Found secrets:
    • AWS Keys: 3
    • API Keys: 12
    • JWT Tokens: 7
    • Database URLs: 2
```

---

## 🎯 Best Practices

### Pre-Scan Checklist
- [ ] Verify you have permission to scan the target
- [ ] Ensure adequate disk space (10GB+ recommended)
- [ ] Check internet connection stability
- [ ] Review and customize wordlists if needed
- [ ] Verify all tools are installed (`./install.sh --check`)

### During Scan
- Monitor resource usage (`htop`, `free -h`)
- Check logs for errors (`tail -f logs/main.log`)
- Use `--resume` if scan is interrupted

### Post-Scan
- Review all findings manually
- Validate discovered vulnerabilities
- Organize results by severity
- Archive scan data for future reference

### Responsible Disclosure
- Always obtain permission before scanning
- Follow responsible disclosure guidelines
- Report findings ethically
- Respect scope and boundaries

---

## 🐛 Troubleshooting

### Common Issues

#### Tool Not Found
```bash
# Problem: Command not found
# Solution: Ensure Go/Python bin directories are in PATH
echo 'export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin' >> ~/.bashrc
source ~/.bashrc
```

#### Permission Denied
```bash
# Problem: Permission denied on scripts
# Solution: Make scripts executable
chmod +x recon.sh install.sh
```

#### Out of Memory
```bash
# Problem: Script crashes due to memory
# Solution: Reduce concurrency in recon.sh
MAX_PARALLEL_JOBS=5  # Reduce from 10
```

#### DNS Resolution Fails
```bash
# Problem: DNS resolution errors
# Solution: Use better resolvers
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
./recon.sh -d example.com -r resolvers.txt
```

#### Proxy Not Working
```bash
# Problem: Tor proxy connection fails
# Solution: Restart Tor service
sudo systemctl restart tor
sudo systemctl status tor
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Bugs
1. Check if the bug is already reported in [Issues](https://github.com/yourusername/recon-pipeline/issues)
2. Create a detailed bug report with:
   - System information (OS, version)
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs

### Suggesting Features
1. Open a [Feature Request](https://github.com/yourusername/recon-pipeline/issues/new)
2. Describe the feature and its use case
3. Explain why it would be valuable

### Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style
- Use clear, descriptive variable names
- Add comments for complex logic
- Follow existing code structure
- Test thoroughly before submitting

---

## 📝 Changelog

### v3.3 (Current)
- ✅ Added resume feature with checkpointing
- ✅ Improved error handling and retry logic
- ✅ Enhanced JavaScript secret scanning
- ✅ Added archive.org fallback for JS files
- ✅ Better resource management
- ✅ Comprehensive logging system

### v3.2
- Added proxy support with Tor
- Improved parallel processing
- Added technology fingerprinting
- Enhanced screenshot capture

### v3.1
- Initial public release
- Basic reconnaissance pipeline
- Subdomain enumeration
- Port scanning
- URL discovery

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use
- ❌ Liability
- ❌ Warranty

---

## ⚠️ Disclaimer

**IMPORTANT**: This tool is for educational and authorized testing purposes only.

- ✅ **DO**: Use on systems you own or have explicit permission to test
- ✅ **DO**: Follow responsible disclosure practices
- ✅ **DO**: Respect scope and boundaries
- ❌ **DON'T**: Use for unauthorized scanning
- ❌ **DON'T**: Attack systems without permission
- ❌ **DON'T**: Use for malicious purposes

**By using this tool, you agree to:**
1. Only test systems you own or have written permission to test
2. Comply with all applicable laws and regulations
3. Take full responsibility for your actions
4. Not hold the authors liable for any misuse

**The authors and contributors are not responsible for any misuse or damage caused by this tool.**

---

## 👤 Author

**Shakibul (Shakibul_Cybersec)**

- GitHub: [@yourusername](https://github.com/yourusername)
- Twitter: [@yourtwitter](https://twitter.com/yourtwitter)
- Website: [yourwebsite.com](https://yourwebsite.com)

---

## 🌟 Acknowledgments

Special thanks to:
- ProjectDiscovery for their amazing tools
- Tom Hudson (tomnomnom) for essential utilities
- OWASP Amass team
- The bug bounty community
- All contributors and supporters

---

## 📚 Resources

### Learning Materials
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)
- [Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Similar Projects
- [Reconftw](https://github.com/six2dez/reconftw)
- [AutoRecon](https://github.com/Tib3rius/AutoRecon)
- [LazyRecon](https://github.com/capt-meelo/LazyRecon)

### Bug Bounty Platforms
- [HackerOne](https://hackerone.com)
- [Bugcrowd](https://bugcrowd.com)
- [Intigriti](https://intigriti.com)
- [YesWeHack](https://yeswehack.com)

---

## ⭐ Star History

If you find this project useful, please consider giving it a star! ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/recon-pipeline&type=Date)](https://star-history.com/#yourusername/recon-pipeline&Date)

---

<div align="center">

**Made with ❤️ for the Bug Bounty Community**

[⬆ Back to Top](#-bug-bounty-recon-pipeline-v33)

</div>
