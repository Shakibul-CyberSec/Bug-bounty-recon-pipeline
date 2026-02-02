# Quick Start Guide

Get up and running with Bug Bounty Recon Pipeline in under 5 minutes!

## 🚀 30-Second Quick Start

```bash
# 1. Clone repository
git clone https://github.com/yourusername/recon-pipeline.git && cd recon-pipeline

# 2. Install (requires sudo)
sudo ./install.sh

# 3. Run first scan (requires permission!)
./recon.sh -d yourdomain.com
```

Done! Check `recon_yourdomain.com_*/` for results.

---

## 📦 Installation (5 minutes)

### Automated Installation

```bash
git clone https://github.com/yourusername/recon-pipeline.git
cd recon-pipeline
chmod +x install.sh
sudo ./install.sh
```

### Verify Installation

```bash
./install.sh --check
```

---

## 💻 Basic Usage

### Simple Scan

```bash
./recon.sh -d example.com
```

### With Custom Wordlist

```bash
./recon.sh -d example.com -w /path/to/wordlist.txt
```

### With Custom Resolvers

```bash
./recon.sh -d example.com -r /path/to/resolvers.txt
```

### Full Custom Configuration

```bash
./recon.sh -d example.com \
  -w wordlist.txt \
  -r resolvers.txt \
  -f fingerprint.json \
  -o custom_output
```

---

## 🔄 Resume Feature

Interrupted scan? No problem!

```bash
# Automatically resumes
./recon.sh -d example.com

# Force resume
./recon.sh -d example.com --resume

# Start fresh
./recon.sh -d example.com --clean-resume
```

---

## 🛠️ Custom Tools

### JSScan - Find Secrets in JS

```bash
# Scan directory
jsscan -d /path/to/js_files

# Single file
jsscan -f script.js

# Aggressive mode
jsscan -d /path/to/js_files --aggressive

# JSON output
jsscan -d /path/to/js_files -o results.json
```

### Down - Download JS Files

```bash
# Basic
down -u urls.txt

# Custom settings
down -u urls.txt -o output -p 50 -t 20 -r 3
```

### URL-Extension - Filter Files

```bash
# Basic
url-extension -f urls.txt

# Custom output
url-extension -f urls.txt -o filtered
```

---

## 📁 Output Structure

```
recon_example.com_20240215_120000/
├── 01_subdomain_enum/      # Subdomains found
├── 02_dns_bruteforce/      # Bruteforced domains
├── 03_dns_resolution/      # Resolved IPs
├── 04_live_hosts/          # Live HTTP/HTTPS
├── 05_port_scan/           # Open ports
├── 06_screenshots/         # Visual recon
├── 07_url_discovery/       # All URLs
├── 08_js_files/            # JavaScript files
│   └── secrets/            # Found secrets
├── 09_parameters/          # URL parameters
├── 10_vulnerabilities/     # Vulnerabilities
├── 11_sensitive_files/     # Sensitive files
└── logs/                   # Execution logs
```

---

## 🎯 Common Workflows

### Workflow 1: Quick Recon

```bash
# Default scan
./recon.sh -d target.com

# Check results
cd recon_target.com_*
cat 01_subdomain_enum/all_subdomains.txt
cat 04_live_hosts/live_hosts.txt
```

### Workflow 2: JS Analysis

```bash
# Run full scan
./recon.sh -d target.com

# Scan JS for secrets
cd recon_target.com_*/08_js_files
jsscan -d success/ > secrets.txt
cat secrets.txt
```

### Workflow 3: Parameter Testing

```bash
# Get parameters
./recon.sh -d target.com
cd recon_target.com_*

# Test for XSS
cat 09_parameters/parameters.txt | \
  qsreplace '"><script>alert(1)</script>' > xss_test.txt
```

---

## 🔧 Configuration

### Performance Tuning

Edit `recon.sh` (around line 22-32):

```bash
# For low-resource systems
MAX_PARALLEL_JOBS=5
HTTPX_THREADS=50
KATANA_CONCURRENCY=25

# For high-resource systems
MAX_PARALLEL_JOBS=20
HTTPX_THREADS=200
KATANA_CONCURRENCY=100
```

### Proxy Setup

```bash
# Ensure Tor is running
sudo systemctl start tor

# Verify
curl --socks5 127.0.0.1:9050 https://check.torproject.org

# Scan with proxy (automatic)
./recon.sh -d target.com

# Disable proxy
./recon.sh -d target.com --no-proxy
```

---

## 🐛 Quick Troubleshooting

### "Command not found"

```bash
# Add Go bin to PATH
export PATH=$PATH:$HOME/go/bin
source ~/.bashrc
```

### "Permission denied"

```bash
chmod +x recon.sh install.sh
```

### "Tool X not found"

```bash
# Reinstall
sudo ./install.sh

# Or install specific tool
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### "Out of memory"

```bash
# Reduce concurrency in recon.sh
MAX_PARALLEL_JOBS=5
```

---

## 📚 Next Steps

### Learn More
- **Detailed Guide**: Read [USAGE.md](USAGE.md)
- **Examples**: Check [examples/](examples/) directory
- **Troubleshooting**: See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

### Get Help
- **Issues**: [GitHub Issues](https://github.com/yourusername/recon-pipeline/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/recon-pipeline/discussions)

### Contribute
- Read [CONTRIBUTING.md](CONTRIBUTING.md)
- Check [open issues](https://github.com/yourusername/recon-pipeline/issues)
- Submit pull requests

---

## ⚠️ Important Reminders

### Before Scanning

- ✅ **Get Permission**: Only scan authorized targets
- ✅ **Check Scope**: Verify what's in scope
- ✅ **Read Rules**: Follow program guidelines
- ✅ **Use Responsibly**: Respect rate limits

### Security

- 🔒 Protect discovered secrets
- 🔒 Secure scan results
- 🔒 Follow responsible disclosure
- 🔒 Don't share sensitive data

---

## 🎓 Learning Resources

### Recommended Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists)
- [Assetnote](https://wordlists.assetnote.io/)
- [jhaddix all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)

### Recommended Resolvers
- [Trickest Resolvers](https://github.com/trickest/resolvers)
- [Public DNS](https://public-dns.info/nameservers.txt)

### Bug Bounty Resources
- [HackerOne](https://hackerone.com)
- [Bugcrowd](https://bugcrowd.com)
- [Web Security Academy](https://portswigger.net/web-security)
- [OWASP](https://owasp.org)

---

## 💡 Pro Tips

### Speed Up Scans
1. Use fast resolvers
2. Reduce wordlist size for testing
3. Skip nmap for speed
4. Increase concurrency (if resources allow)

### Better Results
1. Use comprehensive wordlists
2. Enable aggressive JS scanning
3. Let scans complete fully
4. Review all findings manually

### Stay Organized
1. Use consistent naming
2. Archive old scans
3. Keep notes
4. Track findings in spreadsheet

---

## 🌟 Quick Reference

### Main Commands

| Command | Description |
|---------|-------------|
| `./recon.sh -d domain.com` | Basic scan |
| `./recon.sh -d domain.com --resume` | Resume scan |
| `jsscan -d js_files/` | Scan JS files |
| `down -u urls.txt` | Download JS |
| `url-extension -f urls.txt` | Filter URLs |

### Important Paths

| Path | Contents |
|------|----------|
| `/usr/share/default-recon-resources/` | Default wordlists/resolvers |
| `$HOME/go/bin/` | Go tools |
| `/usr/local/bin/` | Custom tools |
| `recon_DOMAIN_*/` | Scan results |

### Key Files

| File | Purpose |
|------|---------|
| `recon.sh` | Main script |
| `install.sh` | Installer |
| `jsscan.sh` | JS scanner |
| `README.md` | Main docs |
| `USAGE.md` | Detailed guide |

---

## ✅ Checklist for First Scan

- [ ] Installed all tools (`./install.sh`)
- [ ] Verified installation (`./install.sh --check`)
- [ ] Have permission to scan target
- [ ] Read program rules and scope
- [ ] Adequate disk space (10GB+)
- [ ] Stable internet connection
- [ ] Ready to wait (scans take time)

---

**Ready to start?**

```bash
./recon.sh -d yourdomain.com
```

**Happy Hacking! 🚀**

---

*For detailed information, see [README.md](README.md) and [USAGE.md](USAGE.md)*
