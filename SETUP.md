# Setup Guide

Complete installation and configuration guide for the Bug Bounty Recon Pipeline.

## Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04+ (or Debian-based Linux)
- **RAM**: Minimum 2GB, recommended 4GB+
- **Storage**: 10GB free space
- **Network**: Stable internet connection
- **Permissions**: Root/sudo access

### Check System Resources
```bash
# Check RAM
free -h

# Check disk space
df -h

# Check Ubuntu version
lsb_release -a
```

## Installation Steps

### 1. Clone Repository
```bash
git clone https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline.git
cd Bug-bounty-recon-pipeline
```

### 2. Make Scripts Executable
```bash
chmod +x install.sh
chmod +x recon.sh
```

### 3. Run Installer
```bash
sudo ./install.sh
```

The installer will:
1. Update system packages
2. Install Go programming language
3. Install Python3 and pip3
4. Install 50+ security tools
5. Set up default wordlists,resolvers and fingerprints.json
6. Configure Tor proxy
7. Download Nuclei templates

**Note**: Installation may take 10-15 minutes depending on your internet speed.

### 4. Verify Installation
```bash
# Check if all tools are installed
subfinder -version
nuclei -version
httpx -version
naabu -version
.....
```

## Post-Installation Configuration

### Update PATH (if needed)
If tools aren't found, add to your shell config:

**For Bash** (~/.bashrc):
```bash
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH
```

**For Zsh** (~/.zshrc):
```bash
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH
```

Reload shell:
```bash
source ~/.bashrc  # or source ~/.zshrc
```

### Nuclei Templates
Update Nuclei templates regularly:
```bash
nuclei -update-templates
```

### Tor Configuration (Optional)
Enable Tor for anonymized scanning:
```bash
# Start Tor service
sudo systemctl start tor
sudo systemctl enable tor

# Test Tor connection
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

## Default Resource Locations

- **Wordlists**: `/usr/share/default-recon-resources/subdomains-top1million-5000.txt`
- **Resolvers**: `/usr/share/default-recon-resources/resolvers.txt`
- **Fingerprints**: `/usr/share/default-recon-resources/fingerprint.json`
- **Go Tools**: `$HOME/go/bin/`
- **Nuclei Templates**: `$HOME/nuclei-templates/`

## First Run

### Basic Test
```bash
# Test with a domain
./recon.sh example.com
```

### With Verbose Mode
```bash
# See detailed output
./recon.sh example.com --verbose
```

## Common Installation Issues

### Issue: Go Not Found
```bash
# Verify Go installation
/usr/local/go/bin/go version

# If not installed, manually install
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
```

### Issue: Tool Installation Failed
```bash
# Reinstall specific tool
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Or use apt
sudo apt install nmap
```

### Issue: Permission Denied
```bash
# Fix script permissions
chmod +x *.sh

# Fix ownership
sudo chown -R $USER:$USER ~/go
```

### Issue: Out of Memory
```bash
# Increase swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Updating

### Update Script
```bash
cd Bug-bounty-recon-pipeline
git pull origin main
```

### Update Tools
```bash
# Update Go tools
go get -u all

# Update Nuclei templates
nuclei -update-templates

# Update system packages
sudo apt update && sudo apt upgrade
```

## Uninstallation

### Remove Installed Tools
```bash
# Remove Go tools
rm -rf $HOME/go/bin/*

# Remove default resources
sudo rm -rf /usr/share/default-recon-resources

# Remove repository
cd ..
rm -rf Bug-bounty-recon-pipeline
```

### Remove System Packages
```bash
sudo apt remove nmap tor chromium-browser
sudo apt autoremove
```

## Next Steps

1. Read the [README.md](README.md) for usage examples
2. Check [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
3. Review [CHANGELOG.md](CHANGELOG.md) for version history
4. Start your first reconnaissance scan!

## Support

If you encounter issues:
1. Check the troubleshooting section in [README.md](README.md)
2. Search existing [GitHub Issues](https://github.com/Shakibul-CyberSec/Bug-bounty-recon-pipeline/issues)
3. Create a new issue with detailed information

---

**Happy Hunting! 🚀**
