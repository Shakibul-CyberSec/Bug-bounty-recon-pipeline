# Frequently Asked Questions (FAQ)

## General Questions

### Q: What is this tool for?
A: This is a comprehensive reconnaissance automation tool for bug bounty hunters and penetration testers. It performs 17 phases of security assessment including subdomain enumeration, port scanning, vulnerability detection, and more.

### Q: Is this tool free?
A: Yes, completely free and open-source.

### Q: What makes this different from other recon tools?
A: 
- **Security-hardened**: Production-ready bash with proper error handling
- **Resume capability**: Never lose progress on interrupted scans
- **17 comprehensive phases**: Complete workflow from enumeration to exploitation
- **30+ tools integrated**: Best-in-class security tools
- **Performance optimized**: Parallel execution with smart rate limiting

## Installation

### Q: What operating systems are supported?
A: Ubuntu 20.04+ and Debian-based Linux distributions. Tested on Ubuntu 24.04.

### Q: How long does installation take?
A: Approximately 10-15 minutes depending on your internet speed and system resources.

### Q: Do I need root access?
A: Yes, sudo/root access is required for installing system packages and tools.

### Q: Can I install on macOS or Windows?
A: Not officially supported. However, you can use WSL2 on Windows or a Linux VM on macOS.

### Q: Installation failed, what should I do?
A: 
1. Check the error message in the terminal
2. Ensure you have internet connectivity
3. Verify system requirements (4GB RAM, 10GB disk)
4. Try installing failed tools manually
5. Check [SETUP.md](SETUP.md) for troubleshooting

## Usage

### Q: How do I run a basic scan?
A: `./recon_v5.sh target.com`

### Q: Can I scan multiple domains?
A: Yes, create a text file with one domain per line and run: `./recon_v5.sh targets.txt`

### Q: How long does a scan take?
A: Depends on the target size. Small targets: 30-60 minutes. Large targets: 2-9+ hours.

### Q: Can I pause and resume a scan?
A: Yes! The checkpoint system automatically saves progress. If interrupted, run the script again and select the incomplete scan.

### Q: Where are results saved?
A: Results are saved in `recon_v5_YYYYMMDD_HHMMSS/domain/` directory with organized subdirectories.

### Q: Can I customize the scan?
A: Yes, edit configuration variables in `recon_v5.sh` for wordlists, concurrency, timeouts, etc.

## Performance

### Q: My scan is very slow, what can I do?
A: 
1. Increase `MAX_CONCURRENT_JOBS` for more parallel processing
2. Increase rate limits: `NAABU_RATE`, `HTTPX_THREADS`
3. Reduce timeout values if targets respond quickly
4. Use a faster internet connection
5. Upgrade system RAM

### Q: The script uses too much memory, what should I do?
A: 
1. Decrease `MAX_CONCURRENT_JOBS`
2. Reduce thread counts
3. Add swap space to your system
4. Run phases individually instead of all at once

### Q: Can I run multiple scans simultaneously?
A: Yes, but each scan will compete for system resources. Monitor CPU and memory usage.

## Features

### Q: Does this tool use Nuclei?
A: Yes, Nuclei is integrated in Phase 7 for vulnerability scanning. You can enable/disable it during scan configuration.

### Q: What is Tor support?
A: Tor allows anonymous reconnaissance by routing traffic through the Tor network. Enable it when prompted during scan setup.

### Q: Does it detect WAF/CDN?
A: Yes, the tool includes WAF detection and CDN filtering to identify protected assets.

### Q: Can it find subdomain takeovers?
A: Yes, Phase 8 includes subdomain takeover detection using subjack.

### Q: Does it take screenshots?
A: Yes, Phase 9 uses gowitness to capture screenshots of live web applications.

## Security & Legal

### Q: Is this tool legal to use?
A: The tool itself is legal. However, you must only scan targets you have permission to test. Unauthorized scanning is illegal.

### Q: Can I use this for bug bounties?
A: Yes! This tool is specifically designed for bug bounty programs. Always follow the program's scope and rules.

### Q: Does it create a lot of traffic?
A: Yes, reconnaissance generates significant network traffic. Use responsibly and follow rate limits.

### Q: Will I get detected/blocked?
A: Possible. Use Tor mode for anonymity, adjust rate limits, and respect target infrastructure.

## Troubleshooting

### Q: Tool X is not found after installation
A: 
1. Verify PATH: `echo $PATH`
2. Check tool location: `which $tool`
3. Reload shell: `source ~/.bashrc or source ~/.zshrc`
4. Reinstall the tool manually

### Q: DNS resolution is failing
A: 
1. Check your resolvers: `cat /usr/share/default-recon-resources/resolvers.txt`
2. Update resolvers from public lists
3. Test DNS: `dig @8.8.8.8 google.com`

### Q: Nuclei templates are outdated
A: Update templates: `nuclei -update-templates`

### Q: Permission denied errors
A: 
1. Make scripts executable: `chmod +x *.sh`
2. Check file ownership: `ls -la`
3. Use sudo for system operations

### Q: Out of disk space
A: 
1. Clean old scan results: `rm -rf recon_v5_*/`
2. Clean temp files: `rm -rf /tmp/recon_*`
3. Free up space: `sudo apt clean`

## Advanced

### Q: Can I skip certain phases?
A: Yes, modify the script or manually run phases by commenting out unwanted sections.

### Q: How do I integrate with other tools?
A: Results are saved in text files. Parse output directories to feed other tools (Burp, Metasploit, etc.).

### Q: Can I run this in a Docker container?
A: Not officially supported, but you can create your own Dockerfile based on Ubuntu.

### Q: How do I contribute to this project?
A: Read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues and pull requests.

## Support

### Q: Where can I get help?
A: 
1. Check documentation: README.md, SETUP.md, EXAMPLES.md
2. Search GitHub Issues
3. Create a new issue with details
4. Join community discussions

### Q: How do I report bugs?
A: Create a GitHub issue with:
- Clear description
- Steps to reproduce
- System information
- Error messages/logs

### Q: How often is this updated?
A: Check [CHANGELOG.md](CHANGELOG.md) for version history. Updates are released as needed.

### Q: Can I request features?
A: Yes! Create a GitHub issue with the "enhancement" label describing your feature request.

---

**Still have questions?** Open an issue on [GitHub](https://github.com/Shakibul-CyberSec/Bug-Bounty-Reconnaissance-Automation/issues).
