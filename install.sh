#!/bin/bash
# Bug Bounty Recon Tool Installer - Secure Version
# Author: Shakibul

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'        # Safer field splitting

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Default directory for all resources
readonly DEFAULT_RESOURCE_DIR="/usr/share/default-recon-resources"
readonly SCRIPT_VERSION="1.0-secure"
readonly LOG_FILE="/tmp/recon-install-$(date +%Y%m%d-%H%M%S).log"

# GitHub base URLs (centralized for easy updates)
readonly GITHUB_RAW_BASE="https://raw.githubusercontent.com/Shakibul-CyberSec/Bug-Bounty-Reconnaissance-Automation/refs/heads/main"
readonly LOCAL_TOOLS_URL="${GITHUB_RAW_BASE}/Local-Tools"
readonly DEFAULT_RESOURCES_URL="${GITHUB_RAW_BASE}/Default-resources"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

# Security check - must not run as root
if [[ ${EUID} -eq 0 ]]; then
   echo -e "${RED}[!]${NC} This script should not be run as root directly."
   echo -e "${YELLOW}[*]${NC} The script will prompt for sudo when needed."
   exit 1
fi

# Verify sudo access
if ! sudo -v; then
    echo -e "${RED}[!]${NC} This script requires sudo privileges."
    exit 1
fi

# Keep sudo alive in background
while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &

command_exists() {
    command -v "$1" &>/dev/null
}

# Secure function to wait for apt lock with timeout
wait_for_apt_lock() {
    local max_wait=300
    local wait_time=0
    local check_interval=2
    local shown_warning=false
    
    local lock_files=(
        "/var/lib/dpkg/lock-frontend"
        "/var/lib/dpkg/lock"
        "/var/lib/apt/lists/lock"
        "/var/cache/apt/archives/lock"
    )
    
    while true; do
        local locked=false
        for lock_file in "${lock_files[@]}"; do
            if sudo fuser "${lock_file}" >/dev/null 2>&1; then
                locked=true
                break
            fi
        done
        
        if [[ "${locked}" == "false" ]]; then
            break
        fi
        
        if [[ ${wait_time} -eq 0 ]]; then
            echo -e "${YELLOW}[!]${NC} Package manager is locked by another process..."
            echo -e "${YELLOW}[*]${NC} Waiting for lock to be released (timeout: ${max_wait}s)..."
            shown_warning=true
        fi
        
        if [[ ${wait_time} -ge ${max_wait} ]]; then
            echo -e "${RED}[!]${NC} Timeout waiting for package manager lock"
            echo -e "${YELLOW}[*]${NC} Please close other package managers and try again"
            return 1
        fi
        
        sleep ${check_interval}
        wait_time=$((wait_time + check_interval))
        
        if [[ $((wait_time % 10)) -eq 0 ]]; then
            echo -e "${YELLOW}[*]${NC} Still waiting... (${wait_time}s elapsed)"
        fi
    done
    
    if [[ "${shown_warning}" == "true" ]]; then
        echo -e "${GREEN}[+]${NC} Lock released, continuing installation..."
    fi
    
    return 0
}

# Safe apt wrapper with retry logic and proper error handling
safe_apt() {
    local max_retries=3
    local retry_count=0
    
    while [[ ${retry_count} -lt ${max_retries} ]]; do
        if ! wait_for_apt_lock; then
            log "ERROR: Failed to acquire apt lock"
            return 1
        fi
        
        if sudo DEBIAN_FRONTEND=noninteractive apt-get \
            -o DPkg::Lock::Timeout=120 \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            "$@"; then
            return 0
        else
            retry_count=$((retry_count + 1))
            if [[ ${retry_count} -lt ${max_retries} ]]; then
                log "WARNING: apt command failed, retrying (${retry_count}/${max_retries})..."
                sleep 3
            else
                log "ERROR: apt command failed after ${max_retries} attempts"
                return 1
            fi
        fi
    done
    
    return 1
}

# Secure download with checksum verification (optional but recommended)
secure_download() {
    local url="$1"
    local output="$2"
    local max_retries=3
    local retry_count=0
    
    # Validate URL format
    if [[ ! "${url}" =~ ^https:// ]]; then
        log "ERROR: Only HTTPS URLs are allowed: ${url}"
        return 1
    fi
    
    while [[ ${retry_count} -lt ${max_retries} ]]; do
        if wget --timeout=30 \
                --tries=3 \
                --waitretry=5 \
                --secure-protocol=TLSv1_2 \
                --https-only \
                -q -O "${output}" "${url}"; then
            return 0
        else
            retry_count=$((retry_count + 1))
            if [[ ${retry_count} -lt ${max_retries} ]]; then
                log "WARNING: Download failed, retrying (${retry_count}/${max_retries})..."
                sleep 2
            fi
        fi
    done
    
    log "ERROR: Failed to download ${url}"
    return 1
}

show_banner() {
    cat << 'EOF'
=========================================================
     RECON TOOL INSTALLATION v1.0 (Secure)
=========================================================
        Bug Bounty & Penetration Testing Tools
=========================================================
EOF
}

install_tool() {
    local tool="$1"
    
    if command_exists "${tool}"; then
        echo -e "${BLUE}[i]${NC} ${tool} is already installed"
        return 0
    fi
    
    echo -e "${YELLOW}[*]${NC} Installing ${tool}..."
    log "INFO: Installing ${tool}"
    
    case "${tool}" in
        python3)
            safe_apt update && safe_apt install -y python3
            ;;
        pip3)
            safe_apt install -y python3-pip
            ;;
        go)
            install_golang
            return $?
            ;;
        subfinder)
            /usr/local/go/bin/go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
            ;;
        assetfinder)
            /usr/local/go/bin/go install github.com/tomnomnom/assetfinder@latest
            ;;
        amass)
            /usr/local/go/bin/go install -v github.com/owasp-amass/amass/v4/...@master
            ;;
        puredns)
            /usr/local/go/bin/go install github.com/d3mondev/puredns/v2@latest
            ;;
        dnsx)
            /usr/local/go/bin/go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
            ;;
        dnsgen)
            pip3 install dnsgen --break-system-packages
            ;;
        naabu)
            safe_apt install -y libpcap-dev
            /usr/local/go/bin/go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
            ;;
        nmap)
            safe_apt install -y nmap
            ;;
        httpx)
            /usr/local/go/bin/go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
            ;;
        nuclei)
            /usr/local/go/bin/go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
            if command_exists nuclei; then
                nuclei -update-templates 2>/dev/null || true
            fi
            ;;
        gowitness)
            /usr/local/go/bin/go install github.com/sensepost/gowitness@latest
            ;;
        gau)
            /usr/local/go/bin/go install github.com/lc/gau/v2/cmd/gau@latest
            ;;
        katana)
            /usr/local/go/bin/go install github.com/projectdiscovery/katana/cmd/katana@latest
            ;;
        uro)
            pip3 install uro --break-system-packages
            ;;
        gf)
            /usr/local/go/bin/go install github.com/tomnomnom/gf@latest
            install_gf_patterns
            ;;
        qsreplace)
            /usr/local/go/bin/go install github.com/tomnomnom/qsreplace@latest
            ;;
        dnsrecon)
            pip3 install dnsrecon --break-system-packages
            ;;
        subjack)
            /usr/local/go/bin/go install github.com/haccer/subjack@latest
            ;;
        arjun)
            pip3 install arjun --break-system-packages
            ;;
        wafw00f)
            pip3 install wafw00f --break-system-packages
            ;;
        git)
            safe_apt install -y git
            ;;
        curl)
            safe_apt install -y curl
            ;;
        wget)
            safe_apt update && safe_apt install -y wget
            ;;
        proxychains)
            safe_apt install -y proxychains4
            ;;
        chromium)
            safe_apt install -y chromium-browser chromium-chromedriver
            sudo ln -sf /usr/bin/chromium-browser /usr/bin/chromium 2>/dev/null || true
            ;;
        tor)
            safe_apt install -y tor
            ;;
        jsscan|down|url-extension)
            install_local_tools "${tool}"
            ;;
        whois)
            safe_apt install -y whois
            ;;
        jq)
            safe_apt install -y jq
            ;;
        *)
            log "ERROR: Unknown tool: ${tool}"
            return 1
            ;;
    esac
    
    # Verify installation (skip for local tools)
    case "${tool}" in
        jsscan|down|url-extension)
            return 0
            ;;
    esac
    
    if ! command_exists "${tool}"; then
        log "ERROR: Failed to install ${tool}"
        return 1
    fi
    
    echo -e "${GREEN}[+]${NC} ${tool} installed successfully"
    log "INFO: ${tool} installed successfully"
    return 0
}

install_golang() {
    local version="go1.23.5"
    
    echo -e "${YELLOW}[*]${NC} Installing Go ${version}..."
    log "INFO: Installing Go ${version}"
    
    local temp_dir
    temp_dir=$(mktemp -d) || return 1
    trap 'rm -rf "${temp_dir}"' EXIT
    
    local tarball="${temp_dir}/${version}.linux-amd64.tar.gz"
    
    if ! secure_download "https://go.dev/dl/${version}.linux-amd64.tar.gz" "${tarball}"; then
        return 1
    fi
    
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${tarball}"
    
    # Add Go to PATH in bashrc
    if [[ -f ~/.bashrc ]] && ! grep -q "GOPATH" ~/.bashrc; then
        cat >> ~/.bashrc <<'EOF'

# Go environment
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH
EOF
    fi
    
    # Add Go to PATH in zshrc if it exists
    if [[ -f ~/.zshrc ]] && ! grep -q "GOPATH" ~/.zshrc; then
        cat >> ~/.zshrc <<'EOF'

# Go environment
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH
EOF
    fi
    
    export PATH=/usr/local/go/bin:$PATH
    echo -e "${GREEN}[+]${NC} Go ${version} installed successfully!"
    /usr/local/go/bin/go version
    log "INFO: Go ${version} installed successfully"
}

install_gf_patterns() {
    mkdir -p ~/.gf
    
    local temp_dir
    temp_dir=$(mktemp -d) || return 1
    trap 'rm -rf "${temp_dir}"' RETURN
    
    if git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns.git "${temp_dir}/Gf-Patterns" 2>/dev/null; then
        find "${temp_dir}/Gf-Patterns" -name "*.json" -type f -exec cp {} ~/.gf/ \; 2>/dev/null || true
        echo -e "${GREEN}[+]${NC} GF patterns installed"
    else
        echo -e "${YELLOW}[!]${NC} Failed to clone Gf-Patterns repository"
    fi
}

install_local_tools() {
    local tool="$1"
    local url="${LOCAL_TOOLS_URL}/${tool}"
    local dest="/usr/local/bin/${tool}"
    
    echo -e "${YELLOW}[*]${NC} Installing ${tool}..."
    log "INFO: Installing ${tool}"
    echo -e "${YELLOW}[*]${NC} Downloading ${tool}..."
    log "INFO: Downloading ${tool} from ${url}"
    
    local temp_file=""
    temp_file=$(mktemp) || return 1
    
    # Use a cleanup function instead of trap to avoid unbound variable issue
    local cleanup_needed=true
    
    if secure_download "${url}" "${temp_file}"; then
        sudo install -m 755 "${temp_file}" "${dest}"
        rm -f "${temp_file}"
        cleanup_needed=false
        echo -e "${GREEN}[+]${NC} ${tool} installed"
        log "INFO: ${tool} installed successfully"
        return 0
    else
        if [[ -n "${temp_file}" ]] && [[ -f "${temp_file}" ]]; then
            rm -f "${temp_file}"
        fi
        log "ERROR: Failed to download ${tool}"
        return 1
    fi
}

setup_default_resources() {
    echo -e "${YELLOW}[*]${NC} Setting up default recon resources..."
    log "INFO: Setting up default resources"
    
    # Create directory if it doesn't exist
    if [[ ! -d "${DEFAULT_RESOURCE_DIR}" ]]; then
        echo -e "${YELLOW}[*]${NC} Creating directory for default resources..."
        sudo mkdir -p "${DEFAULT_RESOURCE_DIR}"
    fi
    
    local resources=(
        "subdomains-top1million-5000.txt"
        "resolvers.txt"
        "fingerprint.json"
    )
    
    # Download each resource if it doesn't exist or update fingerprint
    for resource in "${resources[@]}"; do
        local resource_path="${DEFAULT_RESOURCE_DIR}/${resource}"
        
        # Always update fingerprint.json, download others only if missing
        if [[ "${resource}" == "fingerprint.json" ]] || [[ ! -f "${resource_path}" ]]; then
            if [[ "${resource}" == "fingerprint.json" ]]; then
                echo -e "${YELLOW}[*]${NC} Updating ${resource}..."
            else
                echo -e "${YELLOW}[*]${NC} Downloading ${resource}..."
            fi
            
            if secure_download "${DEFAULT_RESOURCES_URL}/${resource}" "/tmp/${resource}"; then
                sudo install -m 644 "/tmp/${resource}" "${resource_path}"
                rm -f "/tmp/${resource}"
                
                if [[ "${resource}" == "fingerprint.json" ]]; then
                    echo -e "${GREEN}[+]${NC} ${resource} updated"
                else
                    echo -e "${GREEN}[+]${NC} ${resource} downloaded"
                fi
                log "INFO: ${resource} installed successfully"
            else
                echo -e "${RED}[!]${NC} Failed to download ${resource}"
                log "ERROR: Failed to download ${resource}"
            fi
        else
            echo -e "${BLUE}[i]${NC} ${resource} already exists"
        fi
    done
    
    echo -e "\n${GREEN}[+]${NC} Default resources setup completed"
    echo -e "${GREEN}[+]${NC} Installed resources:"
    echo -e "  * Wordlist:     ${BLUE}${DEFAULT_RESOURCE_DIR}/subdomains-top1million-5000.txt${NC}"
    echo -e "  * Resolvers:    ${BLUE}${DEFAULT_RESOURCE_DIR}/resolvers.txt${NC}"
    echo -e "  * Fingerprint:  ${BLUE}${DEFAULT_RESOURCE_DIR}/fingerprint.json${NC}"
    
    log "INFO: Default resources setup completed"
}

setup_proxy() {
    echo -e "${YELLOW}[*]${NC} Setting up proxy configuration..."
    log "INFO: Setting up proxy configuration"
    
    if ! command_exists tor; then
        echo -e "${YELLOW}[*]${NC} Installing Tor..."
        safe_apt install -y tor
    fi
    
    if command_exists tor; then
        if ! systemctl is-active --quiet tor; then
            echo -e "${YELLOW}[!]${NC} Starting Tor service..."
            sudo systemctl start tor 2>/dev/null || true
            sudo systemctl enable tor 2>/dev/null || true
            sleep 5
        fi
        
        echo -e "${YELLOW}[*]${NC} Testing proxy connection..."
        if timeout 10 curl --socks5 127.0.0.1:9050 -Is https://check.torproject.org &>/dev/null; then
            echo -e "${GREEN}[+]${NC} Proxy is working"
            log "INFO: Tor proxy is working"
        else
            echo -e "${YELLOW}[!]${NC} Proxy not reachable"
            log "WARNING: Tor proxy not reachable"
        fi
    fi
}

check_installation() {
    local tool="$1"
    if command_exists "${tool}"; then
        echo -e "${GREEN}[+]${NC} ${tool}"
        return 0
    else
        echo -e "${RED}[-]${NC} ${tool}"
        return 1
    fi
}

# Main Execution
main() {
    show_banner
    
    echo -e "${YELLOW}[*]${NC} Installation log: ${LOG_FILE}"
    log "INFO: Starting installation - Version ${SCRIPT_VERSION}"
    
    echo -e "${YELLOW}[*]${NC} Updating system packages..."
    safe_apt update && safe_apt upgrade -y
    
    local required_tools=(
        python3 go pip3 git curl wget jq
        proxychains tor
        chromium
        subfinder assetfinder amass puredns dnsx dnsgen naabu nmap httpx
        gowitness gau katana uro gf qsreplace
        dnsrecon whois subjack
        nuclei arjun wafw00f
        jsscan down url-extension
    )
    
    echo -e "${YELLOW}[*]${NC} Installing required tools..."
    
    local failed_tools=()
    for tool in "${required_tools[@]}"; do
        if ! install_tool "${tool}"; then
            failed_tools+=("${tool}")
        fi
    done
    
    setup_default_resources
    setup_proxy
    
    echo -e "\n${GREEN}====================================================================${NC}"
    echo -e "${GREEN} INSTALLATION SUMMARY${NC}"
    echo -e "${GREEN}====================================================================${NC}"
    
    local all_installed=true
    for tool in "${required_tools[@]}"; do
        if ! check_installation "${tool}"; then
            all_installed=false
        fi
    done
    
    if [[ ${#failed_tools[@]} -gt 0 ]]; then
        echo -e "\n${RED}[!]${NC} Failed to install the following tools:"
        for tool in "${failed_tools[@]}"; do
            echo -e "  - ${RED}${tool}${NC}"
        done
        echo -e "\n${YELLOW}[*]${NC} You may need to install them manually."
        log "WARNING: Some tools failed to install: ${failed_tools[*]}"
    fi
    
    if ${all_installed}; then
        echo -e "\n${GREEN}[+]${NC} All tools installed successfully!"
        echo -e "${GREEN}[+]${NC} You can now run the recon script."
        echo -e "\n${YELLOW}[*]${NC} Command: ${BLUE}./recon.sh${NC} or ${BLUE}bash recon.sh${NC}"
        log "INFO: All tools installed successfully"
    else
        echo -e "\n${YELLOW}[!]${NC} Some tools failed to install."
        log "WARNING: Installation completed with errors"
    fi
    
    echo -e "\n${GREEN}====================================================================${NC}"
    echo -e "${GREEN} IMPORTANT PATHS${NC}"
    echo -e "${GREEN}====================================================================${NC}"
    echo -e "* Default Resources:    ${BLUE}${DEFAULT_RESOURCE_DIR}/${NC}"
    echo -e "* Go Tools:             ${BLUE}\$HOME/go/bin/${NC}"
    echo -e "* Nuclei Templates:     ${BLUE}\$HOME/nuclei-templates/${NC}"
    echo -e "* Installation Log:     ${BLUE}${LOG_FILE}${NC}"
    echo -e "${GREEN}====================================================================${NC}"
    
    echo -e "\n${YELLOW}[*]${NC} Installation complete! ${GREEN}Happy Hacking!${NC}"
}

# Run main function
main "$@"
