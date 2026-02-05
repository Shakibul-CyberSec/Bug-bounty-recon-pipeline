#!/bin/bash
# Ultra-Fast Bug Bounty Recon Tool Installer - Enhanced Version v5
# Author: Shakibul

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default directory for all resources
DEFAULT_RESOURCE_DIR="/usr/share/default-recon-resources"

# --------------- Function Definitions ---------------
command_exists() {
    command -v "$1" &>/dev/null
}

show_banner() {
    echo -e "\e[1;36m"
    echo "========================================================="
    echo "     RECON TOOL INSTALLATION - ENHANCED v5.0           "
    echo "========================================================="
    echo -e "\e[1;32m"
    echo "        Bug Bounty & Penetration Testing Tools"
    echo -e "\e[0m"
}

install_tool() {
    local tool=$1
    if ! command_exists "$tool"; then
        echo -e "${YELLOW}[*]${NC} Installing $tool..."
        
        case $tool in
            python3)
                sudo apt update && sudo apt install python3 -y
                ;;
            pip3)
                sudo apt install python3-pip -y
                ;;
            go)
                VERSION=$(curl -s "https://go.dev/VERSION?m=text" | head -1) && \
                echo "Installing Go $VERSION..." && \
                wget -q "https://go.dev/dl/${VERSION}.linux-amd64.tar.gz" && \
                sudo rm -rf /usr/local/go && \
                sudo tar -C /usr/local -xzf "${VERSION}.linux-amd64.tar.gz" && \
                rm "${VERSION}.linux-amd64.tar.gz"

                # bash
                if ! grep -q "GOPATH" ~/.bashrc; then
                    cat >> ~/.bashrc <<'EOF'
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH
EOF
                fi

                # zsh
                if [ -f ~/.zshrc ]; then
                    if ! grep -q "GOPATH" ~/.zshrc; then
                        cat >> ~/.zshrc <<'EOF'
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH
EOF
                    fi
                fi 

                # current shell
                export PATH=$PATH:/usr/local/go/bin && \
                echo "✅ Go $VERSION installed successfully!" && \
                /usr/local/go/bin/go version
                ;;
            subfinder)
                go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                ;;
            assetfinder)
                go install github.com/tomnomnom/assetfinder@latest
                ;;
            amass)
                go install -v github.com/owasp-amass/amass/v4/...@master
                ;;
            puredns)
                go install github.com/d3mondev/puredns/v2@latest
                ;;
            dnsx)
                go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
                ;;
            dnsgen)
                pip3 install dnsgen --break-system-packages
                ;;
            naabu)
                sudo apt install -y libpcap-dev
                go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
                ;;
            nmap)
                sudo apt install -y nmap
                ;;
            httpx)
                go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
                ;;
            nuclei)
                go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
                # Download nuclei templates
                nuclei -update-templates 2>/dev/null || true
                ;;
            gowitness)
                go install github.com/sensepost/gowitness@latest
                ;;
            gau)
                go install github.com/lc/gau/v2/cmd/gau@latest
                ;;
            katana)
                go install github.com/projectdiscovery/katana/cmd/katana@latest
                ;;
            uro)
                pip3 install uro --break-system-packages || sudo apt install uro -y
                ;;
            gf)
                go install github.com/tomnomnom/gf@latest
                mkdir -p ~/.gf
                if git clone https://github.com/1ndianl33t/Gf-Patterns.git /tmp/Gf-Patterns 2>/dev/null; then
                    cp /tmp/Gf-Patterns/*.json ~/.gf/ 2>/dev/null || echo -e "${YELLOW}[!]${NC} No patterns to copy"
                    rm -rf /tmp/Gf-Patterns
                else
                    echo -e "${YELLOW}[!]${NC} Failed to clone Gf-Patterns repository (continuing without patterns)"
                fi
                ;;
            qsreplace)
                go install github.com/tomnomnom/qsreplace@latest
                ;;
            arjun)
                pip3 install arjun --break-system-packages
                ;;
            wafw00f)
                pip3 install wafw00f --break-system-packages || sudo apt install wafw00f -y
                ;;
            cloud_enum)
                if [ ! -d "/opt/cloud_enum" ]; then
                    git clone https://github.com/initstring/cloud_enum.git /opt/cloud_enum || return 1
                fi
                cd /opt/cloud_enum || return 1
                pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true
                sudo ln -sf /opt/cloud_enum/cloud_enum.py /usr/local/bin/cloud_enum
                sudo chmod +x /opt/cloud_enum/cloud_enum.py
                cd - >/dev/null 2>&1
                ;;
            dnsrecon)
                sudo apt install dnsrecon -y
                ;;
            whois)
                sudo apt install whois -y
                ;;
            subjack)
                go install github.com/haccer/subjack@latest
                ;;
            jq)
                sudo apt install jq -y
                ;;
            git)
                sudo apt update
                sudo apt install -y git
                ;;
            curl)
                sudo apt update
                sudo apt install -y curl
                ;;
            wget)
                sudo apt update
                sudo apt install -y wget
                ;;
            proxychains)
                sudo apt install -y proxychains4
                ;; 
            chromium)
                sudo apt install -y chromium-browser chromium-chromedriver
                sudo ln -sf /usr/bin/chromium-browser /usr/bin/chromium 2>/dev/null || true
                ;;
            tor)
                sudo apt install -y tor
                ;;
            # Local tools installation
            jsscan|down|url-extension)
                install_local_tools "$tool"
                ;;
            *)
                echo -e "${RED}[!]${NC} Unknown tool: $tool"
                return 1
                ;;
        esac
        
        # Skip command_exists check for local tools (they're shell scripts, check was done in install_local_tools)
        case $tool in
            jsscan|down|url-extension)
                # install_local_tools already returned success/failure
                return 0
                ;;
        esac
        
        if ! command_exists "$tool"; then
            echo -e "${RED}[!]${NC} Failed to install $tool"
            return 1
        else
            echo -e "${GREEN}[+]${NC} Successfully installed $tool"
        fi
    else
        echo -e "${BLUE}[i]${NC} $tool is already installed"
    fi
}

install_local_tools() {
    local tool=$1
    LOCAL_TOOL_DIR="$HOME/local-tool"
    REPO="https://github.com/Shakibul-CyberSec/Local-Tool.git"

    if [ ! -d "$LOCAL_TOOL_DIR" ]; then
        echo -e "${YELLOW}[*]${NC} Cloning Local-Tool repository..."
        git clone "$REPO" "$LOCAL_TOOL_DIR" || return 1
    fi

    cd "$LOCAL_TOOL_DIR" || return 1
    
    # Install specific local tool
    case $tool in
        jsscan)
            if [ -f "jsscan" ]; then
                sudo install -m 755 "jsscan" /usr/local/bin/jsscan || { cd - >/dev/null 2>&1; return 1; }
            else
                echo -e "${RED}[!]${NC} jsscan not found in repository"
                cd - >/dev/null 2>&1
                return 1
            fi
            ;;
        down)
            if [ -f "down" ]; then
                sudo install -m 755 "down" /usr/local/bin/down || { cd - >/dev/null 2>&1; return 1; }
            else
                echo -e "${RED}[!]${NC} down not found in repository"
                cd - >/dev/null 2>&1
                return 1
            fi
            ;;
        url-extension)
            if [ -f "url-extension" ]; then
                sudo install -m 755 "url-extension" /usr/local/bin/url-extension || { cd - >/dev/null 2>&1; return 1; }
            else
                echo -e "${RED}[!]${NC} url-extension not found in repository"
                cd - >/dev/null 2>&1
                return 1
            fi
            ;;
    esac
    
    cd - >/dev/null 2>&1
    return 0
}

setup_default_resources() {
    echo -e "${YELLOW}[*]${NC} Setting up default recon resources..."
    
    if [ ! -d "$DEFAULT_RESOURCE_DIR" ]; then
        echo -e "${YELLOW}[*]${NC} Creating directory for default resources..."
        sudo mkdir -p "$DEFAULT_RESOURCE_DIR"
        
        # Clone the repository if not already cloned
        LOCAL_TOOL_DIR="$HOME/local-tool"
        if [ ! -d "$LOCAL_TOOL_DIR" ]; then
            git clone https://github.com/Shakibul-CyberSec/Local-Tool.git "$LOCAL_TOOL_DIR"
        fi
        
        # Check if the resources exist in the local tool repo
        if [ -d "$LOCAL_TOOL_DIR" ]; then
            echo -e "${YELLOW}[*]${NC} Copying default resources..."
            
            # Copy wordlist
            if [ -f "$LOCAL_TOOL_DIR/default-wordlist-resolver/subdomains-top1million-5000.txt" ]; then
                sudo cp "$LOCAL_TOOL_DIR/default-wordlist-resolver/subdomains-top1million-5000.txt" "$DEFAULT_RESOURCE_DIR/" 2>/dev/null || true
                echo -e "${GREEN}[+]${NC} Wordlist copied"
            else
                echo -e "${YELLOW}[!]${NC} Wordlist not found in local tool repository"
                # Download default wordlist
                echo -e "${YELLOW}[*]${NC} Downloading default wordlist..."
                sudo wget -q -O "$DEFAULT_RESOURCE_DIR/subdomains-top1million-5000.txt" \
                    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
            fi
            
            # Copy resolvers
            if [ -f "$LOCAL_TOOL_DIR/default-wordlist-resolver/resolvers.txt" ]; then
                sudo cp "$LOCAL_TOOL_DIR/default-wordlist-resolver/resolvers.txt" "$DEFAULT_RESOURCE_DIR/" 2>/dev/null || true
                echo -e "${GREEN}[+]${NC} Resolvers copied"
            else
                echo -e "${YELLOW}[!]${NC} Resolvers not found in local tool repository"
                # Download default resolvers
                echo -e "${YELLOW}[*]${NC} Downloading default resolvers..."
                sudo wget -q -O "$DEFAULT_RESOURCE_DIR/resolvers.txt" \
                    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
            fi
            
            # Copy fingerprint
            echo -e "${YELLOW}[*]${NC} Downloading default fingerprint..."
            sudo wget -q -O "$DEFAULT_RESOURCE_DIR/fingerprint.json" \
                "https://raw.githubusercontent.com/Shakibul-CyberSec/Local-Tool/main/Default_fingerprint.json/fingerprint.json"
            
            # Set appropriate permissions
            sudo chmod 644 "$DEFAULT_RESOURCE_DIR"/*
            
            echo -e "${GREEN}[+]${NC} Default resources setup completed"
            
            # Display summary
            echo -e "\n${GREEN}[+]${NC} Installed resources:"
            echo -e "  • Wordlist:     ${BLUE}$DEFAULT_RESOURCE_DIR/subdomains-top1million-5000.txt${NC}"
            echo -e "  • Resolvers:    ${BLUE}$DEFAULT_RESOURCE_DIR/resolvers.txt${NC}"
            echo -e "  • Fingerprint:  ${BLUE}$DEFAULT_RESOURCE_DIR/fingerprint.json${NC}"
        else
            echo -e "${RED}[!]${NC} Local tool repository not found"
        fi
    else
        echo -e "${BLUE}[i]${NC} Default resources already set up"
        
        # Update fingerprint if exists
        echo -e "${YELLOW}[*]${NC} Updating fingerprint file..."
        sudo wget -q -O "$DEFAULT_RESOURCE_DIR/fingerprint.json" \
            "https://raw.githubusercontent.com/Shakibul-CyberSec/Local-Tool/main/Default_fingerprint.json/fingerprint.json"
    fi
}

setup_proxy() {
    echo -e "${YELLOW}[*]${NC} Setting up proxy configuration..."
    
    # Install Tor if not installed
    if ! command_exists tor; then
        echo -e "${YELLOW}[*]${NC} Installing Tor..."
        sudo apt install -y tor
    fi
    
    if command_exists tor; then
        if ! systemctl is-active --quiet tor; then
            echo -e "${YELLOW}[!]${NC} Starting Tor service..."
            sudo systemctl start tor 2>/dev/null || true
            sudo systemctl enable tor 2>/dev/null || true
            sleep 5
        fi
        
        echo -e "${YELLOW}[*]${NC} Testing proxy connection..."
        if timeout 10 curl --socks5 127.0.0.1:9050 -Is https://google.com &>/dev/null; then
            echo -e "${GREEN}[+]${NC} Proxy is working"
        else
            echo -e "${YELLOW}[!]${NC} Proxy not reachable!"
        fi
    fi
}

check_installation() {
    local tool=$1
    if command_exists "$tool"; then
        echo -e "${GREEN}[✓]${NC} $tool"
        return 0
    else
        echo -e "${RED}[✗]${NC} $tool"
        return 1
    fi
}

# --------------- Main Execution ---------------
show_banner

# Update system first
echo -e "${YELLOW}[*]${NC} Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Required tools list - ALL TOOLS USED IN ENHANCED recon_v5.sh
required_tools=(
    # System essentials
    python3 go pip3 git curl wget jq
    
    # Proxy tools
    proxychains tor
    
    # Web browser for screenshots
    chromium
    
    # Core reconnaissance tools
    subfinder assetfinder amass puredns dnsx dnsgen naabu nmap httpx
    gowitness gau katana uro gf qsreplace
    dnsrecon whois subjack
    
    # Vulnerability scanning & advanced recon
    nuclei arjun wafw00f cloud_enum
    
    # Local tools
    jsscan down url-extension
)

echo -e "${YELLOW}[*]${NC} Installing required tools..."

failed_tools=()
for tool in "${required_tools[@]}"; do
    if ! install_tool "$tool"; then
        failed_tools+=("$tool")
    fi
done

# Setup default resources (wordlist, resolvers, fingerprint)
setup_default_resources

# Setup proxy
setup_proxy

# Final check
echo -e "\n${GREEN}====================================================================${NC}"
echo -e "${GREEN} INSTALLATION SUMMARY${NC}"
echo -e "${GREEN}====================================================================${NC}"

all_installed=true
for tool in "${required_tools[@]}"; do
    if ! check_installation "$tool"; then
        all_installed=false
    fi
done

if [ ${#failed_tools[@]} -gt 0 ]; then
    echo -e "\n${RED}[!]${NC} Failed to install the following tools:"
    for tool in "${failed_tools[@]}"; do
        echo -e "  - ${RED}$tool${NC}"
    done
    echo -e "\n${YELLOW}[*]${NC} You may need to install them manually."
fi

if $all_installed; then
    echo -e "\n${GREEN}[+]${NC} All tools installed successfully!"
    echo -e "${GREEN}[+]${NC} You can now run the enhanced recon script."
    echo -e "\n${YELLOW}[*]${NC} Command: ${BLUE}./recon_v5.sh${NC} or ${BLUE}bash recon_v5.sh${NC}"
else
    echo -e "\n${YELLOW}[!]${NC} Some tools failed to install. You may need to install them manually."
fi

echo -e "\n${GREEN}====================================================================${NC}"
echo -e "${GREEN} IMPORTANT PATHS${NC}"
echo -e "${GREEN}====================================================================${NC}"
echo -e "• Default Resources:    ${BLUE}$DEFAULT_RESOURCE_DIR/${NC}"
echo -e "• Local Tools:          ${BLUE}$HOME/local-tool/${NC}"
echo -e "• Go Tools:             ${BLUE}$HOME/go/bin/${NC}"
echo -e "• Nuclei Templates:     ${BLUE}$HOME/nuclei-templates/${NC}"
echo -e "${GREEN}====================================================================${NC}"


echo -e "\n${YELLOW}[*]${NC} Installation complete! ${GREEN}Happy Hacking! 🚀${NC}"
