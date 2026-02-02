#!/bin/bash
# Ultra-Fast Bug Bounty Recon & Vulnerability Discovery Pipeline
# Author: Shakibul (Shakibul_Cybersec)
# Version: 3.3 - Professional Edition with Resume Feature

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============ CONFIGURATION ============
# Default paths
DEFAULT_RESOURCE_DIR="/usr/share/default-recon-resources"
DEFAULT_WORDLIST="$DEFAULT_RESOURCE_DIR/subdomains-top1million-5000.txt"
DEFAULT_RESOLVERS="$DEFAULT_RESOURCE_DIR/resolvers.txt"
DEFAULT_FINGERPRINT="$DEFAULT_RESOURCE_DIR/fingerprint.json"

# Performance tuning
MAX_PARALLEL_JOBS=10
MAX_RETRIES=3
TIMEOUT_SECONDS=2700
NMAP_TIMEOUT=5400  # 1.5 hours = 90 minutes = 5400 seconds
MEMORY_THRESHOLD=512  # MB

# Tool configurations
NAABU_RATE=2000
HTTPX_THREADS=100
KATANA_CONCURRENCY=50

# Resume feature configuration
STATE_DIR=".recon_state"
CHECKPOINT_FILE="checkpoint.txt"
PROGRESS_FILE="progress.log"

# ============ RESUME FUNCTIONS ============

init_resume_system() {
    local output_dir=$1
    local state_path="$output_dir/$STATE_DIR"
    
    mkdir -p "$state_path"
    
    # Initialize checkpoint file if it doesn't exist
    if [ ! -f "$state_path/$CHECKPOINT_FILE" ]; then
        echo "PHASE=0" > "$state_path/$CHECKPOINT_FILE"
        echo "DOMAIN=" >> "$state_path/$CHECKPOINT_FILE"
        echo "TIMESTAMP=$(date +%s)" >> "$state_path/$CHECKPOINT_FILE"
        echo "STATUS=STARTED" >> "$state_path/$CHECKPOINT_FILE"
    fi
    
    # Initialize progress log
    if [ ! -f "$state_path/$PROGRESS_FILE" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Reconnaissance initialized" > "$state_path/$PROGRESS_FILE"
    fi
}

save_checkpoint() {
    local output_dir=$1
    local phase=$2
    local domain=$3
    local status=$4
    local state_path="$output_dir/$STATE_DIR"
    
    cat > "$state_path/$CHECKPOINT_FILE" <<EOF
PHASE=$phase
DOMAIN=$domain
TIMESTAMP=$(date +%s)
STATUS=$status
LAST_UPDATE=$(date '+%Y-%m-%d %H:%M:%S')
EOF
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Phase $phase: $status" >> "$state_path/$PROGRESS_FILE"
}

load_checkpoint() {
    local output_dir=$1
    local state_path="$output_dir/$STATE_DIR"
    
    if [ -f "$state_path/$CHECKPOINT_FILE" ]; then
        source "$state_path/$CHECKPOINT_FILE"
        echo -e "${YELLOW}[!]${NC} Resuming from Phase $PHASE"
        echo -e "${YELLOW}[!]${NC} Last status: $STATUS"
        echo -e "${YELLOW}[!]${NC} Last update: $LAST_UPDATE"
        return 0
    else
        return 1
    fi
}

should_run_phase() {
    local current_phase=$1
    local saved_phase=$2
    local saved_status=$3
    
    # If saved phase is less than current, we've already completed this phase
    if [ "$saved_phase" -gt "$current_phase" ]; then
        echo -e "${GREEN}[✓]${NC} Phase $current_phase already completed (skipping)"
        return 1
    fi
    
    # If we're on the same phase and it was completed, skip
    if [ "$saved_phase" -eq "$current_phase" ] && [ "$saved_status" == "COMPLETED" ]; then
        echo -e "${GREEN}[✓]${NC} Phase $current_phase already completed (skipping)"
        return 1
    fi
    
    # Otherwise, run the phase
    return 0
}

mark_phase_complete() {
    local output_dir=$1
    local phase=$2
    local domain=$3
    
    save_checkpoint "$output_dir" "$phase" "$domain" "COMPLETED"
    echo -e "${GREEN}[✓]${NC} Phase $phase marked as complete"
}

cleanup_resume_state() {
    local output_dir=$1
    local state_path="$output_dir/$STATE_DIR"
    
    if [ -d "$state_path" ]; then
        # Archive the state instead of deleting
        local archive_name="state_archive_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "$output_dir/$archive_name" -C "$output_dir" "$STATE_DIR" 2>/dev/null
        rm -rf "$state_path"
        echo -e "${GREEN}[✓]${NC} Resume state archived to $archive_name"
    fi
}

# ============ CORE FUNCTIONS ============

command_exists() {
    command -v "$1" &>/dev/null
}

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          BUG BOUNTY RECON PIPELINE v3.3 (Shakibul)          ║"
    echo "║           Professional Reconnaissance & Discovery            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${GREEN}          Parallel • Fast • Comprehensive • Reliable${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}            Created by: Shakibul (Shakibul_Cybersec)           ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
}

setup_proxy() {
    if command_exists tor; then
        if ! systemctl is-active --quiet tor; then
            echo -e "${YELLOW}[!]${NC} Starting Tor service..."
            sudo systemctl start tor 2>/dev/null || true
            sleep 5
        fi
        
        proxy_url="socks5://127.0.0.1:9050"
        echo -e "${YELLOW}[*]${NC} Testing proxy connection..."
        if timeout 10 curl --socks5 127.0.0.1:9050 -Is https://google.com &>/dev/null; then
            echo -e "${GREEN}[+]${NC} Proxy is working"
            proxy_cmd="proxychains -q"
            httpx_proxy="-proxy $proxy_url"
        else
            echo -e "${YELLOW}[!]${NC} Proxy not reachable! Continuing without proxy."
            proxy_cmd=""
            httpx_proxy=""
        fi
    else
        echo -e "${YELLOW}[!]${NC} Tor not installed. Continuing without proxy."
        proxy_cmd=""
        httpx_proxy=""
    fi
}

# --------------- Validation Functions ---------------
validate_domain() {
    local domain=$1
    # Basic domain validation regex
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        echo -e "${RED}[!] Invalid domain format: $domain${NC}"
        return 1
    fi
    return 0
}

validate_file() {
    local file=$1
    local description=$2
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}[!] $description not found: $file${NC}"
        return 1
    fi
    
    if [ ! -s "$file" ]; then
        echo -e "${YELLOW}[!] $description is empty: $file${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[✓] Validated: $file ($(wc -l < "$file") lines)${NC}"
    return 0
}

# --------------- Performance Functions ---------------
check_resources() {
    local required_mem=$1
    local mem_free=$(free -m | awk '/Mem/{print $7}')
    local load_avg=$(awk '{print $1}' /proc/loadavg)
    local cpu_cores=$(nproc)
    
    echo -e "${CYAN}[*]${NC} System Resource Check:"
    echo -e "  • Free Memory: ${mem_free}MB / Required: ${required_mem}MB"
    echo -e "  • Load Average: ${load_avg} / CPU Cores: ${cpu_cores}"
    
    if [ "$mem_free" -lt "$required_mem" ]; then
        echo -e "${YELLOW}[!]${NC} Low memory detected. Adjusting concurrency...${NC}"
        return 1
    fi
    
    if (( $(echo "$load_avg > $cpu_cores" | bc -l) )); then
        echo -e "${YELLOW}[!]${NC} High load detected. Reducing parallelism...${NC}"
        return 1
    fi
    
    return 0
}

adaptive_concurrency() {
    local cpu_cores=$(nproc)
    local mem_free=$(free -m | awk '/Mem/{print $7}')
    
    # Dynamic concurrency based on resources
    if [ "$mem_free" -lt 2048 ]; then
        echo $((cpu_cores * 2))
    elif [ "$mem_free" -lt 4096 ]; then
        echo $((cpu_cores * 3))
    else
        echo $((cpu_cores * 4))
    fi
}

# --------------- Enhanced Command Execution ---------------
run_cmd_with_retry() {
    local cmd="$1"
    local desc="$2"
    local log_file="$3"
    local max_retries=${4:-$MAX_RETRIES}
    local use_timeout=${5:-1}  # Default to use timeout, but can be disabled for specific tools
    
    echo -e "${YELLOW}[>]${NC} Starting: $desc"
    
    for ((retry=1; retry<=max_retries; retry++)); do
        echo -e "  Attempt $retry/$max_retries..."
        
        # Execute command with optional timeout
        if [ "$use_timeout" -eq 1 ]; then
            timeout $TIMEOUT_SECONDS bash -c "$cmd" >> "$log_file" 2>&1
        else
            # For tools that should run without external timeout (like nmap, dnsx)
            bash -c "$cmd" >> "$log_file" 2>&1
        fi
        
        local exit_code=$?
        
        case $exit_code in
            0)
                echo -e "  ${GREEN}✓ Success${NC}"
                return 0
                ;;
            124)
                echo -e "  ${YELLOW}! Timeout (external)${NC}"
                ;;
            *)
                echo -e "  ${RED}! Failed (code: $exit_code)${NC}"
                ;;
        esac
        
        if [ $retry -lt $max_retries ]; then
            echo -e "  Retrying in 2 seconds..."
            sleep 2
        fi
    done
    
    echo -e "${RED}[!]${NC} Failed after $max_retries attempts: $desc" | tee -a "$log_file"
    return 1
}

run_parallel() {
    local commands=("$@")
    local max_jobs=$MAX_PARALLEL_JOBS
    local pids=()
    local job_count=0
    
    echo -e "${CYAN}[*]${NC} Running ${#commands[@]} tasks in parallel (max: $max_jobs)..."
    
    for cmd in "${commands[@]}"; do
        # Extract description for logging
        local desc=""
        if [[ "$cmd" == *"desc:"* ]]; then
            # Try to extract from quotes
            desc=$(echo "$cmd" | grep -o 'desc:"[^"]*"' 2>/dev/null | cut -d'"' -f2)
            if [ -z "$desc" ]; then
                desc=$(echo "$cmd" | grep -o "desc:'[^']*'" 2>/dev/null | cut -d"'" -f2)
            fi
        fi
        [ -z "$desc" ] && desc="Unknown"
        
        echo -e "  [$(printf "%02d" $((job_count+1)))] $desc"
        
        # Remove description from command before execution
        local clean_cmd=$(echo "$cmd" | sed 's/; *echo.*desc:.*$//')
        
        # Execute in background with proper error handling
        bash -c "$clean_cmd" &
        pids+=($!)
        ((job_count++))
        
        # Control concurrent jobs
        if [ $job_count -ge $max_jobs ]; then
            wait -n
            job_count=$((job_count-1))
        fi
    done
    
    # Wait for all remaining jobs
    wait "${pids[@]}"
    echo -e "${GREEN}[✓]${NC} Parallel execution completed"
}

# --------------- Tool Validation ---------------
check_tools() {
    echo -e "${CYAN}[*]${NC} Validating required tools..."
    echo -e "${GREEN}────────────────────────────────────────────────────────────────────────────────────${NC}"
    
    required_tools=(
        subfinder assetfinder amass puredns dnsx naabu nmap httpx
        gowitness gau waybackurls katana
        uro gf qsreplace dnsrecon whois subjack
    )
    
    local all_ok=true
    local tool_count=0
    
    for tool in "${required_tools[@]}"; do
        ((tool_count++))
        if command_exists "$tool"; then
            printf "${GREEN}[✓]${NC} %-20s" "$tool"
        else
            printf "${RED}[✗]${NC} %-20s" "$tool"
            all_ok=false
        fi
        
        # Print 4 tools per line
        if [ $((tool_count % 4)) -eq 0 ]; then
            echo ""
        fi
    done
    
    # Add newline if last line wasn't complete
    if [ $((tool_count % 4)) -ne 0 ]; then
        echo ""
    fi
    
    if ! $all_ok; then
        echo -e "${RED}[!]${NC} Missing required tools detected"
        echo -e "${YELLOW}[*]${NC} Run: ${BLUE}./install.sh${NC} to install missing tools"
        exit 1
    fi

    echo -e "${GREEN}────────────────────────────────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}[+]${NC} All tools validated successfully!"
    
    # Test all tools functionality
    echo -e "${CYAN}[*]${NC} Testing tool functionality..."
    test_tools "${required_tools[@]}"
}

test_tools() {
    local tools=("$@")
    local working=0
    local total=${#tools[@]}
    
    for tool in "${tools[@]}"; do
        if timeout 3 $tool --version >/dev/null 2>&1 || \
           timeout 3 $tool -version >/dev/null 2>&1 || \
           timeout 3 $tool --help >/dev/null 2>&1; then
            ((working++))
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${YELLOW}!${NC} $tool (may need configuration)"
        fi
    done
    
    echo -e "${GREEN}[+]${NC} $working/$total tools fully functional"
}

# --------------- Modular Phases ---------------
phase_subdomain_enum() {
    local domain=$1
    local output_dir=$2
    local wordlist=$3
    local resolvers=$4
    local error_log="$output_dir/errors.log"
    
    echo -e "\n${BLUE}[PHASE 1]${NC} Subdomain Enumeration"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    # Parallel passive discovery 
    local passive_commands=(
        "subfinder -d $domain -silent -o $output_dir/subfinder.txt 2>>$error_log; echo 'desc:\"Subfinder\"'"
        "assetfinder -subs-only $domain > $output_dir/assetfinder.txt 2>>$error_log; echo 'desc:\"Assetfinder\"'"
        "curl -s 'https://crt.sh/?q=%25.$domain&output=json' 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\.//g' | sort -u > $output_dir/crt.txt; echo 'desc:\"crt.sh\"'"
        "amass enum -passive -d $domain -o $output_dir/amass_passive.txt 2>>$error_log; echo 'desc:\"Amass Passive\"'"
    )
    
    run_parallel "${passive_commands[@]}"
    
    # DNS brute force only 
    echo -e "${YELLOW}[>]${NC} Running DNS brute force..."
    
    run_cmd_with_retry \
        "puredns bruteforce $wordlist $domain -r $resolvers -q > $output_dir/puredns.txt 2>/dev/null" \
        "Puredns DNS Brute Force" \
        "$error_log"
    
    # Process and merge results
    process_subdomain_results "$output_dir" "$resolvers"
}

process_subdomain_results() {
    local output_dir=$1
    local resolvers=$2
    
    echo -e "${YELLOW}[>]${NC} Processing and deduplicating results..."
    
    # Combine and clean
    cat "$output_dir"/subfinder.txt \
        "$output_dir"/assetfinder.txt \
        "$output_dir"/crt.txt \
        "$output_dir"/amass_passive.txt \
        "$output_dir"/puredns.txt 2>/dev/null | \
        awk -F: '{print $1}' | \
        sed 's/^\.//; s/\.$//' | \
        sort -u | \
        grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" > "$output_dir/all_subdomains.raw.txt"
    
    # DNS resolution - WITHOUT external timeout
    if [ -s "$output_dir/all_subdomains.raw.txt" ]; then
        echo -e "${YELLOW}[>]${NC} Resolving subdomains with DNS..."
        # Run dnsx without external timeout wrapper
        dnsx -l "$output_dir/all_subdomains.raw.txt" \
             -r "$resolvers" \
             -silent \
             -o "$output_dir/all_subdomains.txt" \
             2>>"$output_dir/errors.log" || echo -e "${YELLOW}[!]${NC} DNS resolution completed (may have timeouts)"
    fi
    
    local count=$(wc -l < "$output_dir/all_subdomains.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓]${NC} Found $count unique and resolved subdomains"
}

phase_port_scanning() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"
    
    echo -e "\n${BLUE}[PHASE 2]${NC} Port Scanning"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    if [ ! -s "$output_dir/all_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No subdomains to scan"
        return
    fi
    
    # Fast port scan
    run_cmd_with_retry \
        "naabu -list $output_dir/all_subdomains.txt \
               -top-ports 100 \
               -rate $NAABU_RATE \
               -c $(adaptive_concurrency) \
               -silent \
               -o $output_dir/portscan/naabu_results.txt" \
        "Naabu Fast Scan" \
        "$error_log"
    
    # Service detection on comprehensive ports list
    local ports="21,22,23,25,53,80,110,143,443,465,587,993,995,1433,1521,2049,2375,2376,2379,2380,3000,3001,3306,3389,3690,4369,4443,4444,4505,4506,4848,5000,5001,5432,5601,5672,5900,5901,5984,5985,5986,6379,6443,7000,7001,7002,7474,7687,7777,8000,8001,8005,8008,8009,8010,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8180,8181,8200,8222,8243,8280,8281,8333,8443,8484,8500,8530,8531,8765,8834,8843,8880,8881,8883,8888,8889,8983,9000,9001,9002,9042,9050,9060,9080,9081,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9160,9180,9200,9300,9418,9443,9500,9600,9673,9800,9876,9898,9980,10000,11211,15672,16010,27017,27018,27019,28017,29000,32768,32769"
    
    # Run nmap WITH timeout and wait for completion before proceeding
    echo -e "${YELLOW}[>]${NC} Running comprehensive Nmap scan (1.5 hour timeout)..."
    echo -e "${YELLOW}[*]${NC} This may take a while for large target lists..."
    echo -e "${YELLOW}[*]${NC} Waiting for nmap to complete before proceeding..."
    
   # Run nmap with timeout and wait for it to finish
    timeout $NMAP_TIMEOUT nmap -iL "$output_dir/all_subdomains.txt" \
           -p "$ports" \
           -Pn \
           -T4 \
           -sV \
           --min-rate 1000 \
           -oA "$output_dir/portscan/nmap_scan" > /dev/null 2>&1
    
    local nmap_exit_code=$?
    
    if [ $nmap_exit_code -eq 124 ]; then
        echo -e "${YELLOW}[!]${NC} Nmap scan timed out after 1.5 hours"
    elif [ $nmap_exit_code -eq 0 ]; then
        echo -e "${GREEN}[✓]${NC} Nmap scan completed successfully"
    else
        echo -e "${YELLOW}[!]${NC} Nmap scan finished with exit code: $nmap_exit_code"
    fi
    
    # Process results after nmap completes
    process_port_results "$output_dir"
}

process_port_results() {
    local output_dir=$1
    
    # Extract open ports from naabu results first
    if [ -f "$output_dir/portscan/naabu_results.txt" ]; then
        cat "$output_dir/portscan/naabu_results.txt" | sort -u | grep -v '^$' > "$output_dir/portscan/all_results.txt"
    fi
    
    # Incorporate nmap results
    if [ -f "$output_dir/portscan/nmap_scan.nmap" ]; then
        grep -E '^[0-9]+/tcp.*open' "$output_dir/portscan/nmap_scan.nmap" 2>/dev/null | \
            awk '{print $1}' | cut -d'/' -f1 >> "$output_dir/portscan/open_ports.txt"
        
        # Update combined results
        cat "$output_dir/portscan/naabu_results.txt" \
            "$output_dir/portscan/open_ports.txt" 2>/dev/null | \
            sort -u | grep -v '^$' > "$output_dir/portscan/all_results.txt"
    fi
    
    local count=$(wc -l < "$output_dir/portscan/all_results.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓]${NC} Found $count open ports"
}
phase_web_discovery() {
    local domain=$1
    local output_dir=$2
    local error_log="$output_dir/errors.log"
    
    echo -e "\n${BLUE}[PHASE 3]${NC} Web Service Discovery"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    if [ ! -s "$output_dir/all_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No subdomains to check"
        echo "$domain" > "$output_dir/alive_subdomains.txt"
        echo "http://$domain" > "$output_dir/alive_subdomains_https.txt"
        return
    fi
    
    # Find alive web services
    run_cmd_with_retry \
        "httpx -l $output_dir/all_subdomains.txt \
               -threads $HTTPX_THREADS \
               -silent \
               -o $output_dir/httpx_output.txt" \
        "HTTPX Alive Check" \
        "$error_log"
    
    # Process results
    if [ -f "$output_dir/httpx_output.txt" ]; then
        # Clean URLs for domain list
        cat "$output_dir/httpx_output.txt" | \
            sed 's|https\?://||' | \
            awk -F/ '{print $1}' | \
            awk -F: '{print $1}' | \
            sed 's/^\.//; s/\.$//' | \
            sort -u > "$output_dir/alive_subdomains.txt"
        
        # Keep full URLs for screenshots
        cp "$output_dir/httpx_output.txt" "$output_dir/alive_subdomains_https.txt"
        
        local count=$(wc -l < "$output_dir/alive_subdomains.txt" 2>/dev/null || echo 0)
        echo -e "${GREEN}[✓]${NC} Found $count alive web services"
    else
        echo -e "${YELLOW}[!]${NC} No alive web services found"
        echo "$domain" > "$output_dir/alive_subdomains.txt"
        echo "http://$domain" > "$output_dir/alive_subdomains_https.txt"
    fi
}

phase_url_collection() {
    local domain=$1
    local output_dir=$2
    local error_log="$output_dir/errors.log"
    
    echo -e "\n${BLUE}[PHASE 4]${NC} URL Discovery"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    if [ ! -s "$output_dir/all_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No subdomains for URL collection"
        return
    fi
    
    # Check if alive_subdomains.txt exists
    if [ ! -s "$output_dir/alive_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive subdomains for URL collection"
        return
    fi
    
    # Parallel URL discovery
    local url_commands=(
        "cat $output_dir/all_subdomains.txt | gau --threads 20 > $output_dir/urls/gau.txt 2>>$error_log; echo 'desc:\"GAU\"'"
        "cat $output_dir/all_subdomains.txt | waybackurls -no-subs > $output_dir/urls/waybackurls.txt 2>>$error_log; echo 'desc:\"Waybackurls\"'"
    )
    
    # Build the Katana command with proper escaping
    local katana_domains=$(sed 's/\./\\./g' "$output_dir/alive_subdomains.txt" | paste -sd '|' - 2>/dev/null)
    if [ -n "$katana_domains" ]; then
        url_commands+=(
            "katana -list $output_dir/alive_subdomains.txt -jc -kf all -d 3 -c 50 -cs '^https?://(www\\.)?($katana_domains)(/|\$)' -o $output_dir/urls/katana.txt 2>>$error_log; echo 'desc:\"Katana\"'"
        )
    fi  

    run_parallel "${url_commands[@]}"
    
    # Combine and deduplicate (safely handle empty files)
    cat "$output_dir/urls/"*.txt 2>/dev/null | sort -u > "$output_dir/all_urls.txt"
    
    local count=$(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓]${NC} Collected $count unique URLs"
    
    # URL filtering by extension
    if command_exists url-extension; then
        if [ -s "$output_dir/all_urls.txt" ]; then
            run_cmd_with_retry \
                "url-extension -f $output_dir/all_urls.txt -o $output_dir/filtered-url-extention" \
                "URL Extension Filter" \
                "$error_log"
        else
            echo -e "${YELLOW}[!]${NC} No URLs to filter with url-extension"
        fi
    fi
}

phase_js_analysis() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"
    
    echo -e "\n${BLUE}[PHASE 5]${NC} JavaScript File Analysis"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    if [ ! -s "$output_dir/all_urls.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No URLs for JavaScript analysis"
        return
    fi
    
    echo -e "${YELLOW}[>]${NC} Extracting JavaScript URLs"
    grep -E "\.js($|\?)" "$output_dir/all_urls.txt" | sort -u > "$output_dir/javascript/js_urls.txt"
    
    if [ -s "$output_dir/javascript/js_urls.txt" ]; then
        echo -e "${YELLOW}[>]${NC} Filtering out noise JavaScript files"
        
        # Smart filtering: Remove only confirmed noise, keep everything else
        cat "$output_dir/javascript/js_urls.txt" | grep -v -E -i \
            -e "(cdn|cloudfront|aws|akamai|cloudflare|fastly|azureedge)\.(net|com)/" \
            -e "/(jquery[^/]*\.js|jquery\-[0-9])" \
            -e "/bootstrap[^/]*\.js" \
            -e "/react[^/]*\.js" \
            -e "/vue[^/]*\.js" \
            -e "/angular[^/]*\.js" \
            -e "/lodash[^/]*\.js" \
            -e "/underscore[^/]*\.js" \
            -e "/modernizr" \
            -e "/polyfill" \
            -e "/webpack\-runtime" \
            -e "/chunk\-[0-9]" \
            -e "/runtime\-[0-9]" \
            -e "/(gtm|tagmanager|google.*analytics)" \
            -e "/hotjar" \
            -e "/mixpanel" \
            -e "/segment\.js" \
            -e "/fbq\.js" \
            -e "/piwik\.js" \
            -e "/matomo\.js" \
            -e "/recaptcha" \
            -e "/hcaptcha" \
            -e "/stripe\.js" \
            -e "/paypal" \
            -e "/recaptcha/api\.js" \
            > "$output_dir/javascript/filtered_js_urls.txt"
        
        # Pattern 2: WordPress core JS (rarely have secrets)
        if grep -q -i "wp-" "$output_dir/javascript/filtered_js_urls.txt"; then
            mv "$output_dir/javascript/filtered_js_urls.txt" "$output_dir/javascript/filtered_js_urls.tmp"
            cat "$output_dir/javascript/filtered_js_urls.tmp" | grep -v -E -i \
                -e "/wp-includes/js/" \
                -e "/wp-content/themes/twenty[^/]*/" \
                -e "/wp-embed\.min\.js" \
                -e "/wp-emoji-release\.min\.js" \
                -e "/admin-bar\.min\.js" \
                -e "/mediaelement[^/]*\.js" \
                -e "/imgareaselect[^/]*\.js" \
                > "$output_dir/javascript/filtered_js_urls.txt"
            rm "$output_dir/javascript/filtered_js_urls.tmp"
        fi
        
        # Pattern 3: Remove build/node_modules if full paths are exposed
        mv "$output_dir/javascript/filtered_js_urls.txt" "$output_dir/javascript/filtered_js_urls.tmp"
        cat "$output_dir/javascript/filtered_js_urls.tmp" | grep -v -E \
            -e "/node_modules/[^/]+/dist/" \
            -e "/node_modules/[^/]+/build/" \
            -e "/bower_components/" \
            -e "/vendor/" \
            -e "/(dist|build|public|static)/[^/]+/chunk\-" \
            > "$output_dir/javascript/filtered_js_urls.txt"
        rm "$output_dir/javascript/filtered_js_urls.tmp"
        
        # Keep files that are more likely to be custom/interesting
        if [ -s "$output_dir/javascript/filtered_js_urls.txt" ]; then
            mv "$output_dir/javascript/filtered_js_urls.txt" "$output_dir/javascript/filtered_js_urls.tmp"
            
            # Create priority list
            cat "$output_dir/javascript/filtered_js_urls.tmp" | grep -E -i \
                -e "/(theme|themes)/" \
                -e "/(plugin|plugins)/" \
                -e "/(custom|customizer)/" \
                -e "/(admin|dashboard)/" \
                -e "/(api|ajax|rest|graphql)/" \
                -e "/(user|auth|login|register)/" \
                -e "/(payment|checkout|order)/" \
                -e "/(config|setting|configuration)/" \
                -e "/(app|application|main|index)\.js" \
                -e "/([0-9a-f]{8,})\.js" \
                -e "\.min\.js$" \
                > "$output_dir/javascript/high_priority_js.txt" 2>/dev/null || true
            
            # Combine: high priority first, then everything else
            if [ -s "$output_dir/javascript/high_priority_js.txt" ]; then
                cat "$output_dir/javascript/high_priority_js.txt" > "$output_dir/javascript/filtered_js_urls.txt"
                cat "$output_dir/javascript/filtered_js_urls.tmp" | grep -v -F -f "$output_dir/javascript/high_priority_js.txt" \
                    >> "$output_dir/javascript/filtered_js_urls.txt" 2>/dev/null || cat "$output_dir/javascript/filtered_js_urls.tmp" \
                    >> "$output_dir/javascript/filtered_js_urls.txt"
            else
                mv "$output_dir/javascript/filtered_js_urls.tmp" "$output_dir/javascript/filtered_js_urls.txt"
            fi
            rm -f "$output_dir/javascript/filtered_js_urls.tmp"
        fi
        
        local total_js_count=$(wc -l < "$output_dir/javascript/js_urls.txt")
        local filtered_js_count=$(wc -l < "$output_dir/javascript/filtered_js_urls.txt")
        
        echo -e "${YELLOW}[>]${NC} Filtered out $((total_js_count - filtered_js_count)) noise JavaScript files"
        echo -e "${YELLOW}[>]${NC} Remaining $filtered_js_count JavaScript files for analysis"
        
        if [ -s "$output_dir/javascript/filtered_js_urls.txt" ]; then
            echo -e "${YELLOW}[>]${NC} Downloading JavaScript files (prioritized)"
            mkdir -p "$output_dir/javascript/js_files"
            
            # Download high priority files first
            if [ -s "$output_dir/javascript/high_priority_js.txt" ]; then
                echo -e "${YELLOW}[>]${NC} Downloading $(wc -l < "$output_dir/javascript/high_priority_js.txt") high priority files"
                if command_exists down; then
                    down -u "$output_dir/javascript/high_priority_js.txt" -o "$output_dir/javascript/js_files" -p 20 -t 10 2>>"$error_log"
                fi
            fi
            
            # Download remaining files
            if command_exists down; then
                echo -e "${YELLOW}[>]${NC} Downloading remaining JavaScript files..."
                if [ -s "$output_dir/javascript/high_priority_js.txt" ]; then
                    grep -v -F -f "$output_dir/javascript/high_priority_js.txt" \
                        "$output_dir/javascript/filtered_js_urls.txt" > "$output_dir/javascript/remaining_js.txt" 2>/dev/null || \
                        cp "$output_dir/javascript/filtered_js_urls.txt" "$output_dir/javascript/remaining_js.txt"
                    
                    if [ -s "$output_dir/javascript/remaining_js.txt" ]; then
                        down -u "$output_dir/javascript/remaining_js.txt" -o "$output_dir/javascript/js_files" -p 20 -t 10 2>>"$error_log"
                    fi
                else
                    down -u "$output_dir/javascript/filtered_js_urls.txt" -o "$output_dir/javascript/js_files" -p 20 -t 10 2>>"$error_log"
                fi
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}[✓]${NC} JavaScript files downloaded successfully"
                else
                    echo -e "${YELLOW}[!]${NC} down command completed (check $error_log for details)"
                fi
            else
                echo -e "${YELLOW}[!]${NC} down not found. Skipping JavaScript file downloading."
            fi
            
            echo -e "${YELLOW}[>]${NC} Analyzing for secrets and endpoints"
            if command_exists jsscan; then
                # Run jsscan only on downloaded files
                if [ -d "$output_dir/javascript/js_files/success" ] && [ "$(ls -A "$output_dir/javascript/js_files/success" 2>/dev/null)" ]; then
                    run_cmd_with_retry \
                        "jsscan '$output_dir/javascript/js_files/success' -a > '$output_dir/javascript/secrets.txt' 2>/dev/null" \
                        "JavaScript Analysis" \
                        "$error_log"
                fi
                
                echo -e "${YELLOW}[>]${NC} Extracting potential endpoints from JS files"
                find "$output_dir/javascript/js_files/success" -name "*.js" -type f 2>/dev/null | while read js_file; do
                    echo "=== File: $(basename "$js_file") ===" >> "$output_dir/javascript/endpoints_raw.txt"
                    grep -E -n "['\"](https?:|/)[^'\"]{10,}['\"]|fetch\(|axios\.|XMLHttpRequest|\.(get|post|put|delete|patch)\(|api/|endpoint|url:|path:|route:" \
                        "$js_file" 2>/dev/null | head -30 >> "$output_dir/javascript/endpoints_raw.txt"
                    echo "" >> "$output_dir/javascript/endpoints_raw.txt"
                done
                
                # Clean and format endpoints
                if [ -f "$output_dir/javascript/endpoints_raw.txt" ]; then
                    grep -o -E "['\"](https?:|/)[^'\"]{10,}['\"]" "$output_dir/javascript/endpoints_raw.txt" | \
                        sed "s/^['\"]//;s/['\"]$//" | sort -u > "$output_dir/javascript/endpoints.txt"
                    
                    echo -e "${GREEN}[✓]${NC} Endpoints extracted: $(wc -l < "$output_dir/javascript/endpoints.txt")"
                    
                    # Create summary file
                    echo "JavaScript Analysis Summary" > "$output_dir/javascript/summary.txt"
                    echo "==========================" >> "$output_dir/javascript/summary.txt"
                    echo "Total JS URLs found: $total_js_count" >> "$output_dir/javascript/summary.txt"
                    echo "Filtered for analysis: $filtered_js_count" >> "$output_dir/javascript/summary.txt"
                    echo "High priority files: $(wc -l < "$output_dir/javascript/high_priority_js.txt" 2>/dev/null || echo 0)" >> "$output_dir/javascript/summary.txt"
                    echo "Unique endpoints found: $(wc -l < "$output_dir/javascript/endpoints.txt")" >> "$output_dir/javascript/summary.txt"
                    echo "" >> "$output_dir/javascript/summary.txt"
                    echo "Top endpoint patterns:" >> "$output_dir/javascript/summary.txt"
                    grep -o -E "(api|ajax|rest|graphql|wp-json)/[^'\"]*" "$output_dir/javascript/endpoints.txt" | \
                        sort | uniq -c | sort -rn | head -10 >> "$output_dir/javascript/summary.txt" 2>/dev/null
                fi
            else
                echo -e "${YELLOW}[!]${NC} jsscan not found. Skipping JavaScript analysis."
            fi
            
            echo -e "${GREEN}[✓]${NC} JavaScript analysis completed"
            echo -e "${YELLOW}[+]${NC} Total JS files found: $total_js_count"
            echo -e "${YELLOW}[+]${NC} Filtered for analysis: $filtered_js_count"
            if [ -s "$output_dir/javascript/high_priority_js.txt" ]; then
                echo -e "${YELLOW}[+]${NC} High priority files: $(wc -l < "$output_dir/javascript/high_priority_js.txt")"
            fi
            echo -e "${YELLOW}[+]${NC} Downloaded to: $output_dir/javascript/js_files/"
        else
            echo -e "${YELLOW}[!]${NC} No relevant JavaScript files to analyze after filtering"
        fi
    else
        echo -e "${YELLOW}[!]${NC} No JavaScript files found"
    fi
}

phase_vulnerability_scanning() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"
    
    echo -e "\n${BLUE}[PHASE 6]${NC} Vulnerability Pattern Matching"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    if [ ! -s "$output_dir/all_urls.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No URLs to scan"
        return
    fi
    
    # Filter and clean URLs
    cat "$output_dir/all_urls.txt" | uro 2>/dev/null | httpx -silent > "$output_dir/filtered-urls.txt" 2>/dev/null
    
    if [ ! -s "$output_dir/filtered-urls.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No filtered URLs for vulnerability scanning"
        return
    fi
    
    # Exclude static files
    cat "$output_dir/filtered-urls.txt" | grep -Eiv "\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)$" > "$output_dir/potential-url.txt"
    
    # Run pattern matching in parallel
    local pattern_commands=()
    local gf_patterns=("xss" "sqli" "lfi" "ssrf" "rce" "redirect" "ssti" "idor")
    
    for pattern in "${gf_patterns[@]}"; do
        pattern_commands+=(
            "cat '$output_dir/potential-url.txt' | gf '$pattern' > '$output_dir/vulnerability_scan/${pattern}.txt' 2>>'$error_log'; count=\$(wc -l < '$output_dir/vulnerability_scan/${pattern}.txt' 2>/dev/null || echo 0); echo 'desc:\"GF $pattern: '\$count' findings\"'"
        )
    done
    
    echo -e "${CYAN}[*]${NC} Running ${#gf_patterns[@]} pattern matching tasks in parallel..."
    
    local i=0
    for pattern in "${gf_patterns[@]}"; do
        echo -e "  [$(printf "%02d" $((i+1)))] GF $pattern"
        ((i++))
    done
    
    # Run commands in background
    local pids=()
    local i=0
    for pattern in "${gf_patterns[@]}"; do
        (
            cat "$output_dir/potential-url.txt" | gf "$pattern" > "$output_dir/vulnerability_scan/${pattern}.txt" 2>>"$error_log"
            local count=$(wc -l < "$output_dir/vulnerability_scan/${pattern}.txt" 2>/dev/null || echo 0)
            echo -e "  [$(printf "%02d" $((i+1)))] ${GREEN}✓${NC} GF $pattern: $count findings"
        ) &
        pids+=($!)
        ((i++))
        
        # Control concurrent jobs
        if [ ${#pids[@]} -ge $MAX_PARALLEL_JOBS ]; then
            wait -n
        fi
    done
    
    # Wait for all remaining jobs
    wait "${pids[@]}"
    
    # Display summary
    echo -e "${YELLOW}[>]${NC} Vulnerability Summary:"
    for pattern in "${gf_patterns[@]}"; do
        local count=$(wc -l < "$output_dir/vulnerability_scan/${pattern}.txt" 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            echo -e "  • ${pattern}: ${YELLOW}${count}${NC} potential findings"
        else
            echo -e "  • ${pattern}: ${GREEN}${count}${NC} potential findings"
        fi
    done
}
phase_dns_recon() {
    local domain=$1
    local output_dir=$2
    local fingerprint=$3
    local error_log="$output_dir/errors.log"
    local subdomain_file="$output_dir/all_subdomains.txt"
    
    echo -e "\n${BLUE}[PHASE 7]${NC} DNS & Network Intelligence"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    # Create directories for subdomain scan results
    mkdir -p "$output_dir/network/subdomains"
    mkdir -p "$output_dir/network/subdomain_dig"
    mkdir -p "$output_dir/network/subdomain_whois"
    
    # Parallel DNS reconnaissance for main domain
    local dns_commands=(
        "dnsrecon -d $domain -t std,axfr -c $output_dir/network/dnsrecon.csv 2>>$error_log; echo 'desc:\"DNSRecon (Main Domain)\"'"
        
        "{ for t in A AAAA MX NS TXT CNAME SOA TRACE; do echo \"=== \$t ===\"&& dig $domain \$t +short; done; } > $output_dir/network/dig_any.txt 2>>$error_log; echo 'desc:\"DIG (Main Domain)\"'"
        
        "whois $domain > $output_dir/network/whois.txt 2>>$error_log; echo 'desc:\"WHOIS (Main Domain)\"'"
    )
    
    # Add subdomain scanning commands if subdomains exist
    if [ -s "$subdomain_file" ]; then
        local subdomain_count=$(wc -l < "$subdomain_file")
        echo -e "${CYAN}[i]${NC} Scanning ${YELLOW}$subdomain_count${NC} discovered subdomains..."
        
        # 1. DNSRecon for all subdomains
        dns_commands+=(
            "while read sub; do [ -z \"\$sub\" ] && continue; safe=\$(echo \$sub | tr -cd '[:alnum:]_-'); timeout 15 dnsrecon -d \$sub -t std,axfr  -c \"$output_dir/network/subdomains/\${safe}_std.csv\" 2>>$error_log; done < \"$subdomain_file\"; echo 'desc:\"DNSRecon (All Subdomains)\"'"
        )
        
        # 2. DIG for all subdomains
        dns_commands+=(
            "while read sub; do [ -z \"\$sub\" ] && continue; safe=\$(echo \"\$sub\" | tr -cd '[:alnum:]_-'); { for t in A AAAA MX NS TXT CNAME SOA TRACE; do echo \"=== \$t ===\" && dig \"\$sub\" \$t +short 2>/dev/null; done; } > \"$output_dir/network/subdomain_dig/\${safe}.txt\" 2>>\"$error_log\"; done < \"$subdomain_file\"; echo 'desc:\"DIG (All Subdomains)\"'"
        )
        
        # 3. Subdomain takeover check
        if command_exists subjack; then
            dns_commands+=(
                "subjack -w $subdomain_file -t 20 -ssl -timeout 15 -v -c $fingerprint -o $output_dir/network/subdomain-takeover.txt 2>>$error_log; echo 'desc:\"Subjack (All Subdomains)\"'"
            )
        fi
    fi
    
    run_parallel "${dns_commands[@]}"
    echo -e "${GREEN}[✓]${NC} DNS reconnaissance completed for all subdomains"
}

phase_screenshots() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"
    
    echo -e "\n${BLUE}[PHASE 8]${NC} Screenshot Capture"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    if [ ! -s "$output_dir/alive_subdomains_https.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No URLs for screenshots"
        return
    fi
    
    # Find Chromium
    local CHROMIUM_PATH=""
    if command_exists chromium; then
        CHROMIUM_PATH="--chrome-path /snap/bin/chromium"
    elif command_exists chromium-browser; then
        CHROMIUM_PATH="--chrome-path /usr/bin/chromium-browser"
    fi
    
    if [ -z "$CHROMIUM_PATH" ]; then
        echo -e "${YELLOW}[!]${NC} Chromium not found. Skipping screenshots."
        return
    fi
    
    mkdir -p "$output_dir/gowitness_screenshots"
    
    run_cmd_with_retry \
        "gowitness scan file -f $output_dir/alive_subdomains_https.txt \
         $CHROMIUM_PATH \
         --threads 20 \
         --timeout 90 \
         --screenshot-path $output_dir/gowitness_screenshots \
         --screenshot-fullpage \
         --write-jsonl --write-jsonl-file gowitness.jsonl \
         --write-screenshots \
         --write-stdout" \
        "Gowitness Screenshots" \
        "$error_log"
    
    local count=$(find "$output_dir/gowitness_screenshots" -name "*.jpeg" 2>/dev/null | wc -l)
    echo -e "${GREEN}[✓]${NC} Captured $count screenshots"
}

phase_quick_checks() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"
    
    echo -e "\n${BLUE}[PHASE 9]${NC} Quick Bug Hunting Checks"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    if [ ! -s "$output_dir/alive_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive subdomains for quick checks"
        return
    fi
    
    # Check for exposed .git directories
    echo -e "${YELLOW}[>]${NC} Checking for exposed .git directories"
    run_cmd_with_retry \
        "cat $output_dir/alive_subdomains.txt | sed 's#\$#/.git/HEAD#g' | httpx -silent -content-length -status-code 200,301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 20 -title 2>/dev/null | sort -u > $output_dir/git_exposed.txt" \
        "Git Exposed Check" \
        "$error_log"
    
    # Check for open redirects
    echo -e "${YELLOW}[>]${NC} Checking for open redirects"
    if [ -f "$output_dir/vulnerability_scan/redirect.txt" ] && [ -s "$output_dir/vulnerability_scan/redirect.txt" ]; then
        local redirect_count=0
        while read -r url; do
            if curl -Is "$url" 2>/dev/null | grep -q "Location: https://evil.com"; then
                echo "VULN! $url" >> "$output_dir/vulnerability_scan/open_redirect_results.txt"
                ((redirect_count++))
            fi
        done < "$output_dir/vulnerability_scan/redirect.txt"
        echo -e "${GREEN}[✓]${NC} Found $redirect_count potential open redirects"
    fi
    
    echo -e "${GREEN}[✓]${NC} Quick checks completed"
}

generate_report() {
    local domain=$1
    local output_dir=$2
    local scan_type=$3
    local reports_dir="$output_dir/reports"
    
    echo -e "\n${BLUE}[REPORTING]${NC} Generating Enhanced HTML Report"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    # Collect statistics
    local subdomain_count=$(wc -l < "$output_dir/all_subdomains.txt" 2>/dev/null || echo 0)
    local alive_count=$(wc -l < "$output_dir/alive_subdomains.txt" 2>/dev/null || echo 0)
    local port_count=$(wc -l < "$output_dir/portscan/all_results.txt" 2>/dev/null || echo 0)
    local url_count=$(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo 0)
    local screenshot_count=$(find "$output_dir/gowitness_screenshots" -name "*.jpeg" 2>/dev/null | wc -l)
    local js_count=$(wc -l < "$output_dir/javascript/js_urls.txt" 2>/dev/null || echo 0)
    local git_exposed_count=$(wc -l < "$output_dir/git_exposed.txt" 2>/dev/null || echo 0)
    
    # Calculate vulnerability counts
    declare -A vuln_counts
    local gf_patterns=("xss" "sqli" "lfi" "ssrf" "rce" "redirect" "ssti" "idor")
    
    for pattern in "${gf_patterns[@]}"; do
        vuln_counts[$pattern]=$(wc -l < "$output_dir/vulnerability_scan/${pattern}.txt" 2>/dev/null || echo 0)
    done
    
    # Create Enhanced HTML report with professional hacker theme
    cat > "$reports_dir/report.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report: DOMAIN_PLACEHOLDER</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #0a0e27;
            --bg-secondary: #10162b;
            --bg-tertiary: #151d38;
            --accent-primary: #00ff41;
            --accent-secondary: #00d4aa;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --border-color: #1f2937;
            --danger: #ff4444;
            --warning: #ffaa00;
            --info: #00aaff;
        }
        
        body {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background: linear-gradient(135deg, var(--bg-primary) 0%, #0d1225 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
        }
        
        h1 {
            font-size: 2.2em;
            color: var(--accent-primary);
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
            letter-spacing: 1px;
        }
        
        .timestamp {
            color: var(--text-secondary);
            font-size: 0.9em;
            font-family: monospace;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin: 30px 0;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: var(--accent-primary);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            border-color: var(--accent-primary);
            box-shadow: 0 5px 20px rgba(0, 255, 65, 0.2);
        }
        
        .stat-card:hover::before {
            transform: scaleX(1);
        }
        
        .stat-label {
            font-size: 0.85em;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: var(--accent-primary);
            text-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
        }
        
        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
        }
        
        h2 {
            color: var(--accent-secondary);
            font-size: 1.5em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        
        th {
            background: var(--bg-tertiary);
            color: var(--accent-primary);
            padding: 12px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        
        tr:hover {
            background: var(--bg-tertiary);
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .badge-critical { background: var(--danger); color: white; }
        .badge-high { background: #ff6b00; color: white; }
        .badge-medium { background: var(--warning); color: #000; }
        .badge-low { background: var(--info); color: white; }
        .badge-none { background: var(--accent-primary); color: #000; }
        
        .screenshot-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .screenshot-item {
            border: 1px solid var(--border-color);
            border-radius: 6px;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .screenshot-item:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 255, 65, 0.2);
            border-color: var(--accent-primary);
        }
        
        .screenshot-item img {
            width: 100%;
            height: 180px;
            object-fit: cover;
            display: block;
        }
        
        .screenshot-caption {
            padding: 10px;
            background: var(--bg-tertiary);
            font-size: 0.75em;
            color: var(--text-secondary);
            text-align: center;
            word-break: break-all;
        }
        
        .code-block {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            color: var(--accent-primary);
        }
        
        .links-list {
            list-style: none;
        }
        
        .links-list li {
            padding: 10px 0;
            border-bottom: 1px solid var(--border-color);
        }
        
        .links-list a {
            color: var(--accent-secondary);
            text-decoration: none;
            transition: color 0.3s ease;
        }
        
        .links-list a:hover {
            color: var(--accent-primary);
            text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
        }
        
        .footer {
            margin-top: 40px;
            padding: 20px;
            text-align: center;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
        }
        
        .progress-tracker {
            display: flex;
            justify-content: space-between;
            margin: 30px 0;
            padding: 20px;
            background: var(--bg-tertiary);
            border-radius: 8px;
            flex-wrap: wrap;
        }
        
        .phase {
            text-align: center;
            flex: 1;
            min-width: 100px;
            padding: 10px;
        }
        
        .phase-number {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--accent-primary);
            color: var(--bg-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 10px;
            font-weight: bold;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.5);
        }
        
        .phase-label {
            font-size: 0.75em;
            color: var(--text-secondary);
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .screenshot-grid {
                grid-template-columns: 1fr;
            }
            
            .progress-tracker {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ RECON REPORT: DOMAIN_PLACEHOLDER</h1>
            <div class="timestamp">» Generated: TIMESTAMP_PLACEHOLDER</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">🌐 Subdomains</div>
                <div class="stat-value">SUBDOMAIN_COUNT</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">✓ Alive</div>
                <div class="stat-value">ALIVE_COUNT</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">🔓 Ports</div>
                <div class="stat-value">PORT_COUNT</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">📄 URLs</div>
                <div class="stat-value">URL_COUNT</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">📸 Screenshots</div>
                <div class="stat-value">SCREENSHOT_COUNT</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">📜 JS Files</div>
                <div class="stat-value">JS_COUNT</div>
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ VULNERABILITY ANALYSIS</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Findings</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
VULN_TABLE_ROWS
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>📸 SCREENSHOT GALLERY</h2>
            <div class="screenshot-grid">
SCREENSHOT_GALLERY
            </div>
        </div>
        
        <div class="section">
            <h2>📂 OUTPUT STRUCTURE</h2>
            <div class="code-block">
recon_TIMESTAMP/$domain/
├── all_subdomains.txt          # All discovered subdomains
├── alive_subdomains.txt        # Active web services
├── all_urls.txt                # All discovered URLs
├── portscan/                   # Port scanning results
│   ├── nmap_scan.*            # Nmap scan results
│   └── naabu_results.txt      # Naabu scan results
├── urls/                       # URL collection results
├── javascript/                 # JavaScript analysis
├── vulnerability_scan/         # Vulnerability patterns
├── network/                    # DNS and network recon
├── gowitness_screenshots/     # Website screenshots
├── filtered-url-extention/    # Filtered URLs by extension
├── reports/                    # This HTML report
└── errors.log                  # Error log
            </div>
        </div>
        
        <div class="section">
            <h2>🔗 QUICK ACCESS</h2>
            <ul class="links-list">
                <li>📋 <a href="../all_subdomains.txt" target="_blank">All Subdomains</a> (SUBDOMAIN_COUNT found)</li>
                <li>🌐 <a href="../alive_subdomains.txt" target="_blank">Alive Services</a> (ALIVE_COUNT found)</li>
                <li>🔗 <a href="../all_urls.txt" target="_blank">All URLs</a> (URL_COUNT found)</li>
                <li>🔓 <a href="../portscan/nmap_scan.nmap" target="_blank">Nmap Results</a></li>
                <li>📇 <a href="../network/whois.txt" target="_blank">WHOIS Information</a></li>
                <li>📜 <a href="../javascript/js_urls.txt" target="_blank">JavaScript URLs</a> (JS_COUNT found)</li>
                <li>🔓 <a href="../git_exposed.txt" target="_blank">Git Exposed</a> (GIT_COUNT found)</li>
            </ul>
        </div>
        
        <div class="progress-tracker">
            <div class="phase">
                <div class="phase-number">1</div>
                <div class="phase-label">Subdomain Enum</div>
            </div>
            <div class="phase">
                <div class="phase-number">2</div>
                <div class="phase-label">Port Scan</div>
            </div>
            <div class="phase">
                <div class="phase-number">3</div>
                <div class="phase-label">Web Discovery</div>
            </div>
            <div class="phase">
                <div class="phase-number">4</div>
                <div class="phase-label">URL Collection</div>
            </div>
            <div class="phase">
                <div class="phase-number">5</div>
                <div class="phase-label">JS Analysis</div>
            </div>
            <div class="phase">
                <div class="phase-number">6</div>
                <div class="phase-label">Vuln Scan</div>
            </div>
            <div class="phase">
                <div class="phase-number">7</div>
                <div class="phase-label">DNS Recon</div>
            </div>
            <div class="phase">
                <div class="phase-number">8</div>
                <div class="phase-label">Screenshots</div>
            </div>
            <div class="phase">
                <div class="phase-number">9</div>
                <div class="phase-label">Quick Checks</div>
            </div>
        </div>
        
        <div class="footer">
            <p style="font-size: 1.2em; color: var(--accent-primary); margin-bottom: 10px;">
                ⚡ <strong>Shakibul's Recon Pipeline v3.3</strong> ⚡
            </p>
            <p>Created by: <strong>Shakibul (Shakibul_Cybersec)</strong></p>
            <p>Execution: EXEC_TIME seconds | Mode: SCAN_TYPE | Jobs: MAX_JOBS</p>
            <p style="font-size: 0.85em; margin-top: 15px; color: var(--text-secondary);">
                ⚠️ Authorized testing only • Validate findings manually
            </p>
        </div>
    </div>
</body>
</html>
EOF

    # Now replace placeholders
    sed -i "s/DOMAIN_PLACEHOLDER/$domain/g" "$reports_dir/report.html"
    sed -i "s/TIMESTAMP_PLACEHOLDER/$(date '+%Y-%m-%d %H:%M:%S')/g" "$reports_dir/report.html"
    sed -i "s/SUBDOMAIN_COUNT/$subdomain_count/g" "$reports_dir/report.html"
    sed -i "s/ALIVE_COUNT/$alive_count/g" "$reports_dir/report.html"
    sed -i "s/PORT_COUNT/$port_count/g" "$reports_dir/report.html"
    sed -i "s/URL_COUNT/$url_count/g" "$reports_dir/report.html"
    sed -i "s/SCREENSHOT_COUNT/$screenshot_count/g" "$reports_dir/report.html"
    sed -i "s/JS_COUNT/$js_count/g" "$reports_dir/report.html"
    sed -i "s/GIT_COUNT/$git_exposed_count/g" "$reports_dir/report.html"
    sed -i "s/EXEC_TIME/$SECONDS/g" "$reports_dir/report.html"
    sed -i "s/SCAN_TYPE/$scan_type/g" "$reports_dir/report.html"
    sed -i "s/MAX_JOBS/$MAX_PARALLEL_JOBS/g" "$reports_dir/report.html"
    
    # Generate vulnerability table rows
    local vuln_rows=""
    for pattern in "${gf_patterns[@]}"; do
        count=${vuln_counts[$pattern]}
        
        if [ "$count" -gt 20 ]; then
            severity="critical"
            badge="badge-critical"
        elif [ "$count" -gt 10 ]; then
            severity="high"
            badge="badge-high"
        elif [ "$count" -gt 5 ]; then
            severity="medium"
            badge="badge-medium"
        elif [ "$count" -gt 0 ]; then
            severity="low"
            badge="badge-low"
        else
            severity="none"
            badge="badge-none"
        fi
        
        vuln_rows+="                    <tr><td>$pattern</td><td>$count</td><td><span class='badge $badge'>$severity</span></td></tr>\n"
    done
    
    # Replace vulnerability table
    sed -i "s|VULN_TABLE_ROWS|$vuln_rows|g" "$reports_dir/report.html"
    
    # Generate screenshot gallery
    local screenshots=""
    if [ -d "$output_dir/gowitness_screenshots" ]; then
        find "$output_dir/gowitness_screenshots" -type f -name "*.jpeg" | head -6 | while read img; do
            img_base=$(basename "$img")
            domain_name=$(echo "$img_base" | sed 's/.jpeg//')
            screenshots+="                <div class='screenshot-item'><a href='../gowitness_screenshots/$img_base' target='_blank'><img src='../gowitness_screenshots/$img_base' alt='$domain_name'></a><div class='screenshot-caption'>$domain_name</div></div>\n"
        done
        
        if [ -z "$screenshots" ]; then
            screenshots="                <p style='color: var(--text-secondary); text-align: center;'>No screenshots available</p>"
        fi
    else
        screenshots="                <p style='color: var(--text-secondary); text-align: center;'>No screenshots available</p>"
    fi
    
    sed -i "s|SCREENSHOT_GALLERY|$screenshots|g" "$reports_dir/report.html"
    
    echo -e "${GREEN}[✓]${NC} Enhanced HTML report generated: $reports_dir/report.html"
}
# --------------- Main Execution Functions with Resume Support ---------------
run_recon_pipeline() {
    local domain=$1
    local output_dir=$2
    local scan_type=$3
    local wordlist=$4
    local resolvers=$5
    local fingerprint=$6
    local exclude_list=$7
    
    echo -e "${GREEN}[+]${NC} Starting reconnaissance for: $domain"
    echo -e "${GREEN}[+]${NC} Output directory: $output_dir"
    echo -e "${GREEN}[+]${NC} Parallel jobs: $MAX_PARALLEL_JOBS | Timeout: ${TIMEOUT_SECONDS}s"
    
    # Create directory structure
    mkdir -p "$output_dir"/{reports,portscan,urls,javascript,vulnerability_scan,network,filtered-url-extention}
    
    local error_log="$output_dir/errors.log"
    > "$error_log"
    
    # Initialize resume system
    init_resume_system "$output_dir"
    
    # Load checkpoint if exists
    local resume_phase=0
    local resume_status=""
    if load_checkpoint "$output_dir"; then
        resume_phase=$PHASE
        resume_status=$STATUS
        echo -e "${CYAN}[*]${NC} Resuming from saved state..."
    fi
    
    # Phase 0: Root domain check
    if [ "$scan_type" == "root" ]; then
        echo "$domain" > "$output_dir/all_subdomains.txt"
        echo -e "${YELLOW}[*]${NC} Running in root domain only mode"
        save_checkpoint "$output_dir" "0" "$domain" "COMPLETED"
    else
        # Phase 1: Subdomain Enumeration
        if should_run_phase 1 $resume_phase "$resume_status"; then
            save_checkpoint "$output_dir" "1" "$domain" "RUNNING"
            phase_subdomain_enum "$domain" "$output_dir" "$wordlist" "$resolvers"
            mark_phase_complete "$output_dir" "1" "$domain"
        fi
    fi
    
    # Phase 2: Port Scanning
    if should_run_phase 2 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "2" "$domain" "RUNNING"
        phase_port_scanning "$output_dir"
        mark_phase_complete "$output_dir" "2" "$domain"
    fi
    
    # Phase 3: Web Discovery
    if should_run_phase 3 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "3" "$domain" "RUNNING"
        phase_web_discovery "$domain" "$output_dir"
        mark_phase_complete "$output_dir" "3" "$domain"
    fi
    
    # Phase 4: URL Collection
    if should_run_phase 4 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "4" "$domain" "RUNNING"
        phase_url_collection "$domain" "$output_dir"
        mark_phase_complete "$output_dir" "4" "$domain"
    fi
    
    # Phase 5: JavaScript Analysis
    if should_run_phase 5 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "5" "$domain" "RUNNING"
        phase_js_analysis "$output_dir"
        mark_phase_complete "$output_dir" "5" "$domain"
    fi
    
    # Phase 6: Vulnerability Scanning
    if should_run_phase 6 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "6" "$domain" "RUNNING"
        phase_vulnerability_scanning "$output_dir"
        mark_phase_complete "$output_dir" "6" "$domain"
    fi
    
    # Phase 7: DNS Reconnaissance
    if should_run_phase 7 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "7" "$domain" "RUNNING"
        phase_dns_recon "$domain" "$output_dir" "$fingerprint"
        mark_phase_complete "$output_dir" "7" "$domain"
    fi
    
    # Phase 8: Screenshots
    if should_run_phase 8 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "8" "$domain" "RUNNING"
        phase_screenshots "$output_dir"
        mark_phase_complete "$output_dir" "8" "$domain"
    fi
    
    # Phase 9: Quick Checks
    if should_run_phase 9 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "9" "$domain" "RUNNING"
        phase_quick_checks "$output_dir"
        mark_phase_complete "$output_dir" "9" "$domain"
    fi
    
    # Generate report
    echo -e "\n${CYAN}[*]${NC} Generating final report..."
    generate_report "$domain" "$output_dir" "$scan_type"
    
    # Mark scan as complete
    save_checkpoint "$output_dir" "10" "$domain" "COMPLETE"
    
    # Final summary
    show_domain_summary "$output_dir" "$domain"
    
    # Cleanup resume state (archive it)
    cleanup_resume_state "$output_dir"
}

show_domain_summary() {
    local output_dir=$1
    local domain=$2
    
    local subdomain_count=$(wc -l < "$output_dir/all_subdomains.txt" 2>/dev/null || echo 0)
    local alive_count=$(wc -l < "$output_dir/alive_subdomains.txt" 2>/dev/null || echo 0)
    local port_count=$(wc -l < "$output_dir/portscan/all_results.txt" 2>/dev/null || echo 0)
    local url_count=$(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo 0)
    local screenshot_count=$(find "$output_dir/gowitness_screenshots" -name "*.jpeg" 2>/dev/null | wc -l)
    local js_count=$(wc -l < "$output_dir/javascript/js_urls.txt" 2>/dev/null || echo 0)
    local git_exposed_count=$(wc -l < "$output_dir/git_exposed.txt" 2>/dev/null || echo 0)
    
    echo -e "\n${GREEN}[++]${NC} Reconnaissance Complete for $domain"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} SUMMARY${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "• Subdomains Discovered:    ${GREEN}$subdomain_count${NC}"
    echo -e "• Web Services Alive:       ${GREEN}$alive_count${NC}"
    echo -e "• Open Ports Found:         ${GREEN}$port_count${NC}"
    echo -e "• Unique URLs Collected:    ${GREEN}$url_count${NC}"
    echo -e "• Screenshots Captured:     ${GREEN}$screenshot_count${NC}"
    echo -e "• JavaScript Files:         ${GREEN}$js_count${NC}"
    echo -e "• Git Exposed:              ${GREEN}$git_exposed_count${NC}"
    
    local gf_patterns=("xss" "sqli" "lfi" "ssrf" "rce" "redirect" "ssti" "idor")
    echo -e "• Vulnerability Patterns:"
    for pattern in "${gf_patterns[@]}"; do
        local count=$(wc -l < "$output_dir/vulnerability_scan/${pattern}.txt" 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            echo -e "   - ${pattern}: ${YELLOW}${count}${NC} potential findings"
        else
            echo -e "   - ${pattern}: ${GREEN}${count}${NC} potential findings"
        fi
    done
    
    echo -e "\n${GREEN}[+]${NC} Report: ${BLUE}$output_dir/reports/report.html${NC}"
    echo -e "${GREEN}[+]${NC} Full Results: ${BLUE}$output_dir/${NC}"
    echo -e "${PURPLE}[+]${NC} Created by: Shakibul (Shakibul_Cybersec)${NC}"
}

configure_scan() {
    echo -e "${CYAN}[*]${NC} Configuration"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    echo -e "${PURPLE}[i]${NC} Script by: Shakibul (Shakibul_Cybersec)${NC}"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    # Scan mode
    echo -e "${YELLOW}Select scan mode:${NC}"
    echo "1. Root domain only (fast)"
    echo "2. Full reconnaissance (comprehensive)"
    read -p "Mode (1/2): " mode_choice
    
    case $mode_choice in
        1) scan_type="root" ;;
        2) scan_type="full" ;;
        *) scan_type="full" ;;
    esac
    
    exclude_list=""
    if [ "$scan_type" == "full" ]; then
        # Exclusions
        read -p "Exclude subdomains? (y/n): " exclude_choice
        if [[ $exclude_choice =~ ^[Yy]$ ]]; then
            read -p "Path to exclusion file: " exclude_file
            [ -f "$exclude_file" ] && exclude_list="$exclude_file"
        fi
        
        # Resources
        configure_resources
    fi
}

configure_resources() {
    echo -e "\n${CYAN}[*]${NC} Resource Configuration"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    
    # Wordlist
    echo -e "${BLUE}Note:${NC} Default wordlist: ${GREEN}$DEFAULT_WORDLIST${NC}"
    echo -e "Press Enter to use default, or provide custom path"
    read -p "Enter path to subdomain wordlist: " user_wordlist
    wordlist="${user_wordlist:-$DEFAULT_WORDLIST}"
    validate_file "$wordlist" "Wordlist" || exit 1
    
    # Resolvers
    echo -e "\n${BLUE}Note:${NC} Default resolvers: ${GREEN}$DEFAULT_RESOLVERS${NC}"
    echo -e "Press Enter to use default, or provide custom path"
    read -p "Enter path to DNS resolvers file: " user_resolvers
    resolvers="${user_resolvers:-$DEFAULT_RESOLVERS}"
    validate_file "$resolvers" "Resolvers" || exit 1
    
    # Fingerprint
    echo -e "\n${BLUE}Note:${NC} Default fingerprint: ${GREEN}$DEFAULT_FINGERPRINT${NC}"
    echo -e "Press Enter to use default, or provide custom path"
    read -p "Enter path to fingerprint file: " user_fingerprint
    fingerprint="${user_fingerprint:-$DEFAULT_FINGERPRINT}"
    validate_file "$fingerprint" "Fingerprint" || exit 1
    
    echo -e "${GREEN}[+]${NC} Resources configured"
}

show_summary() {
    local output_dir=$1
    local target_count=$2
    local total_time=$3
    
    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} RECONNAISSANCE COMPLETE ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "• Targets Processed:  ${target_count}"
    echo -e "• Total Time:         ${total_time} seconds"
    echo -e "• Output Directory:   ${output_dir}/"
    echo -e "• Scan Mode:          ${scan_type}"
    echo -e "• Parallel Jobs:      ${MAX_PARALLEL_JOBS}"
    echo -e "• Timeout per task:   ${TIMEOUT_SECONDS}s"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Happy Hunting! 🚀${NC}"
}

check_resume_option() {
    # Check if there are any existing recon directories with resume state
    local resume_dirs=$(find . -maxdepth 2 -type d -name "$STATE_DIR" 2>/dev/null)
    
    if [ -n "$resume_dirs" ]; then
        echo -e "${YELLOW}[!]${NC} Found incomplete reconnaissance sessions:"
        echo ""
        
        local count=1
        declare -A dir_map
        
        while IFS= read -r state_dir; do
            local parent_dir=$(dirname "$state_dir")
            local checkpoint_file="$state_dir/$CHECKPOINT_FILE"
            
            if [ -f "$checkpoint_file" ]; then
                source "$checkpoint_file"
                echo -e "  ${count}. ${CYAN}$parent_dir${NC}"
                echo -e "     Domain: ${YELLOW}$DOMAIN${NC}"
                echo -e "     Last Phase: ${YELLOW}$PHASE${NC} | Status: ${YELLOW}$STATUS${NC}"
                echo -e "     Last Update: ${YELLOW}$LAST_UPDATE${NC}"
                echo ""
                dir_map[$count]="$parent_dir"
                ((count++))
            fi
        done <<< "$resume_dirs"
        
        echo -e "  ${count}. Start a new scan"
        echo ""
        read -p "Choose option (1-$count): " choice
        
        if [ "$choice" -ge 1 ] && [ "$choice" -lt "$count" ]; then
            resume_dir="${dir_map[$choice]}"
            echo -e "${GREEN}[+]${NC} Resuming scan in: $resume_dir"
            return 0
        fi
    fi
    
    return 1
}

# --------------- Main Execution ---------------
main() {
    show_banner
    
    # Check tools
    check_tools
    
    # Setup proxy
    setup_proxy
    
    # Check resources
    check_resources $MEMORY_THRESHOLD
    
    # Check for resume option
    local resume_dir=""
    if check_resume_option; then
        # Resume existing scan
        if [ -f "$resume_dir/$STATE_DIR/$CHECKPOINT_FILE" ]; then
            source "$resume_dir/$STATE_DIR/$CHECKPOINT_FILE"
            local domain_to_resume="$DOMAIN"
            
            # Load previous configuration
            echo -e "${CYAN}[*]${NC} Loading previous configuration..."
            
            # Set default scan type
            scan_type="full"
            
            # Use default resources
            wordlist="$DEFAULT_WORDLIST"
            resolvers="$DEFAULT_RESOLVERS"
            fingerprint="$DEFAULT_FINGERPRINT"
            
            # Resume the scan
            local domain_start=$SECONDS
            run_recon_pipeline "$domain_to_resume" "$resume_dir" "$scan_type" "$wordlist" "$resolvers" "$fingerprint" ""
            local domain_time=$((SECONDS - domain_start))
            
            echo -e "\n${GREEN}[✓]${NC} Resumed scan completed in ${domain_time}s"
            exit 0
        fi
    fi
    
    # Get target (new scan)
    if [ -z "$1" ]; then
        read -p "Enter target domain or path to target file: " target_input
    else
        target_input="$1"
    fi
    
    if [ -z "$target_input" ]; then
        echo -e "${RED}[!] No target provided${NC}"
        exit 1
    fi
    
    # Configuration
    configure_scan
    
    # Create output directory
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local main_output_dir="recon_${timestamp}"
    mkdir -p "$main_output_dir"
    
    # Process each target
    local target_count=0
    local total_start=$SECONDS

    # Read all targets from file or single target
    if [ -f "$target_input" ]; then
        echo -e "${GREEN}[+]${NC} Loading targets from file: $target_input"
        # Read all targets into an array
        mapfile -t targets < "$target_input"
    else
        # Single target
        targets=("$target_input")
    fi
    
    for domain in "${targets[@]}"; do
        # Clean the domain
        domain=$(echo "$domain" | sed 's/[[:space:]]*$//' | xargs)
        [ -z "$domain" ] && continue
        
        # Skip comments
        [[ "$domain" =~ ^#.* ]] && continue
        
        ((target_count++))
        
        echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN} TARGET [$target_count]: $domain ${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
        
        validate_domain "$domain" || {
            echo -e "${RED}[!]${NC} Skipping invalid domain: $domain"
            continue
        }
        
        local domain_dir="$main_output_dir/$domain"
        
        local domain_start=$SECONDS
        run_recon_pipeline "$domain" "$domain_dir" "$scan_type" "$wordlist" "$resolvers" "$fingerprint" "$exclude_list"
        local domain_time=$((SECONDS - domain_start))
        
        echo -e "\n${GREEN}[✓]${NC} Completed in ${domain_time}s"
        echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
        sleep 2
    done
    
    local total_time=$((SECONDS - total_start))
    
    # Final summary
    show_summary "$main_output_dir" "$target_count" "$total_time"
}

# Run main
main "$@"
