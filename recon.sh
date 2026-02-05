#!/bin/bash
# Ultra-Fast Bug Bounty Recon & Vulnerability Discovery Pipeline
# Author: Shakibul (Shakibul_Cybersec)

set -euo pipefail

GLOBAL_LOG="/tmp/recon_early.log"
VERBOSE=0
SKIP_NUCLEI=0
RUN_NUCLEI=0
TEMP_FILES=()
USE_TOR=0

MAX_CONCURRENT_JOBS=5
JOB_CHECK_INTERVAL=0.5
RATE_LIMIT_DELAY=1
MAX_RATE_LIMIT_DELAY=60
BACKOFF_MULTIPLIER=2

declare -A RUNNING_JOBS=()
JOB_COUNTER=0

cleanup_trap() {
    local exit_code=$?
    
    if [ "${#TEMP_FILES[@]}" -gt 0 ]; then
        for temp_file in "${TEMP_FILES[@]}"; do
            if [ -f "$temp_file" ]; then
                rm -f "$temp_file" 2>/dev/null || true
            fi
        done
    fi
    
    rm -f "/tmp/cdn_ranges_$$.txt" 2>/dev/null || true
    rm -f "/tmp/recon_early.log" 2>/dev/null || true
    
    if [ "$exit_code" -ne 0 ]; then
        echo -e "${RED}[FATAL]${NC} Script exited unexpectedly with code $exit_code" 2>/dev/null || true
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] FATAL EXIT code=$exit_code | Cleaned up ${#TEMP_FILES[@]} temp files" >> "$GLOBAL_LOG" 2>/dev/null || true
    fi
}
trap cleanup_trap EXIT

wait_for_job_slot() {
    while true; do
        local running_count=0
        for pid in "${!RUNNING_JOBS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                ((running_count++))
            else
                unset RUNNING_JOBS["$pid"]
            fi
        done
        
        if [ "$running_count" -lt "$MAX_CONCURRENT_JOBS" ]; then
            break
        fi
        
        sleep "$JOB_CHECK_INTERVAL"
    done
}

register_job() {
    local pid=$1
    local description=${2:-"unnamed job"}
    RUNNING_JOBS["$pid"]="$description"
    vlog "Registered job PID=$pid: $description"
}

wait_for_all_jobs() {
    local timeout=${1:-0}
    local start_time=$SECONDS
    
    while [ "${#RUNNING_JOBS[@]}" -gt 0 ]; do
        for pid in "${!RUNNING_JOBS[@]}"; do
            if ! kill -0 "$pid" 2>/dev/null; then
                unset RUNNING_JOBS["$pid"]
            fi
        done
        
        if [ "$timeout" -gt 0 ]; then
            local elapsed=$((SECONDS - start_time))
            if [ "$elapsed" -ge "$timeout" ]; then
                echo -e "${YELLOW}[!]${NC} Job timeout reached ($timeout seconds), terminating remaining jobs"
                for pid in "${!RUNNING_JOBS[@]}"; do
                    kill -TERM "$pid" 2>/dev/null || true
                done
                sleep 2
                for pid in "${!RUNNING_JOBS[@]}"; do
                    kill -KILL "$pid" 2>/dev/null || true
                done
                RUNNING_JOBS=()
                return 1
            fi
        fi
        
        [ "${#RUNNING_JOBS[@]}" -gt 0 ] && sleep "$JOB_CHECK_INTERVAL"
    done
    
    return 0
}

rate_limit_sleep() {
    local attempt=${1:-0}
    local base_delay=${2:-$RATE_LIMIT_DELAY}
    
    if [ "$attempt" -gt 0 ]; then
        local delay=$((base_delay * (BACKOFF_MULTIPLIER ** (attempt - 1))))
        if [ "$delay" -gt "$MAX_RATE_LIMIT_DELAY" ]; then
            delay=$MAX_RATE_LIMIT_DELAY
        fi
        vlog "Rate limit backoff: sleeping ${delay}s (attempt $attempt)"
        sleep "$delay"
    fi
}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051

DEFAULT_RESOURCE_DIR="/usr/share/default-recon-resources"
DEFAULT_WORDLIST="$DEFAULT_RESOURCE_DIR/subdomains-top1million-5000.txt"
DEFAULT_RESOLVERS="$DEFAULT_RESOURCE_DIR/resolvers.txt"
DEFAULT_FINGERPRINT="$DEFAULT_RESOURCE_DIR/fingerprint.json"

MAX_PARALLEL_JOBS=10
MAX_RETRIES=3
TIMEOUT_SECONDS=2700
NMAP_TIMEOUT=5400
NUCLEI_TIMEOUT=7200
MEMORY_THRESHOLD=2048

NAABU_RATE=2000
HTTPX_THREADS=100
KATANA_CONCURRENCY=50
NUCLEI_RATE_LIMIT=150
NUCLEI_CONCURRENCY=25

STATE_DIR=".recon_state"
CHECKPOINT_FILE="checkpoint.txt"
PROGRESS_FILE="progress.log"

register_temp_file() {
    local file="$1"
    TEMP_FILES+=("$file")
    vlog "Registered temp file for cleanup: $file"
}

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$GLOBAL_LOG" 2>/dev/null || true
}

vlog() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo -e "${CYAN}[VERBOSE]${NC} $*"
    fi
    log_msg "VERBOSE: $*"
}



# ============ RESUME FUNCTIONS ============

init_resume_system() {
    local output_dir="$1"
    local state_path="$output_dir/$STATE_DIR"

    mkdir -p "$state_path"

    # Initialize checkpoint file if it doesn't exist
    if [ ! -f "$state_path/$CHECKPOINT_FILE" ]; then
        cat > "$state_path/$CHECKPOINT_FILE" <<EOF
PHASE=0
DOMAIN=
TIMESTAMP=$(date +%s)
STATUS=STARTED
LAST_UPDATE="$(date '+%Y-%m-%d %H:%M:%S')"
EOF
    fi

    # Initialize progress log
    if [ ! -f "$state_path/$PROGRESS_FILE" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Reconnaissance initialized" > "$state_path/$PROGRESS_FILE"
    fi
}

save_checkpoint() {
    local output_dir="$1"
    local phase="$2"
    local domain="$3"
    local status="$4"
    local state_path="$output_dir/$STATE_DIR"

    cat > "$state_path/$CHECKPOINT_FILE" <<EOF
PHASE=$phase
DOMAIN=$domain
TIMESTAMP=$(date +%s)
STATUS=$status
LAST_UPDATE="$(date '+%Y-%m-%d %H:%M:%S')"
EOF

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Phase $phase: $status" >> "$state_path/$PROGRESS_FILE"
    log_msg "Checkpoint saved: phase=$phase status=$status"
}

load_checkpoint() {
    local output_dir="$1"
    local state_path="$output_dir/$STATE_DIR"

    if [ -f "$state_path/$CHECKPOINT_FILE" ]; then
        # Safe defaults — protects against old/incomplete checkpoint files on disk
        PHASE=0
        DOMAIN=""
        TIMESTAMP=0
        STATUS="UNKNOWN"
        LAST_UPDATE="N/A"
        
        # Manually parse checkpoint file instead of sourcing (more secure)
        while IFS='=' read -r key value; do
            # Remove any leading/trailing whitespace
            key=$(echo "$key" | xargs)
            value=$(echo "$value" | xargs)
            
            case "$key" in
                PHASE)
                    # Validate PHASE is a number or decimal
                    if [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                        PHASE="$value"
                    fi
                    ;;
                DOMAIN)
                    # Store domain (will be validated later)
                    DOMAIN="$value"
                    ;;
                TIMESTAMP)
                    if [[ "$value" =~ ^[0-9]+$ ]]; then
                        TIMESTAMP="$value"
                    fi
                    ;;
                STATUS)
                    STATUS="$value"
                    ;;
                LAST_UPDATE)
                    LAST_UPDATE="$value"
                    ;;
            esac
        done < "$state_path/$CHECKPOINT_FILE"
        
        echo -e "${YELLOW}[!]${NC} Resuming from Phase $PHASE"
        echo -e "${YELLOW}[!]${NC} Last status: $STATUS"
        echo -e "${YELLOW}[!]${NC} Last update: $LAST_UPDATE"
        log_msg "Checkpoint loaded: phase=$PHASE status=$STATUS"
        return 0
    else
        return 1
    fi
}

should_run_phase() {
    local current_phase="$1"
    local saved_phase="$2"
    local saved_status="$3"

    # Convert phase numbers to comparable format (handle decimals like 5.5, 5.6, etc.)
    # Use awk for floating point comparison since bash only handles integers
    local phase_greater=$(awk -v saved="$saved_phase" -v current="$current_phase" 'BEGIN { print (saved > current) ? 1 : 0 }')
    local phase_equal=$(awk -v saved="$saved_phase" -v current="$current_phase" 'BEGIN { print (saved == current) ? 1 : 0 }')

    # If saved phase is greater than current, we've already completed this phase
    if [ "$phase_greater" -eq 1 ]; then
        echo -e "${GREEN}[✓]${NC} Phase $current_phase already completed (skipping)"
        log_msg "Phase $current_phase skipped (already completed)"
        return 1
    fi

    # If we're on the same phase and it was completed, skip
    if [ "$phase_equal" -eq 1 ] && [ "$saved_status" == "COMPLETED" ]; then
        echo -e "${GREEN}[✓]${NC} Phase $current_phase already completed (skipping)"
        log_msg "Phase $current_phase skipped (already completed)"
        return 1
    fi

    # Otherwise, run the phase
    return 0
}

mark_phase_complete() {
    local output_dir="$1"
    local phase="$2"
    local domain="$3"

    save_checkpoint "$output_dir" "$phase" "$domain" "COMPLETED"
    echo -e "${GREEN}[✓]${NC} Phase $phase marked as complete"
}

cleanup_resume_state() {
    local output_dir="$1"
    local state_path="$output_dir/$STATE_DIR"

    # Safety checks before rm -rf
    if [ -z "$state_path" ]; then
        echo -e "${RED}[!]${NC} Error: state_path is empty, skipping cleanup"
        log_msg "Cleanup aborted: empty state_path"
        return 1
    fi
    
    if [ "$state_path" = "/" ] || [ "$state_path" = "/home" ] || [ "$state_path" = "/root" ]; then
        echo -e "${RED}[!]${NC} Error: refusing to delete critical path: $state_path"
        log_msg "Cleanup aborted: critical path protection"
        return 1
    fi

    if [ -d "$state_path" ]; then
        # Archive the state instead of deleting
        local archive_name="state_archive_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "$output_dir/$archive_name" -C "$output_dir" "$STATE_DIR" 2>/dev/null || true
        rm -rf "$state_path"
        echo -e "${GREEN}[✓]${NC} Resume state archived to $archive_name"
        log_msg "Resume state archived: $archive_name"
    fi
}

# Clean up temporary files from output directory
cleanup_temp_files() {
    local output_dir="$1"
    
    if [ -z "$output_dir" ] || [ ! -d "$output_dir" ]; then
        return 0
    fi
    
    echo -e "${CYAN}[*]${NC} Cleaning up temporary files..."
    
    # Find and remove all .tmp files
    local tmp_count=0
    if [ -d "$output_dir" ]; then
        tmp_count=$(find "$output_dir" -type f -name "*.tmp" 2>/dev/null | wc -l)
        find "$output_dir" -type f -name "*.tmp" -delete 2>/dev/null || true
    fi
    
    if [ "$tmp_count" -gt 0 ]; then
        echo -e "${GREEN}[✓]${NC} Cleaned up $tmp_count temporary files"
        log_msg "Cleaned up $tmp_count .tmp files from $output_dir"
    else
        vlog "No temporary files to clean up"
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
    echo "║          BUG BOUNTY RECON PIPELINE v5.0 (Shakibul)          ║"
    echo "║        Professional Elite Reconnaissance & Discovery         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${GREEN}       Parallel • Fast • Comprehensive • Elite Level${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}            Created by: Shakibul (Shakibul_Cybersec)           ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
}

prompt_tor_usage() {
    if ! command_exists tor; then
        echo -e "${YELLOW}[!]${NC} Tor not installed. Continuing without proxy."
        USE_TOR=0
        return
    fi
    
    echo -e "${CYAN}[?]${NC} Would you like to use Tor for scanning? (recommended for anonymity)"
    echo -e "${CYAN}    Note:${NC} Tor will be used only for tools that benefit from it"
    echo -e "${CYAN}          (httpx, nuclei, nmap, gowitness, curl-based operations)"
    read -p "Use Tor? [y/N]: " tor_choice
    
    if [[ "$tor_choice" =~ ^[Yy]$ ]]; then
        if ! systemctl is-active --quiet tor; then
            echo -e "${YELLOW}[!]${NC} Tor service is not running, attempting to start..."
            if command -v sudo &>/dev/null && sudo -n systemctl start tor 2>/dev/null; then
                echo -e "${GREEN}[+]${NC} Tor started successfully"
                sleep 3
            else
                echo -e "${YELLOW}[!]${NC} Could not start Tor. Run: sudo systemctl start tor"
                USE_TOR=0
                return
            fi
        fi
        
        if timeout 5 curl --socks5 127.0.0.1:$TOR_SOCKS_PORT -Is https://check.torproject.org &>/dev/null; then
            echo -e "${GREEN}[+]${NC} Tor connection verified"
            USE_TOR=1
        else
            echo -e "${RED}[!]${NC} Tor connection failed. Continuing without proxy."
            USE_TOR=0
        fi
    else
        USE_TOR=0
    fi
    log_msg "Tor usage: $USE_TOR"
}

get_tor_proxy() {
    if [ "$USE_TOR" -eq 1 ]; then
        echo "socks5://127.0.0.1:$TOR_SOCKS_PORT"
    else
        echo ""
    fi
}

get_proxychains_cmd() {
    if [ "$USE_TOR" -eq 1 ]; then
        echo "proxychains -q"
    else
        echo ""
    fi
}

get_httpx_proxy() {
    if [ "$USE_TOR" -eq 1 ]; then
        echo "-proxy socks5://127.0.0.1:$TOR_SOCKS_PORT"
    else
        echo ""
    fi
}

get_curl_proxy() {
    if [ "$USE_TOR" -eq 1 ]; then
        echo "--socks5 127.0.0.1:$TOR_SOCKS_PORT"
    else
        echo ""
    fi
}

get_nmap_proxy() {
    if [ "$USE_TOR" -eq 1 ]; then
        echo "--proxies socks5://127.0.0.1:$TOR_SOCKS_PORT"
    else
        echo ""
    fi
}

# --------------- Validation Functions ---------------
# Domain validation with hardened regex — blocks injection chars like ;|`$()&><
validate_domain() {
    local domain="$1"

    # Strip any leading/trailing whitespace
    domain=$(echo "$domain" | xargs)

    # Block empty
    if [ -z "$domain" ]; then
        echo -e "${RED}[!] Empty domain input${NC}"
        log_msg "Validation FAIL: empty input"
        return 1
    fi

    # Block length (max 253 chars per RFC 1035)
    if [ "${#domain}" -gt 253 ]; then
        echo -e "${RED}[!] Domain too long (${#domain} chars, max 253): $domain${NC}"
        log_msg "Validation FAIL: too long ($domain)"
        return 1
    fi

    # Block any character outside the safe set:
    # Only allow: a-z A-Z 0-9 . -
    # This kills: ; | ` $ ( ) & > < ! { } [ ] space / \ ' " etc.
    if [[ "$domain" =~ [^a-zA-Z0-9.\-] ]]; then
        echo -e "${RED}[!] Invalid characters in domain: $domain${NC}"
        log_msg "Validation FAIL: bad chars ($domain)"
        return 1
    fi

    # Block leading/trailing dot or hyphen on the whole string
    if [[ "$domain" =~ ^[\.\-] ]] || [[ "$domain" =~ [\.\-]$ ]]; then
        echo -e "${RED}[!] Domain cannot start or end with dot/hyphen: $domain${NC}"
        log_msg "Validation FAIL: leading/trailing dot-hyphen ($domain)"
        return 1
    fi

    # Block consecutive dots
    if [[ "$domain" =~ \.\. ]]; then
        echo -e "${RED}[!] Domain contains consecutive dots: $domain${NC}"
        log_msg "Validation FAIL: consecutive dots ($domain)"
        return 1
    fi

    # Each label: 1-63 chars, alphanumeric or hyphen, cannot start/end with hyphen
    # Final label (TLD) must be at least 2 alpha chars
    if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,63}$ ]]; then
        echo -e "${RED}[!] Invalid domain format: $domain${NC}"
        log_msg "Validation FAIL: format ($domain)"
        return 1
    fi

    log_msg "Validation PASS: $domain"
    return 0
}

validate_file() {
    local file="$1"
    local description="$2"

    if [ ! -f "$file" ]; then
        echo -e "${RED}[!] $description not found: $file${NC}"
        log_msg "File validation FAIL: not found ($file)"
        return 1
    fi

    if [ ! -s "$file" ]; then
        echo -e "${YELLOW}[!] $description is empty: $file${NC}"
        log_msg "File validation FAIL: empty ($file)"
        return 1
    fi

    echo -e "${GREEN}[✓] Validated: $file ($(wc -l < "$file") lines)${NC}"
    log_msg "File validation PASS: $file"
    return 0
}

# --------------- Input Sanitization Functions ---------------
# sanitize_string: Remove dangerous shell metacharacters
# Usage: clean_string=$(sanitize_string "$user_input")
sanitize_string() {
    local input="$1"
    # Remove shell metacharacters: ; | & $ ` < > ( ) { } [ ] ! \
    # Keep safe chars: alphanumeric, dot, dash, underscore, slash, colon
    echo "$input" | tr -d ';|&$`<>(){}[]!\\' | tr -s '/' '/'
}

# validate_ip: Validate IP address format
# Usage: validate_ip "192.168.1.1" || return 1
validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Validate each octet
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# validate_url: Basic URL validation
# Usage: validate_url "$url" || return 1
validate_url() {
    local url="$1"
    # Basic URL format check
    if [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(/[^\ \"\'\;]*)?$ ]]; then
        return 0
    fi
    return 1
}

# --------------- End Sanitization Functions ---------------

# Validate output directory path for security
validate_output_path() {
    local path="$1"
    
    # Block empty paths
    if [ -z "$path" ]; then
        echo -e "${RED}[!] Empty output path${NC}"
        return 1
    fi
    
    # Block absolute critical paths
    if [ "$path" = "/" ] || [ "$path" = "/home" ] || [ "$path" = "/root" ] || \
       [ "$path" = "/etc" ] || [ "$path" = "/usr" ] || [ "$path" = "/var" ]; then
        echo -e "${RED}[!] Cannot use critical system path: $path${NC}"
        return 1
    fi
    
    # Block path traversal attempts
    if [[ "$path" =~ \.\. ]]; then
        echo -e "${RED}[!] Path traversal detected: $path${NC}"
        return 1
    fi
    
    # Block paths starting with / (except /tmp and user home recon dirs)
    if [[ "$path" =~ ^/ ]] && [[ ! "$path" =~ ^/tmp/ ]] && [[ ! "$path" =~ ^$HOME/.*/recon ]]; then
        echo -e "${YELLOW}[!] Warning: Using absolute path: $path${NC}"
    fi
    
    return 0
}

# --------------- Performance Functions ---------------
check_resources() {
    local required_mem=$1
    local mem_free
    mem_free=$(free -m | awk '/Mem/{print $7}')
    local load_avg
    load_avg=$(awk '{print $1}' /proc/loadavg)
    local cpu_cores
    cpu_cores=$(nproc)

    echo -e "${CYAN}[*]${NC} System Resource Check:"
    echo -e "  • Free Memory: ${mem_free}MB / Required: ${required_mem}MB"
    echo -e "  • Load Average: ${load_avg} / CPU Cores: ${cpu_cores}"
    log_msg "Resources: mem_free=${mem_free}MB load=${load_avg} cores=${cpu_cores}"

    if [ "$mem_free" -lt "$required_mem" ]; then
        echo -e "${YELLOW}[!]${NC} Low memory detected. Adjusting concurrency..."
        return 1
    fi

    if (( $(echo "$load_avg > $cpu_cores" | bc -l) )); then
        echo -e "${YELLOW}[!]${NC} High load detected. Reducing parallelism..."
        return 1
    fi

    return 0
}

adaptive_concurrency() {
    local cpu_cores
    cpu_cores=$(nproc)
    local mem_free
    mem_free=$(free -m | awk '/Mem/{print $7}')

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
    log_msg "CMD START: $desc"

    for ((retry=1; retry<=max_retries; retry++)); do
        echo -e "  Attempt $retry/$max_retries..."
        vlog "Executing: $cmd"

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
                log_msg "CMD SUCCESS: $desc"
                return 0
                ;;
            124)
                echo -e "  ${YELLOW}! Timeout (external)${NC}"
                log_msg "CMD TIMEOUT: $desc (attempt $retry)"
                ;;
            *)
                echo -e "  ${RED}! Failed (code: $exit_code)${NC}"
                log_msg "CMD FAIL: $desc (attempt $retry, code=$exit_code)"
                ;;
        esac

        if [ "$retry" -lt "$max_retries" ]; then
            # Exponential backoff: 2s, 4s, 6s, etc.
            local delay=$((2 * retry))
            echo -e "  Retrying in $delay seconds (exponential backoff)..."
            sleep "$delay"
        fi
    done

    echo -e "${RED}[!]${NC} Failed after $max_retries attempts: $desc" | tee -a "$log_file"
    log_msg "CMD FAILED FINAL: $desc after $max_retries attempts"
    return 1
}

run_parallel() {
    local commands=("$@")
    local pids=()
    local results=()
    
    # Start all jobs in background with centralized control
    for cmd in "${commands[@]}"; do
        # Wait for job slot before starting new job
        wait_for_job_slot
        
        (
            bash -c "$cmd" > /dev/null 2>&1
            local exit_code=$?
            local desc=$(echo "$cmd" | grep -o 'desc:"[^"]*"' | cut -d'"' -f2)
            if [ "$exit_code" -eq 0 ]; then
                echo -e "  ${GREEN}✓${NC} $desc"
            else
                echo -e "  ${YELLOW}!${NC} $desc (non-critical failure)"
            fi
        ) &
        local bg_pid=$!
        pids+=("$bg_pid")
        register_job "$bg_pid" "parallel_task"
    done
    
    # Wait for all jobs to complete
    wait_for_all_jobs
}

# ============ TOOL CHECKING ============
check_tools() {
    echo -e "${CYAN}[*]${NC} Checking required tools..."
    
    local required_tools=(
        "subfinder" "assetfinder" "amass" "puredns" "dnsx" "dnsgen"
        "naabu" "nmap" "httpx" "gowitness" "gau" "katana" 
        "uro" "gf" "qsreplace" "dnsrecon" "whois" "subjack"
        "jq" "curl" "wget" "jsscan" "down" "url-extension" 
        "nuclei" "arjun" "wafw00f"
    )
    
    local missing_required=()
    
    # Check required tools
    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_required+=("$tool")
            echo -e "${RED}[✗]${NC} $tool (required)"
        else
            echo -e "${GREEN}[✓]${NC} $tool"
        fi
    done
    
    # Exit if required tools are missing
    if [ ${#missing_required[@]} -gt 0 ]; then
        echo -e "\n${RED}[!]${NC} Missing required tools:"
        for tool in "${missing_required[@]}"; do
            echo -e "  - ${RED}$tool${NC}"
        done
        echo -e "\n${YELLOW}[*]${NC} Please run: ${BLUE}bash install_v5.sh${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+]${NC} Tool check completed"
    log_msg "Tool check: all required tools present"
}

# ===============================================================
# PHASE IMPLEMENTATIONS START HERE
# ===============================================================

# --------------- Modular Phases ---------------
phase_subdomain_enum() {
    local domain=$1
    local output_dir=$2
    local wordlist=$3
    local resolvers=$4
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 1]${NC} Subdomain Enumeration"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 1 START: Subdomain Enumeration ==="

    # Parallel passive discovery
    local curl_proxy=$(get_curl_proxy)
    
    local passive_commands=(
        "subfinder -d \"$domain\" -silent -o \"$output_dir\"/subfinder.txt 2>>\"$error_log\"; echo 'desc:\"Subfinder\"'"
        "assetfinder -subs-only \"$domain\" > \"$output_dir\"/assetfinder.txt 2>>\"$error_log\"; echo 'desc:\"Assetfinder\"'"
        "curl -s $curl_proxy 'https://crt.sh/?q=%25.$domain&output=json' 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\.//g' | sort -u > \"$output_dir\"/crt.txt; echo 'desc:\"crt.sh\"'"
        "amass enum -passive -d \"$domain\" -o \"$output_dir\"/amass_passive.txt 2>>\"$error_log\"; echo 'desc:\"Amass Passive\"'"
    )

    run_parallel "${passive_commands[@]}"

    # DNS brute force only
    echo -e "${YELLOW}[>]${NC} Running DNS brute force..."

    run_cmd_with_retry \
        "puredns bruteforce \"$wordlist\" \"$domain\" -r \"$resolvers\" -q > \"$output_dir\"/puredns.txt 2>/dev/null" \
        "Puredns DNS Brute Force" \
        "$error_log"

    # Process and merge results
    process_subdomain_results "$output_dir" "$resolvers"
    log_msg "=== PHASE 1 DONE ==="
}

process_subdomain_results() {
    local output_dir="$1"
    local resolvers="$2"

    echo -e "${YELLOW}[>]${NC} Processing and deduplicating results..."

    # Combine and clean
    cat "$output_dir/subfinder.txt" \
        "$output_dir/assetfinder.txt" \
        "$output_dir/crt.txt" \
        "$output_dir/amass_passive.txt" \
        "$output_dir/puredns.txt" 2>/dev/null | \
        awk -F: '{print $1}' | \
        sed 's/^\.//; s/\.$//' | \
        sort -u | \
        grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" > "$output_dir/all_subdomains.raw.txt"

    # DNS resolution
    if [ -s "$output_dir/all_subdomains.raw.txt" ]; then
        echo -e "${YELLOW}[>]${NC} Resolving subdomains with DNS..."
        dnsx -l "$output_dir/all_subdomains.raw.txt" \
             -r "$resolvers" \
             -silent \
             -o "$output_dir/all_subdomains.txt" \
             2>>"$output_dir/errors.log" || echo -e "${YELLOW}[!]${NC} DNS resolution completed (may have timeouts)"
    fi

    # Generate permutations with dnsgen
    if [ -s "$output_dir/all_subdomains.txt" ]; then
        echo -e "${YELLOW}[>]${NC} Generating subdomain permutations with dnsgen..."
        cat "$output_dir/all_subdomains.txt" | dnsgen - > "$output_dir/dnsgen.txt" 2>>"$output_dir/errors.log"

        # Resolve dnsgen results
        echo -e "${YELLOW}[>]${NC} Resolving dnsgen permutations..."
        dnsx -l "$output_dir/dnsgen.txt" \
             -r "$resolvers" \
             -silent \
             -o "$output_dir/dnsgen_resolved.txt" \
             2>>"$output_dir/errors.log" || echo -e "${YELLOW}[!]${NC} dnsgen resolution completed (may have timeouts)"

        # Merge resolved results back to all_subdomains.txt
        cat "$output_dir/all_subdomains.txt" "$output_dir/dnsgen_resolved.txt" 2>/dev/null | \
            sort -u > "$output_dir/all_subdomains.tmp.txt"
        mv "$output_dir/all_subdomains.tmp.txt" "$output_dir/all_subdomains.txt"
    fi

    local count
    count=$(wc -l < "$output_dir/all_subdomains.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓]${NC} Found $count unique and resolved subdomains"
    log_msg "Subdomain processing done: $count unique resolved"
}

# ============ CDN/CLOUD IP DETECTION ============

# Known CDN/Cloud IP ranges (CIDR notation)
declare -A CDN_RANGES=(
    # Cloudflare
    ["cloudflare_1"]="173.245.48.0/20"
    ["cloudflare_2"]="103.21.244.0/22"
    ["cloudflare_3"]="103.22.200.0/22"
    ["cloudflare_4"]="103.31.4.0/22"
    ["cloudflare_5"]="141.101.64.0/18"
    ["cloudflare_6"]="108.162.192.0/18"
    ["cloudflare_7"]="190.93.240.0/20"
    ["cloudflare_8"]="188.114.96.0/20"
    ["cloudflare_9"]="197.234.240.0/22"
    ["cloudflare_10"]="198.41.128.0/17"
    ["cloudflare_11"]="162.158.0.0/15"
    ["cloudflare_12"]="104.16.0.0/13"
    ["cloudflare_13"]="104.24.0.0/14"
    ["cloudflare_14"]="172.64.0.0/13"
    ["cloudflare_15"]="131.0.72.0/22"
    
    # Fastly
    ["fastly_1"]="23.235.32.0/20"
    ["fastly_2"]="43.249.72.0/22"
    ["fastly_3"]="103.244.50.0/24"
    ["fastly_4"]="103.245.222.0/23"
    ["fastly_5"]="103.245.224.0/24"
    ["fastly_6"]="104.156.80.0/20"
    ["fastly_7"]="151.101.0.0/16"
    ["fastly_8"]="157.52.64.0/18"
    
    # Akamai
    ["akamai_1"]="23.0.0.0/12"
    ["akamai_2"]="104.64.0.0/10"
    
    # AWS CloudFront
    ["aws_cloudfront"]="13.32.0.0/15"
    
    # Vercel (shared platform and edge network)
    ["vercel_1"]="76.76.21.0/24"
    ["vercel_2"]="76.223.0.0/20"
    ["vercel_3"]="76.76.19.0/24"
    ["vercel_4"]="76.76.20.0/24"
    # Vercel Edge Network (Anycast IPs)
    ["vercel_edge_1"]="216.198.73.0/24"
    ["vercel_edge_2"]="216.198.74.0/24"
    ["vercel_edge_3"]="216.198.75.0/24"
    ["vercel_edge_4"]="216.198.76.0/24"
    ["vercel_edge_5"]="216.198.77.0/24"
    ["vercel_edge_6"]="216.198.78.0/24"
    ["vercel_edge_7"]="216.198.79.0/24"
    
    # NOTE: DigitalOcean, GCP, and Azure ranges removed
    # These are hosting/VPS providers, not shared CDN infrastructure
    # IPs in these ranges are likely ORIGIN servers, not CDN proxies
)

# Check if IP belongs to known CDN/Cloud ranges
is_cdn_ip() {
    local ip=$1
    local cidr_list="/tmp/cdn_ranges_$$.txt"
    
    # Register temp file for cleanup
    register_temp_file "$cidr_list"
    
    > "$cidr_list"
    for cidr in "${CDN_RANGES[@]}"; do
        echo "$cidr" >> "$cidr_list"
    done
    
    if command -v grepcidr &> /dev/null; then
        if echo "$ip" | grepcidr -f "$cidr_list" &> /dev/null; then
            rm -f "$cidr_list"
            return 0
        fi
    else
        # Fallback: pattern matching for SHARED CDN infrastructure ONLY
        # NOTE: Being conservative - only mark as CDN if definitely shared multi-tenant
        if [[ "$ip" =~ ^104\.(1[6-9]|2[0-7])\. ]] || \
           [[ "$ip" =~ ^172\.(6[4-9]|7[0-1])\. ]] || \
           [[ "$ip" =~ ^103\.21\.24[4-7]\. ]] || \
           [[ "$ip" =~ ^151\.101\. ]] || \
           [[ "$ip" =~ ^76\.76\.(19|20|21)\. ]] || \
           [[ "$ip" =~ ^76\.223\. ]] || \
           [[ "$ip" =~ ^216\.198\.(7[3-9])\. ]]; then
            rm -f "$cidr_list"
            return 0
        fi
    fi
    
    rm -f "$cidr_list"
    return 1
}

detect_cdn_provider() {
    local ip=$1
    
    # Only detect SHARED multi-tenant CDN infrastructure
    # Hosting providers (DigitalOcean, GCP, Azure) are NOT CDN
    
    if [[ "$ip" =~ ^104\.(1[6-9]|2[0-7])\. ]] || \
       [[ "$ip" =~ ^172\.(6[4-9]|7[0-1])\. ]] || \
       [[ "$ip" =~ ^103\.21\.24[4-7]\. ]]; then
        echo "Cloudflare"
        return
    fi
    
    if [[ "$ip" =~ ^151\.101\. ]] || \
       [[ "$ip" =~ ^104\.15[6-9]\. ]] || \
       [[ "$ip" =~ ^157\.52\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then
        echo "Fastly"
        return
    fi
    
    if [[ "$ip" =~ ^76\.76\.(19|20|21)\. ]] || \
       [[ "$ip" =~ ^76\.223\. ]] || \
       [[ "$ip" =~ ^216\.198\.(7[3-9])\. ]]; then
        echo "Vercel"
        return
    fi
    
    if [[ "$ip" =~ ^23\. ]] || [[ "$ip" =~ ^104\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then
        echo "Akamai"
        return
    fi
    
    if [[ "$ip" =~ ^13\.32\. ]] || [[ "$ip" =~ ^13\.33\. ]]; then
        echo "AWS CloudFront"
        return
    fi
    
    echo "Unknown CDN"
}

perform_smart_scan() {
    local output_dir=$1
    local origin_hosts=$2
    
    echo -e "\n${CYAN}[*]${NC} Scanning likely origin IPs for comprehensive port discovery..."
    
    echo -e "${YELLOW}[>]${NC} Running Naabu on likely origin IPs (all 65535 ports)..."
    naabu -list "$origin_hosts" \
          -p - \
          -rate "$NAABU_RATE" \
          -c "$(adaptive_concurrency)" \
          -silent \
          -o "$output_dir/portscan/naabu_results.txt" 2>>"$output_dir/errors.log" || true
    
    if [ -s "$output_dir/portscan/naabu_results.txt" ]; then
        local discovered_port_count=$(cut -d':' -f2 "$output_dir/portscan/naabu_results.txt" | sort -nu | wc -l)
        
        if [ "$discovered_port_count" -gt 0 ]; then
            echo -e "${GREEN}[✓]${NC} Discovered $discovered_port_count unique ports on likely origin IPs"
            
            # Run nmap service detection on discovered ports
            echo -e "${YELLOW}[>]${NC} Running Nmap service detection on discovered ports..."
            
            # Extract unique hosts and their ports from naabu results
            local nmap_proxy=$(get_nmap_proxy)
            local hosts_ports_file="$output_dir/portscan/hosts_ports.tmp"
            
            # Group ports by host
            awk -F':' '{ports[$1]=ports[$1]","$2} END {for (host in ports) print host, substr(ports[host],2)}' \
                "$output_dir/portscan/naabu_results.txt" > "$hosts_ports_file"
            
            # Run nmap for each host with its discovered ports
            while read -r host ports; do
                if [ -n "$host" ] && [ -n "$ports" ]; then
                    local safe_host=$(echo "$host" | tr -cd '[:alnum:].-')
                    echo -e "${CYAN}[*]${NC} Scanning $host (ports: ${ports:0:50}...)"
                    
                    if [ "$USE_TOR" -eq 1 ]; then
                        nmap -Pn -T4 -sV -p "$ports" $nmap_proxy \
                            --min-rate 1000 \
                            -oA "$output_dir/portscan/nmap_${safe_host}" \
                            "$host" 2>>"$output_dir/errors.log" || true
                    else
                        nmap -Pn -T4 -sV -p "$ports" \
                            --min-rate 1000 \
                            -oA "$output_dir/portscan/nmap_${safe_host}" \
                            "$host" 2>>"$output_dir/errors.log" || true
                    fi
                fi
            done < "$hosts_ports_file"
            
            rm -f "$hosts_ports_file"
            
            # Merge all nmap results
            if ls "$output_dir/portscan"/nmap_*.nmap 1> /dev/null 2>&1; then
                cat "$output_dir/portscan"/nmap_*.nmap > "$output_dir/portscan/nmap_scan.nmap" 2>/dev/null || true
                cat "$output_dir/portscan"/nmap_*.xml > "$output_dir/portscan/nmap_scan.xml" 2>/dev/null || true
                echo -e "${GREEN}[✓]${NC} Nmap service detection completed"
            fi
        fi
    else
        echo -e "${YELLOW}[!]${NC} No open ports found on likely origin IPs"
    fi
}

perform_full_scan() {
    local output_dir=$1
    
    echo -e "\n${CYAN}[*]${NC} Scanning ALL hosts (including CDN)..."
    echo -e "${YELLOW}[!]${NC} Note: Results for CDN IPs will contain noise"
    
    echo -e "${YELLOW}[>]${NC} Running Naabu on all hosts..."
    naabu -list "$output_dir/all_subdomains.txt" \
          -p - \
          -rate "$NAABU_RATE" \
          -c "$(adaptive_concurrency)" \
          -silent \
          -o "$output_dir/portscan/naabu_results.txt" 2>>"$output_dir/errors.log" || true
    
    if [ -s "$output_dir/portscan/naabu_results.txt" ]; then
        local discovered_port_count=$(cut -d':' -f2 "$output_dir/portscan/naabu_results.txt" | sort -nu | wc -l)
        
        if [ "$discovered_port_count" -gt 0 ]; then
            echo -e "${GREEN}[✓]${NC} Discovered $discovered_port_count unique ports"
            
            # Run nmap service detection on discovered ports
            echo -e "${YELLOW}[>]${NC} Running Nmap service detection on discovered ports..."
            
            local nmap_proxy=$(get_nmap_proxy)
            local hosts_ports_file="$output_dir/portscan/hosts_ports.tmp"
            
            # Group ports by host
            awk -F':' '{ports[$1]=ports[$1]","$2} END {for (host in ports) print host, substr(ports[host],2)}' \
                "$output_dir/portscan/naabu_results.txt" > "$hosts_ports_file"
            
            # Run nmap for each host with its discovered ports
            while read -r host ports; do
                if [ -n "$host" ] && [ -n "$ports" ]; then
                    local safe_host=$(echo "$host" | tr -cd '[:alnum:].-')
                    echo -e "${CYAN}[*]${NC} Scanning $host (ports: ${ports:0:50}...)"
                    
                    if [ "$USE_TOR" -eq 1 ]; then
                        nmap -Pn -T4 -sV -p "$ports" $nmap_proxy \
                            --min-rate 1000 \
                            -oA "$output_dir/portscan/nmap_${safe_host}" \
                            "$host" 2>>"$output_dir/errors.log" || true
                    else
                        nmap -Pn -T4 -sV -p "$ports" \
                            --min-rate 1000 \
                            -oA "$output_dir/portscan/nmap_${safe_host}" \
                            "$host" 2>>"$output_dir/errors.log" || true
                    fi
                fi
            done < "$hosts_ports_file"
            
            rm -f "$hosts_ports_file"
            
            # Merge all nmap results
            if ls "$output_dir/portscan"/nmap_*.nmap 1> /dev/null 2>&1; then
                cat "$output_dir/portscan"/nmap_*.nmap > "$output_dir/portscan/nmap_scan.nmap" 2>/dev/null || true
                cat "$output_dir/portscan"/nmap_*.xml > "$output_dir/portscan/nmap_scan.xml" 2>/dev/null || true
                echo -e "${GREEN}[✓]${NC} Nmap service detection completed"
            fi
        fi
    fi
}

perform_quick_scan() {
    local output_dir=$1
    
    echo -e "\n${CYAN}[*]${NC} Quick scan on common web ports..."
    
    local web_ports="80,443,8080,8443,8000,8888,3000,5000,9000"
    
    echo -e "${YELLOW}[>]${NC} Scanning ports: $web_ports"
    naabu -list "$output_dir/all_subdomains.txt" \
          -p "$web_ports" \
          -rate $NAABU_RATE \
          -silent \
          -o "$output_dir/portscan/naabu_results.txt" 2>>"$output_dir/errors.log" || true
    
    if [ -s "$output_dir/portscan/naabu_results.txt" ]; then
        echo -e "${GREEN}[✓]${NC} Quick scan completed"
    fi
}

phase_port_scanning() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 2]${NC} Intelligent Port Scanning"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 2 START: Intelligent Port Scanning ==="

    if [ ! -s "$output_dir/all_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No subdomains to scan"
        log_msg "Phase 2 SKIP: no subdomains"
        return
    fi

    mkdir -p "$output_dir/portscan"

    echo -e "\n${CYAN}[*]${NC} Analyzing IP addresses and detecting CDN/Cloud services..."
    
    local ip_analysis="$output_dir/portscan/ip_analysis.txt"
    local cdn_hosts="$output_dir/portscan/cdn_hosts.txt"
    local origin_hosts="$output_dir/portscan/likely_origin_hosts.txt"
    local cdn_summary="$output_dir/portscan/cdn_summary.txt"
    
    > "$ip_analysis"
    > "$cdn_hosts"
    > "$origin_hosts"
    > "$cdn_summary"
    
    local total_hosts=0
    local cdn_count=0
    local origin_count=0
    
    while IFS= read -r subdomain; do
        total_hosts=$((total_hosts + 1))
        
        local ip=$(dig +short "$subdomain" A | head -1 2>/dev/null)
        
        if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if is_cdn_ip "$ip"; then
                local provider=$(detect_cdn_provider "$ip")
                echo "$subdomain|$ip|CDN|$provider" >> "$ip_analysis"
                echo "$subdomain" >> "$cdn_hosts"
                cdn_count=$((cdn_count + 1))
            else
                echo "$subdomain|$ip|ORIGIN|Direct" >> "$ip_analysis"
                echo "$subdomain" >> "$origin_hosts"
                origin_count=$((origin_count + 1))
            fi
        else
            echo "$subdomain|N/A|UNKNOWN|NoIP" >> "$ip_analysis"
        fi
    done < "$output_dir/all_subdomains.txt"
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}           IP ANALYSIS SUMMARY${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
    echo -e "  ${YELLOW}Total Hosts:${NC}        $total_hosts"
    echo -e "  ${RED}CDN/Cloud IPs:${NC}      $cdn_count (will produce noise)"
    echo -e "  ${GREEN}Likely Origin IPs:${NC}  $origin_count (valuable targets)"
    echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
    
    if [ "$cdn_count" -gt 0 ]; then
        echo -e "\n${YELLOW}[!]${NC} CDN/Cloud Providers Detected:"
        grep "CDN" "$ip_analysis" 2>/dev/null | cut -d'|' -f4 | sort | uniq -c | while read count provider; do
            echo -e "  • ${provider}: ${YELLOW}${count}${NC} hosts"
        done
    fi
    
    cat > "$cdn_summary" <<EOF
IP Analysis Summary
===================
Total Hosts: $total_hosts
CDN/Cloud IPs: $cdn_count
Likely Origin IPs: $origin_count

CDN Provider Breakdown:
$(grep "CDN" "$ip_analysis" 2>/dev/null | cut -d'|' -f4 | sort | uniq -c)

WARNING: Port scanning CDN/Cloud IPs will produce massive noise and false positives.
These IPs host thousands of websites and port scan results are NOT specific to your target.

RECOMMENDATION: Focus port scanning on ORIGIN IPs only for meaningful results.
EOF

    echo -e "\n${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│         PORT SCANNING STRATEGY SELECTOR             │${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────┘${NC}"
    echo -e ""
    echo -e "${YELLOW}⚠  WARNING: Port scanning CDN IPs produces NOISE${NC}"
    echo -e ""
    echo -e "Port scanning IPs like Cloudflare or Vercel will show thousands"
    echo -e "of 'open' ports that are NOT accessible for your specific target."
    echo -e ""
    echo -e "${GREEN}Choose scanning strategy:${NC}"
    echo -e ""
    echo -e "  ${CYAN}1)${NC} Smart Scan - Only scan likely ORIGIN IPs (${GREEN}${origin_count} hosts${NC})"
    echo -e "     ${BLUE}→${NC} Fast, clean results, no noise"
    echo -e ""
    echo -e "  ${CYAN}2)${NC} Full Scan - Scan ALL hosts including CDN (${YELLOW}${total_hosts} hosts${NC})"
    echo -e "     ${RED}→${NC} Will produce noise and false positives"
    echo -e ""
    echo -e "  ${CYAN}3)${NC} Quick Web Ports Only - Scan 80,443,8080,8443 on ALL"
    echo -e "     ${BLUE}→${NC} Fast scan, minimal noise"
    echo -e ""
    echo -e "  ${CYAN}4)${NC} Skip Port Scanning"
    echo -e "     ${BLUE}→${NC} Fastest, rely on HTTP probing only"
    echo -e ""
    echo -e "${YELLOW}⏱  Timeout: Auto-selecting option 1 in 5 minute if no input provided${NC}"
    echo -e ""
    
    local scan_choice=""
    local timeout_duration=300
    
    # Read with timeout - if timeout occurs or invalid input, default to 1
    if read -t $timeout_duration -p "Enter choice (1-4) [default: 1]: " scan_choice; then
        scan_choice=${scan_choice:-1}
    else
        echo ""
        echo -e "${YELLOW}[!]${NC} Timeout reached. Auto-selecting Smart Scan (option 1)"
        scan_choice=1
        log_msg "Port scan: timeout - defaulting to SMART scan"
    fi
    
    case $scan_choice in
        1)
            echo -e "\n${GREEN}[✓]${NC} Strategy: Smart Scan (Origin IPs only)"
            log_msg "Port scan strategy: SMART (origin only)"
            if [ "$origin_count" -eq 0 ]; then
                echo -e "${YELLOW}[!]${NC} No likely origin IPs detected. All hosts are behind CDN."
                echo -e "${YELLOW}[!]${NC} Skipping port scan to avoid noise."
                log_msg "Phase 2 SKIP: no likely origin IPs to scan"
                return
            fi
            perform_smart_scan "$output_dir" "$origin_hosts"
            ;;
        2)
            echo -e "\n${YELLOW}[!]${NC} Strategy: Full Scan (ALL hosts including CDN)"
            echo -e "${RED}[!]${NC} Warning: This will produce significant noise"
            log_msg "Port scan strategy: FULL (all hosts)"
            perform_full_scan "$output_dir"
            ;;
        3)
            echo -e "\n${CYAN}[*]${NC} Strategy: Quick Web Ports"
            log_msg "Port scan strategy: QUICK (web ports only)"
            perform_quick_scan "$output_dir"
            ;;
        4)
            echo -e "\n${BLUE}[i]${NC} Skipping port scanning phase"
            log_msg "Phase 2 SKIP: user choice"
            return
            ;;
        *)
            echo -e "${YELLOW}[!]${NC} Invalid choice '$scan_choice'. Defaulting to Smart Scan (option 1)"
            log_msg "Port scan strategy: SMART (invalid input - default)"
            if [ "$origin_count" -eq 0 ]; then
                echo -e "${YELLOW}[!]${NC} No origin IPs detected. Skipping scan."
                return
            fi
            perform_smart_scan "$output_dir" "$origin_hosts"
            ;;
    esac
    
    process_port_results "$output_dir"
    log_msg "=== PHASE 2 DONE ==="
}

process_port_results() {
    local output_dir=$1
    
    if [ -f "$output_dir/portscan/naabu_results.txt" ]; then
        sort -u "$output_dir/portscan/naabu_results.txt" > "$output_dir/portscan/all_results.txt"
    fi
    
    if [ -f "$output_dir/portscan/nmap_scan.nmap" ]; then
        grep -E '^[0-9]+/tcp.*open' "$output_dir/portscan/nmap_scan.nmap" 2>/dev/null | \
            awk '{print $1}' | cut -d'/' -f1 >> "$output_dir/portscan/open_ports.txt"
    fi
    
    if [ -f "$output_dir/portscan/ip_analysis.txt" ]; then
        echo -e "\n${CYAN}[*]${NC} Port Scan Results Summary:"
        
        local origin_port_count=0
        local cdn_port_count=0
        
        if [ -f "$output_dir/portscan/naabu_results.txt" ]; then
            while IFS= read -r line; do
                local host=$(echo "$line" | cut -d':' -f1)
                # Use grep -F for fixed string matching to prevent regex injection
                if grep -qF "$host|" "$output_dir/portscan/ip_analysis.txt" 2>/dev/null | grep -q "ORIGIN"; then
                    origin_port_count=$((origin_port_count + 1))
                elif grep -qF "$host|" "$output_dir/portscan/ip_analysis.txt" 2>/dev/null | grep -q "CDN"; then
                    cdn_port_count=$((cdn_port_count + 1))
                fi
            done < "$output_dir/portscan/naabu_results.txt"
        fi
        
        echo -e "  ${GREEN}Origin IPs:${NC}    $origin_port_count open ports (valuable)"
        echo -e "  ${YELLOW}CDN IPs:${NC}       $cdn_port_count open ports (likely noise)"
        
        if [ "$origin_port_count" -gt 0 ]; then
            echo -e "\n${CYAN}[*]${NC} Interesting ports on origin servers:"
            grep -E ":(22|3306|5432|6379|9200|27017|3389|5900|1433|3000|5000|8080)" \
                "$output_dir/portscan/naabu_results.txt" 2>/dev/null | \
                while IFS= read -r line; do
                    local host=$(echo "$line" | cut -d':' -f1)
                    local port=$(echo "$line" | cut -d':' -f2)
                    if grep -qF "$host|" "$output_dir/portscan/ip_analysis.txt" 2>/dev/null | grep -q "ORIGIN"; then
                        local service_name=""
                        case $port in
                            22) service_name="SSH" ;;
                            3306) service_name="MySQL" ;;
                            5432) service_name="PostgreSQL" ;;
                            6379) service_name="Redis" ;;
                            9200) service_name="Elasticsearch" ;;
                            27017) service_name="MongoDB" ;;
                            3389) service_name="RDP" ;;
                            5900) service_name="VNC" ;;
                            1433) service_name="MSSQL" ;;
                            *) service_name="Web Service" ;;
                        esac
                        echo -e "  ${YELLOW}→${NC} $host:$port ${GREEN}($service_name)${NC}"
                    fi
                done
        fi
    fi
    
    local total_count=$(wc -l < "$output_dir/portscan/all_results.txt" 2>/dev/null || echo 0)
    echo -e "\n${GREEN}[✓]${NC} Total open ports found: $total_count"
    log_msg "Port scan results: total=$total_count origin=${origin_port_count:-0} cdn=${cdn_port_count:-0}"
}

phase_web_discovery() {
    local domain=$1
    local output_dir=$2
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 3]${NC} Web Service Discovery"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 3 START: Web Service Discovery ==="

    if [ ! -s "$output_dir/all_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No subdomains to check"
        echo "$domain" > "$output_dir/alive_subdomains.txt"
        echo "http://$domain" > "$output_dir/alive_subdomains_https.txt"
        log_msg "Phase 3: no subdomains — used root domain fallback"
        return
    fi

    local httpx_proxy=$(get_httpx_proxy)

    run_cmd_with_retry \
        "httpx -l $output_dir/all_subdomains.txt \
               -threads $HTTPX_THREADS \
               -silent \
               $httpx_proxy \
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

        local count
        count=$(wc -l < "$output_dir/alive_subdomains.txt" 2>/dev/null || echo 0)
        echo -e "${GREEN}[✓]${NC} Found $count alive web services"
        log_msg "Web discovery: $count alive services"
    else
        echo -e "${YELLOW}[!]${NC} No alive web services found"
        echo "$domain" > "$output_dir/alive_subdomains.txt"
        echo "http://$domain" > "$output_dir/alive_subdomains_https.txt"
        log_msg "Web discovery: zero alive — used root domain fallback"
    fi
    log_msg "=== PHASE 3 DONE ==="
}

phase_url_collection() {
    local domain=$1
    local output_dir=$2
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 4]${NC} URL Discovery"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 4 START: URL Discovery ==="

    if [ ! -s "$output_dir/all_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No subdomains for URL collection"
        log_msg "Phase 4 SKIP: no subdomains"
        return
    fi

    # Check if alive_subdomains.txt exists
    if [ ! -s "$output_dir/alive_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive subdomains for URL collection"
        log_msg "Phase 4 SKIP: no alive subdomains"
        return
    fi

    # URL discovery using GAU only (waybackurls removed - redundant)
    echo -e "${YELLOW}[>]${NC} Collecting URLs from web archive (GAU)..."
    run_cmd_with_retry \
        "cat $output_dir/all_subdomains.txt | gau --threads 20 > $output_dir/urls/gau.txt" \
        "GAU URL Collection" \
        "$error_log"

    # Active crawling with Katana
    echo -e "${YELLOW}[>]${NC} Active crawling with Katana..."
    local katana_domains
    katana_domains=$(sed 's/\./\\./g' "$output_dir/alive_subdomains.txt" | paste -sd '|' - 2>/dev/null)
    if [ -n "$katana_domains" ]; then
        run_cmd_with_retry \
            "katana -list $output_dir/alive_subdomains.txt -jc -kf all -d 3 -c 50 -cs '^https?://(www\\.)?($katana_domains)(/|\$)' -o $output_dir/urls/katana.txt" \
            "Katana Active Crawl" \
            "$error_log"
    fi

    # Combine and deduplicate (safely handle empty files)
    cat "$output_dir/urls/"*.txt 2>/dev/null | sort -u > "$output_dir/all_urls.txt"

    local count
    count=$(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓]${NC} Collected $count unique URLs"
    log_msg "URL collection: $count unique URLs"

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
    log_msg "=== PHASE 4 DONE ==="
}

phase_js_analysis() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 5]${NC} JavaScript File Analysis"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 5 START: JavaScript Analysis ==="

    if [ ! -s "$output_dir/all_urls.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No URLs for JavaScript analysis"
        log_msg "Phase 5 SKIP: no URLs"
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

        local total_js_count
        total_js_count=$(wc -l < "$output_dir/javascript/js_urls.txt")
        local filtered_js_count
        filtered_js_count=$(wc -l < "$output_dir/javascript/filtered_js_urls.txt" 2>/dev/null || echo 0)

        echo -e "${GREEN}[✓]${NC} JavaScript URLs: $total_js_count total, $filtered_js_count after filtering"
        log_msg "JS filtering: $total_js_count total → $filtered_js_count filtered"

        if [ -s "$output_dir/javascript/filtered_js_urls.txt" ] && [ "$filtered_js_count" -gt 0 ]; then
            # Download high priority files first
            if [ -s "$output_dir/javascript/high_priority_js.txt" ]; then
                echo -e "${YELLOW}[>]${NC} Downloading $(wc -l < "$output_dir/javascript/high_priority_js.txt") high priority files"
                if command_exists down; then
                    down -u "$output_dir/javascript/high_priority_js.txt" -o "$output_dir/javascript/js_files" -p 20 -t 10 2>>"$error_log" || true
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
                        down -u "$output_dir/javascript/remaining_js.txt" -o "$output_dir/javascript/js_files" -p 20 -t 10 2>>"$error_log" || true
                    fi
                else
                    down -u "$output_dir/javascript/filtered_js_urls.txt" -o "$output_dir/javascript/js_files" -p 20 -t 10 2>>"$error_log" || true
                fi

                echo -e "${GREEN}[✓]${NC} JavaScript files downloaded"
                log_msg "JS download complete"
            else
                echo -e "${YELLOW}[!]${NC} down not found. Skipping JavaScript file downloading."
                log_msg "JS download SKIP: 'down' command not found"
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
                find "$output_dir/javascript/js_files/success" -name "*.js" -type f 2>/dev/null | while read -r js_file; do
                    echo "=== File: $(basename "$js_file") ===" >> "$output_dir/javascript/endpoints_raw.txt"
                    # Extract URLs and API patterns with better filtering
                    grep -E -o "(https?://[^\s\"'<>]+|/[a-zA-Z0-9/_-]+\.(php|asp|aspx|jsp|do|action|json|xml)|/api/[^\s\"'<>]+|/v[0-9]+/[^\s\"'<>]+)" "$js_file" 2>/dev/null | \
                        grep -v -E "\.(js|css|jpg|jpeg|png|gif|svg|woff|woff2|ttf|eot|ico|mp4|webm|mp3)(\?|$)" | \
                        head -30 >> "$output_dir/javascript/endpoints_raw.txt"
                    echo "" >> "$output_dir/javascript/endpoints_raw.txt"
                done

                # Clean and format endpoints with better validation
                if [ -f "$output_dir/javascript/endpoints_raw.txt" ]; then
                    # Extract and validate endpoints
                    grep -oE "(https?://[^\s\"'<>]+|/[a-zA-Z0-9/_-]+)" "$output_dir/javascript/endpoints_raw.txt" | \
                        grep -v -E "\.(js|css|jpg|jpeg|png|gif|svg|woff|woff2|ttf|eot|ico|mp4|webm|mp3)(\?|$)" | \
                        grep -v -E "^/$|^//$|^http://$|^https://$" | \
                        grep -E "^(https?://|/[a-zA-Z])" | \
                        awk 'length($0) > 5 && length($0) < 200' | \
                        sort -u > "$output_dir/javascript/endpoints.txt"

                    local endpoint_count
                    endpoint_count=$(wc -l < "$output_dir/javascript/endpoints.txt" 2>/dev/null || echo 0)
                    echo -e "${GREEN}[✓]${NC} Endpoints extracted: $endpoint_count"
                    log_msg "JS endpoints extracted: $endpoint_count"

                    # Create summary file
                    echo "JavaScript Analysis Summary" > "$output_dir/javascript/summary.txt"
                    echo "==========================" >> "$output_dir/javascript/summary.txt"
                    echo "Total JS URLs found: $total_js_count" >> "$output_dir/javascript/summary.txt"
                    echo "Filtered for analysis: $filtered_js_count" >> "$output_dir/javascript/summary.txt"
                    echo "High priority files: $(wc -l < "$output_dir/javascript/high_priority_js.txt" 2>/dev/null || echo 0)" >> "$output_dir/javascript/summary.txt"
                    echo "Unique endpoints found: $endpoint_count" >> "$output_dir/javascript/summary.txt"
                    echo "" >> "$output_dir/javascript/summary.txt"
                    echo "Top endpoint patterns:" >> "$output_dir/javascript/summary.txt"
                    grep -o -E "(api|ajax|rest|graphql|wp-json|v[0-9]+)/[^'\"?&]+" "$output_dir/javascript/endpoints.txt" 2>/dev/null | \
                        sort | uniq -c | sort -rn | head -10 >> "$output_dir/javascript/summary.txt" 2>/dev/null || true
                fi
            else
                echo -e "${YELLOW}[!]${NC} jsscan not found. Skipping JavaScript analysis."
                log_msg "JS analysis SKIP: jsscan not found"
            fi

            echo -e "${YELLOW}[>]${NC} Checking for source maps..."
            local httpx_proxy=$(get_httpx_proxy)
            cat "$output_dir/javascript/filtered_js_urls.txt" | \
                sed 's/\.js$/\.js.map/' | \
                httpx -silent -mc 200 $httpx_proxy -o "$output_dir/javascript/source_maps.txt" 2>>"$error_log" || true
            
            local map_count
            map_count=$(wc -l < "$output_dir/javascript/source_maps.txt" 2>/dev/null || echo 0)
            if [ "$map_count" -gt 0 ]; then
                echo -e "${GREEN}[✓]${NC} Found $map_count source maps (potential code leakage!)"
                log_msg "Source maps found: $map_count"
            else
                echo -e "${BLUE}[i]${NC} No source maps found"
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
            log_msg "JS analysis: zero files after filter"
        fi
    else
        echo -e "${YELLOW}[!]${NC} No JavaScript files found"
        log_msg "Phase 5: zero JS files found"
    fi
    log_msg "=== PHASE 5 DONE ==="
}

# API Discovery
phase_api_discovery() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 5.5]${NC} API Endpoint Discovery"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 5.5 START: API Discovery ==="

    if [ ! -s "$output_dir/alive_subdomains_https.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive hosts for API discovery"
        log_msg "Phase 5.5 SKIP: no alive hosts"
        return
    fi

    mkdir -p "$output_dir/api_discovery"

    echo -e "${YELLOW}[>]${NC} Probing for common API paths..."
    
    # Check for common API endpoints
    local api_paths=(
        "/api"
        "/api/v1"
        "/api/v2"
        "/api/v3"
        "/v1"
        "/v2"
        "/rest"
        "/rest/api"
        "/graphql"
        "/api/graphql"
        "/swagger"
        "/swagger.json"
        "/swagger.yaml"
        "/swagger-ui"
        "/api-docs"
        "/api/docs"
        "/openapi.json"
        "/openapi.yaml"
        "/api/swagger"
        "/api.php"
        "/api/index.php"
        "/rest.php"
    )

    # Create temporary file with all path combinations
    > "$output_dir/api_discovery/api_paths_to_test.txt"
    while IFS= read -r host; do
        for path in "${api_paths[@]}"; do
            echo "${host}${path}" >> "$output_dir/api_discovery/api_paths_to_test.txt"
        done
    done < "$output_dir/alive_subdomains_https.txt"

    local httpx_proxy=$(get_httpx_proxy)
    run_cmd_with_retry \
        "httpx -l $output_dir/api_discovery/api_paths_to_test.txt -mc 200,201,401,403 -silent $httpx_proxy -o $output_dir/api_discovery/api_endpoints.txt" \
        "API Path Discovery" \
        "$error_log"

    local api_count
    api_count=$(wc -l < "$output_dir/api_discovery/api_endpoints.txt" 2>/dev/null || echo 0)
    
    if [ "$api_count" -gt 0 ]; then
        echo -e "${GREEN}[✓]${NC} Found $api_count API endpoints"
        log_msg "API endpoints found: $api_count"

        # Check for GraphQL
        echo -e "${YELLOW}[>]${NC} Checking for GraphQL endpoints..."
        grep -i "graphql" "$output_dir/api_discovery/api_endpoints.txt" > "$output_dir/api_discovery/graphql_endpoints.txt" 2>/dev/null || true
        
        local graphql_count
        graphql_count=$(wc -l < "$output_dir/api_discovery/graphql_endpoints.txt" 2>/dev/null || echo 0)
        if [ "$graphql_count" -gt 0 ]; then
            echo -e "${GREEN}[✓]${NC} Found $graphql_count GraphQL endpoints"
        fi

        # Check for Swagger/OpenAPI docs
        echo -e "${YELLOW}[>]${NC} Checking for Swagger/OpenAPI documentation..."
        grep -iE "swagger|openapi|api-docs" "$output_dir/api_discovery/api_endpoints.txt" > "$output_dir/api_discovery/swagger_endpoints.txt" 2>/dev/null || true
        
        local swagger_count
        swagger_count=$(wc -l < "$output_dir/api_discovery/swagger_endpoints.txt" 2>/dev/null || echo 0)
        if [ "$swagger_count" -gt 0 ]; then
            echo -e "${GREEN}[✓]${NC} Found $swagger_count Swagger/OpenAPI documentation endpoints"
        fi
    else
        echo -e "${BLUE}[i]${NC} No API endpoints found"
    fi

    log_msg "=== PHASE 5.5 DONE ==="
}

# Lightweight Cloud Asset Check (CT Logs)
phase_cloud_discovery() {
    local domain=$1
    local output_dir=$2
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 5.6]${NC} Lightweight Cloud Asset Check"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 5.6 START: Lightweight Cloud Check ==="

    mkdir -p "$output_dir/cloud_assets"

    # Important notice for users
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}ℹ️  CLOUD ENUMERATION NOTICE${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} This is a LIGHTWEIGHT quick check via CT logs.            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${RED}⚠️  Proper cloud enumeration should be done SEPARATELY${NC}   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    and MANUALLY for best results.                         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} Professional cloud hunting requires:                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   • Keyword generation (company names, products, etc.)    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   • Multiple tools (cloud_enum, S3Scanner, CloudBrute)    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   • GitHub/JS analysis for bucket references              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   • Manual validation of findings                         ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${YELLOW}[>]${NC} Running quick CT logs check for cloud patterns (30s max)..."
    log_msg "Quick cloud check via Certificate Transparency logs"

    # Extract base domain
    local base_domain
    base_domain=$(echo "$domain" | sed 's/www\.//')

    # Initialize output files
    > "$output_dir/cloud_assets/s3_buckets.txt"
    > "$output_dir/cloud_assets/azure_blobs.txt"
    > "$output_dir/cloud_assets/gcs_buckets.txt"
    > "$output_dir/cloud_assets/ct_cloud_patterns.txt"

    # Check CT logs for cloud patterns (with timeout)
    echo -e "${CYAN}[*]${NC} Checking Certificate Transparency logs for cloud service patterns..."
    
    local curl_proxy=$(get_curl_proxy)
    
    (
        curl -s $curl_proxy "https://crt.sh/?q=%.${base_domain}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | \
            sort -u > "$output_dir/cloud_assets/ct_subdomains.txt" || true

        # Extract cloud patterns from CT results
        if [ -s "$output_dir/cloud_assets/ct_subdomains.txt" ]; then
            # Look for S3 patterns
            grep -iE "s3|aws|amazon|bucket" "$output_dir/cloud_assets/ct_subdomains.txt" | \
                grep -v "\.js$" > "$output_dir/cloud_assets/s3_patterns.txt" 2>/dev/null || true
            
            # Look for Azure patterns  
            grep -iE "blob|azure|windows\.net" "$output_dir/cloud_assets/ct_subdomains.txt" | \
                grep -v "\.js$" > "$output_dir/cloud_assets/azure_patterns.txt" 2>/dev/null || true
            
            # Look for GCS patterns
            grep -iE "storage|googleapis|gcp|google" "$output_dir/cloud_assets/ct_subdomains.txt" | \
                grep -v "\.js$" > "$output_dir/cloud_assets/gcs_patterns.txt" 2>/dev/null || true

            # Combine all patterns
            cat "$output_dir/cloud_assets/s3_patterns.txt" \
                "$output_dir/cloud_assets/azure_patterns.txt" \
                "$output_dir/cloud_assets/gcs_patterns.txt" 2>/dev/null | \
                sort -u > "$output_dir/cloud_assets/ct_cloud_patterns.txt" || true
        fi

        # Also check already discovered subdomains for cloud patterns
        if [ -s "$output_dir/all_subdomains.txt" ]; then
            grep -iE "s3\.|\.s3\.|s3-|amazonaws\.com" "$output_dir/all_subdomains.txt" >> "$output_dir/cloud_assets/s3_buckets.txt" 2>/dev/null || true
            grep -iE "blob\.core\.windows\.net|azure" "$output_dir/all_subdomains.txt" >> "$output_dir/cloud_assets/azure_blobs.txt" 2>/dev/null || true
            grep -iE "storage\.googleapis\.com|\.gcp\." "$output_dir/all_subdomains.txt" >> "$output_dir/cloud_assets/gcs_buckets.txt" 2>/dev/null || true
        fi

        # Sort and deduplicate
        sort -u -o "$output_dir/cloud_assets/s3_buckets.txt" "$output_dir/cloud_assets/s3_buckets.txt" 2>/dev/null || true
        sort -u -o "$output_dir/cloud_assets/azure_blobs.txt" "$output_dir/cloud_assets/azure_blobs.txt" 2>/dev/null || true
        sort -u -o "$output_dir/cloud_assets/gcs_buckets.txt" "$output_dir/cloud_assets/gcs_buckets.txt" 2>/dev/null || true
    ) &
    
    local ct_pid=$!
    
    # Wait with 30 second timeout
    local elapsed=0
    while kill -0 $ct_pid 2>/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ $elapsed -ge 30 ]; then
            kill $ct_pid 2>/dev/null || true
            echo -e "${YELLOW}[!]${NC} CT check timeout (30s) - continuing..."
            break
        fi
    done
    
    wait $ct_pid 2>/dev/null || true

    # Count results
    local s3_count azure_count gcs_count ct_patterns_count
    s3_count=$(wc -l < "$output_dir/cloud_assets/s3_buckets.txt" 2>/dev/null || echo 0)
    azure_count=$(wc -l < "$output_dir/cloud_assets/azure_blobs.txt" 2>/dev/null || echo 0)
    gcs_count=$(wc -l < "$output_dir/cloud_assets/gcs_buckets.txt" 2>/dev/null || echo 0)
    ct_patterns_count=$(wc -l < "$output_dir/cloud_assets/ct_cloud_patterns.txt" 2>/dev/null || echo 0)

    # Summary
    echo -e "${GREEN}[✓]${NC} Lightweight Cloud Check Summary:"
    echo -e "  • S3 Patterns Found:   ${YELLOW}$s3_count${NC}"
    echo -e "  • Azure Patterns:      ${YELLOW}$azure_count${NC}"
    echo -e "  • GCS Patterns:        ${YELLOW}$gcs_count${NC}"
    echo -e "  • CT Cloud Patterns:   ${YELLOW}$ct_patterns_count${NC}"
    
    if [ $((s3_count + azure_count + gcs_count)) -gt 0 ]; then
        echo -e "${CYAN}[i]${NC} These are POTENTIAL indicators. Validate manually!"
    else
        echo -e "${BLUE}[i]${NC} No cloud patterns detected in quick check"
    fi

    # Create lightweight summary
    cat > "$output_dir/cloud_assets/README.txt" <<EOF
Cloud Asset Quick Check Summary
================================
Date: $(date '+%Y-%m-%d %H:%M:%S')
Domain: $domain
Method: Certificate Transparency Logs + Subdomain Pattern Matching

⚠️  IMPORTANT: This is a LIGHTWEIGHT quick check only!

For comprehensive cloud enumeration, you should:
1. Generate proper keywords (company names, products, teams)
2. Use multiple tools: cloud_enum, S3Scanner, CloudBrute
3. Check GitHub repos for bucket references
4. Analyze JavaScript files for cloud URLs
5. Monitor CT logs continuously
6. Manually validate all findings

Results from this quick check:
- S3 Patterns: $s3_count (see s3_buckets.txt)
- Azure Patterns: $azure_count (see azure_blobs.txt)  
- GCS Patterns: $gcs_count (see gcs_buckets.txt)
- CT Patterns: $ct_patterns_count (see ct_cloud_patterns.txt)

These are POTENTIAL indicators only - not confirmed cloud assets.
Manual validation required!
EOF

    log_msg "Lightweight cloud check: S3=$s3_count Azure=$azure_count GCS=$gcs_count CT=$ct_patterns_count"
    log_msg "=== PHASE 5.6 DONE ==="
}

# NEW PHASE: WAF Detection
phase_waf_detection() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 5.7]${NC} WAF Detection"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 5.7 START: WAF Detection ==="

    if [ ! -s "$output_dir/alive_subdomains_https.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive hosts for WAF detection"
        log_msg "Phase 5.7 SKIP: no alive hosts"
        return
    fi

    mkdir -p "$output_dir/waf_detection"

    # Check if wafw00f is available
    if ! command_exists wafw00f; then
        echo -e "${YELLOW}[!]${NC} wafw00f not found. Skipping WAF detection."
        log_msg "Phase 5.7 SKIP: wafw00f not installed"
        return
    fi

    echo -e "${YELLOW}[>]${NC} Detecting Web Application Firewalls..."
    
    # Run wafw00f on alive hosts (limit to first 20 to avoid long scan times)
    head -20 "$output_dir/alive_subdomains_https.txt" | while read -r url; do
        echo "=== Testing: $url ===" >> "$output_dir/waf_detection/waf_results.txt"
        wafw00f "$url" -a 2>>"$error_log" >> "$output_dir/waf_detection/waf_results.txt" || true
        echo "" >> "$output_dir/waf_detection/waf_results.txt"
    done

    # Parse results for detected WAFs
    if [ -f "$output_dir/waf_detection/waf_results.txt" ]; then
        grep -B1 "is behind" "$output_dir/waf_detection/waf_results.txt" > "$output_dir/waf_detection/detected_wafs.txt" 2>/dev/null || true
        
        local waf_count
        waf_count=$(grep -c "is behind" "$output_dir/waf_detection/waf_results.txt" 2>/dev/null || echo "0")
        
        # Ensure waf_count is a valid integer (remove any extra characters/spaces)
        waf_count=$(echo "$waf_count" | tr -d ' ' | grep -oE '^[0-9]+$' || echo "0")
        
        if [ "$waf_count" -gt 0 ] 2>/dev/null; then
            echo -e "${GREEN}[✓]${NC} Detected WAF on $waf_count hosts"
            log_msg "WAFs detected: $waf_count hosts"
        else
            echo -e "${BLUE}[i]${NC} No WAFs detected"
        fi
    fi

    log_msg "=== PHASE 5.7 DONE ==="
}

phase_nuclei_scanning() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 6]${NC} Nuclei Vulnerability Scanning"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 6 START: Nuclei Vulnerability Scanning ==="

    # Check if user wants to run Nuclei
    if [ "$RUN_NUCLEI" -ne 1 ]; then
        echo -e "${YELLOW}[!]${NC} Nuclei scanning disabled by user choice"
        log_msg "Phase 6 SKIP: user chose not to run Nuclei"
        return
    fi

    if [ ! -s "$output_dir/alive_subdomains_https.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive hosts for Nuclei scanning"
        log_msg "Phase 6 SKIP: no alive hosts"
        return
    fi

    # Check if nuclei is installed
    if ! command_exists nuclei; then
        echo -e "${YELLOW}[!]${NC} Nuclei not found. Skipping Nuclei scan."
        log_msg "Phase 6 SKIP: nuclei not installed"
        return
    fi

    mkdir -p "$output_dir/nuclei_scan"

    echo -e "${CYAN}[*]${NC} Starting Nuclei scan..."
    echo -e "${YELLOW}[!]${NC} This may take a while. Press ${RED}Ctrl+C${NC} to skip Nuclei and continue to next phase."
    echo -e "${YELLOW}[!]${NC} Rate limit: $NUCLEI_RATE_LIMIT req/min | Concurrency: $NUCLEI_CONCURRENCY"
    log_msg "Nuclei scan starting: rate=$NUCLEI_RATE_LIMIT concurrency=$NUCLEI_CONCURRENCY"

    # Set up trap for Ctrl+C during Nuclei scan only
    nuclei_interrupted=0
    nuclei_trap() {
        nuclei_interrupted=1
        echo -e "\n${YELLOW}[!]${NC} Nuclei scan interrupted by user. Skipping to next phase..."
        log_msg "Nuclei scan interrupted by user (Ctrl+C)"
        # Kill the nuclei process
        pkill -P $$ nuclei 2>/dev/null || true
        return 0
    }
    
    trap nuclei_trap SIGINT

    local nuclei_proxy=$(get_httpx_proxy)
    if [ -n "$nuclei_proxy" ]; then
        echo -e "${CYAN}[*]${NC} Using Tor proxy for Nuclei scan"
    fi

    (
        nuclei -l "$output_dir/alive_subdomains_https.txt" \
               -severity critical,high,medium \
               -exclude-severity info \
               -rl "$NUCLEI_RATE_LIMIT" \
               -c "$NUCLEI_CONCURRENCY" \
               -timeout 10 \
               -retries 1 \
               -stats \
               -silent \
               $nuclei_proxy \
               -o "$output_dir/nuclei_scan/nuclei_findings.txt" \
               2>>"$error_log" || true
    ) &
    
    local nuclei_pid=$!

    # Monitor the Nuclei process
    local elapsed=0
    while kill -0 $nuclei_pid 2>/dev/null; do
        if [ $nuclei_interrupted -eq 1 ]; then
            break
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        
        # Show progress every minute
        if [ $((elapsed % 60)) -eq 0 ]; then
            echo -e "${CYAN}[*]${NC} Nuclei scan running... ($((elapsed / 60)) minutes elapsed)"
        fi
        
        # Check timeout
        if [ $elapsed -ge $NUCLEI_TIMEOUT ]; then
            echo -e "${YELLOW}[!]${NC} Nuclei scan timeout reached ($NUCLEI_TIMEOUT seconds)"
            log_msg "Nuclei scan TIMEOUT after ${NUCLEI_TIMEOUT}s"
            kill $nuclei_pid 2>/dev/null || true
            break
        fi
    done

    # Wait for cleanup
    wait $nuclei_pid 2>/dev/null || true

    # Reset trap
    trap - SIGINT

    # Ensure nuclei result files exist (create empty ones if needed)
    touch "$output_dir/nuclei_scan/critical.txt" 2>/dev/null || true
    touch "$output_dir/nuclei_scan/high.txt" 2>/dev/null || true
    touch "$output_dir/nuclei_scan/medium.txt" 2>/dev/null || true

    # Process results
    if [ -f "$output_dir/nuclei_scan/nuclei_findings.txt" ] && [ -s "$output_dir/nuclei_scan/nuclei_findings.txt" ]; then
        local findings_count
        findings_count=$(wc -l < "$output_dir/nuclei_scan/nuclei_findings.txt")
        
        # Parse by severity (overwrite the empty files)
        grep "\[critical\]" "$output_dir/nuclei_scan/nuclei_findings.txt" > "$output_dir/nuclei_scan/critical.txt" 2>/dev/null || touch "$output_dir/nuclei_scan/critical.txt"
        grep "\[high\]" "$output_dir/nuclei_scan/nuclei_findings.txt" > "$output_dir/nuclei_scan/high.txt" 2>/dev/null || touch "$output_dir/nuclei_scan/high.txt"
        grep "\[medium\]" "$output_dir/nuclei_scan/nuclei_findings.txt" > "$output_dir/nuclei_scan/medium.txt" 2>/dev/null || touch "$output_dir/nuclei_scan/medium.txt"
        
        local critical_count high_count medium_count
        critical_count=$(wc -l < "$output_dir/nuclei_scan/critical.txt" 2>/dev/null || echo 0)
        high_count=$(wc -l < "$output_dir/nuclei_scan/high.txt" 2>/dev/null || echo 0)
        medium_count=$(wc -l < "$output_dir/nuclei_scan/medium.txt" 2>/dev/null || echo 0)
        
        echo -e "${GREEN}[✓]${NC} Nuclei scan completed: $findings_count total findings"
        echo -e "  • Critical: ${RED}$critical_count${NC}"
        echo -e "  • High:     ${YELLOW}$high_count${NC}"
        echo -e "  • Medium:   ${BLUE}$medium_count${NC}"
        
        log_msg "Nuclei findings: total=$findings_count critical=$critical_count high=$high_count medium=$medium_count"
    elif [ $nuclei_interrupted -eq 1 ]; then
        echo -e "${YELLOW}[!]${NC} Nuclei scan was interrupted. Partial results may be available."
        log_msg "Nuclei scan interrupted - partial results"
    else
        echo -e "${GREEN}[✓]${NC} Nuclei scan completed"
        echo -e "${BLUE}[i]${NC} No vulnerabilities found - target appears secure!"
        log_msg "Nuclei scan: zero findings (clean scan)"
    fi

    log_msg "=== PHASE 6 DONE ==="
}

phase_vulnerability_scanning() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 7]${NC} Vulnerability Pattern Matching"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 7 START: Vulnerability Pattern Matching ==="

    if [ ! -s "$output_dir/all_urls.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No URLs to scan"
        log_msg "Phase 7 SKIP: no URLs"
        return
    fi

    local httpx_proxy=$(get_httpx_proxy)
    cat "$output_dir/all_urls.txt" | uro 2>/dev/null | httpx -silent $httpx_proxy > "$output_dir/filtered-urls.txt" 2>/dev/null

    if [ ! -s "$output_dir/filtered-urls.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No filtered URLs for vulnerability scanning"
        log_msg "Phase 7 SKIP: no filtered URLs after uro+httpx"
        return
    fi

    # Exclude static files
    cat "$output_dir/filtered-urls.txt" | grep -Eiv "\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)$" > "$output_dir/potential-url.txt"

    # Run pattern matching in parallel
    local gf_patterns=("xss" "sqli" "lfi" "ssrf" "rce" "redirect" "ssti" "idor")

    echo -e "${CYAN}[*]${NC} Running ${#gf_patterns[@]} pattern matching tasks in parallel..."

    local i=0
    for pattern in "${gf_patterns[@]}"; do
        echo -e "  [$(printf "%02d" $((i+1)))] GF $pattern"
        i=$((i + 1))
    done

    # Run commands in background
    local pids=()
    i=0
    for pattern in "${gf_patterns[@]}"; do
        (
            cat "$output_dir/potential-url.txt" | gf "$pattern" > "$output_dir/vulnerability_scan/${pattern}.txt" 2>>"$error_log"
            local count
            count=$(wc -l < "$output_dir/vulnerability_scan/${pattern}.txt" 2>/dev/null || echo 0)
            echo -e "  [$(printf "%02d" $((i+1)))] ${GREEN}✓${NC} GF $pattern: $count findings"
        ) &
        pids+=($!)
        i=$((i + 1))

        # Control concurrent jobs
        if [ ${#pids[@]} -ge $MAX_PARALLEL_JOBS ]; then
            wait -n 2>/dev/null || true
        fi
    done

    # Wait for all remaining jobs
    wait "${pids[@]}" 2>/dev/null || true

    # Display summary
    echo -e "${YELLOW}[>]${NC} Vulnerability Summary:"
    for pattern in "${gf_patterns[@]}"; do
        local count
        count=$(wc -l < "$output_dir/vulnerability_scan/${pattern}.txt" 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            echo -e "  • ${pattern}: ${YELLOW}${count}${NC} potential findings"
        else
            echo -e "  • ${pattern}: ${GREEN}${count}${NC} potential findings"
        fi
        log_msg "Vuln pattern $pattern: $count findings"
    done
    log_msg "=== PHASE 7 DONE ==="
}

phase_dns_recon() {
    local domain=$1
    local output_dir=$2
    local fingerprint=$3
    local error_log="$output_dir/errors.log"
    local subdomain_file="$output_dir/all_subdomains.txt"

    echo -e "\n${BLUE}[PHASE 8]${NC} DNS & Network Intelligence"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 8 START: DNS & Network Intelligence ==="

    # Create directories for subdomain scan results
    mkdir -p "$output_dir/network/subdomains_dnsrecon"
    mkdir -p "$output_dir/network/subdomains_dig"

    # Parallel DNS reconnaissance for main domain
    local dns_commands=(
        "dnsrecon -d $domain -t std,axfr -c $output_dir/network/dnsrecon.csv 2>>$error_log; echo 'desc:\"DNSRecon (Main Domain)\"'"

        "{ for t in A AAAA MX NS TXT CNAME SOA TRACE; do echo \"=== \$t ===\"&& dig $domain \$t +short; done; } > $output_dir/network/dig.txt 2>>$error_log; echo 'desc:\"DIG (Main Domain)\"'"

        "whois $domain > $output_dir/network/whois.txt 2>>$error_log; echo 'desc:\"WHOIS (Main Domain)\"'"
    )

    # Add subdomain scanning commands if subdomains exist
    if [ -s "$subdomain_file" ]; then
        local subdomain_count
        subdomain_count=$(wc -l < "$subdomain_file")
        echo -e "${CYAN}[i]${NC} Scanning ${YELLOW}$subdomain_count${NC} discovered subdomains..."
        log_msg "DNS recon: scanning $subdomain_count subdomains"

        # 1. DNSRecon for all subdomains
        dns_commands+=(
            "while read sub; do [ -z \"\$sub\" ] && continue; safe=\$(echo \$sub | tr -cd '[:alnum:]_-'); timeout 15 dnsrecon -d \$sub -t std,axfr  -c \"$output_dir/network/subdomains_dnsrecon/\${safe}_std.csv\" 2>>$error_log; done < \"$subdomain_file\"; echo 'desc:\"DNSRecon (All Subdomains)\"'"
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
        else
            log_msg "Phase 8: subjack not found — skipping takeover check"
        fi
    fi

    run_parallel "${dns_commands[@]}"
    echo -e "${GREEN}[✓]${NC} DNS reconnaissance completed for all subdomains"
    log_msg "=== PHASE 8 DONE ==="
}

phase_screenshots() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 9]${NC} Screenshot Capture"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 9 START: Screenshot Capture ==="

    if [ ! -s "$output_dir/alive_subdomains_https.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No URLs for screenshots"
        log_msg "Phase 9 SKIP: no alive URLs"
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
        log_msg "Phase 9 SKIP: Chromium not found"
        return
    fi

    mkdir -p "$output_dir/gowitness_screenshots"

    local gowitness_proxy=""
    local httpx_proxy=$(get_httpx_proxy)
    if [ -n "$httpx_proxy" ]; then
        gowitness_proxy="--chrome-proxy socks5://127.0.0.1:$TOR_SOCKS_PORT"
    fi

    run_cmd_with_retry \
        "gowitness scan file -f $output_dir/alive_subdomains_https.txt \
         $CHROMIUM_PATH \
         --threads 20 \
         --timeout 90 \
         $gowitness_proxy \
         --screenshot-path $output_dir/gowitness_screenshots \
         --screenshot-fullpage \
         --write-jsonl --write-jsonl-file gowitness.jsonl \
         --write-screenshots \
         --write-stdout" \
        "Gowitness Screenshots" \
        "$error_log"

    local count
    count=$(find "$output_dir/gowitness_screenshots" -name "*.jpeg" 2>/dev/null | wc -l)
    echo -e "${GREEN}[✓]${NC} Captured $count screenshots"
    log_msg "Screenshots captured: $count"
    log_msg "=== PHASE 9 DONE ==="
}

phase_technology_detection() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 10]${NC} Technology Detection & Fingerprinting"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 10 START: Technology Detection ==="

    if [ ! -s "$output_dir/alive_subdomains_https.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive hosts for technology detection"
        log_msg "Phase 10 SKIP: no alive hosts"
        return
    fi

    mkdir -p "$output_dir/technology"

    echo -e "${YELLOW}[>]${NC} Running comprehensive technology fingerprinting..."

    local httpx_proxy=$(get_httpx_proxy)
    run_cmd_with_retry \
        "httpx -l $output_dir/alive_subdomains_https.txt \
               -td \
               -server \
               -title \
               -sc \
               -cl \
               -ct \
               -method \
               -websocket \
               -http2 \
               -pipeline \
               -tls-grab \
               -jarm \
               -favicon \
               -hash sha256 \
               -rt \
               -threads $HTTPX_THREADS \
               -timeout 10 \
               -retries 2 \
               $httpx_proxy \
               -json \
               -o $output_dir/technology/tech_detection.json \
               2>>$error_log" \
        "Technology Detection (httpx)" \
        "$error_log"

    if [ ! -s "$output_dir/technology/tech_detection.json" ]; then
        echo -e "${RED}[!]${NC} Tech detection JSON is empty — httpx may have failed entirely"
        log_msg "Phase 10 WARNING: tech_detection.json is empty"
        echo -e "${YELLOW}[>]${NC} Running fallback plain-text tech detection..."
        httpx -l "$output_dir/alive_subdomains_https.txt" \
              -td -server -title -sc \
              -threads "$HTTPX_THREADS" \
              $httpx_proxy \
              -timeout 10 \
              -o "$output_dir/technology/tech_detection_plain.txt" \
              2>>"$error_log" || true
        log_msg "Phase 10: fallback plain-text detection ran"
    fi

    # Process and categorize results
    process_technology_results "$output_dir"
    log_msg "=== PHASE 10 DONE ==="
}

process_technology_results() {
    local output_dir=$1

    echo -e "${YELLOW}[>]${NC} Processing technology detection results..."

    # All jq commands use --slurp to handle NDJSON properly
    if command_exists jq && [ -f "$output_dir/technology/tech_detection.json" ] && [ -s "$output_dir/technology/tech_detection.json" ]; then
        echo -e "${YELLOW}[>]${NC} Extracting technology statistics..."
        vlog "Processing NDJSON with jq --slurp"

        # Generate human-readable output
        jq -s -r '.[] | "[\(.status_code)] \(.url) [\(.webserver // "Unknown")] [\(.title // "No Title")] [Tech: \(.tech // [] | join(", "))]"' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null \
            > "$output_dir/technology/tech_detection.txt" || true

        # Extract unique technologies
        jq -s -r '.[] | .tech[]?' "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/unique_technologies.txt" || true

        # Extract web servers
        jq -s -r '.[] | select(.webserver != null) | "\(.url) | \(.webserver)"' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/web_servers.txt" || true

        # Extract HTTP/2 support
        jq -s -r '.[] | select(.http2 == true) | .url' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/http2_support.txt" || true

        # Extract pipeline support
        jq -s -r '.[] | select(.pipeline == true) | .url' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/pipeline_support.txt" || true

        # Extract WebSocket support
        jq -s -r '.[] | select(.websocket == true) | .url' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/websocket_support.txt" || true

        # Group by technology (CMSs, Frameworks, etc.)
        echo -e "${YELLOW}[>]${NC} Categorizing technologies..."

        # WordPress sites
        jq -s -r '.[] | select((.tech // [])[] | ascii_downcase | contains("wordpress")) | .url' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/cms_wordpress.txt" || true

        # Joomla sites
        jq -s -r '.[] | select((.tech // [])[] | ascii_downcase | contains("joomla")) | .url' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/cms_joomla.txt" || true

        # Drupal sites
        jq -s -r '.[] | select((.tech // [])[] | ascii_downcase | contains("drupal")) | .url' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/cms_drupal.txt" || true

        # ASP.NET sites
        jq -s -r '.[] | select((.tech // [])[] | ascii_downcase | contains("asp.net")) | .url' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/framework_aspnet.txt" || true

        # Laravel sites
        jq -s -r '.[] | select((.tech // [])[] | ascii_downcase | contains("laravel")) | .url' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/framework_laravel.txt" || true

        # React sites
        jq -s -r '.[] | select((.tech // [])[] | ascii_downcase | contains("react")) | .url' \
            "$output_dir/technology/tech_detection.json" 2>/dev/null | \
            sort -u > "$output_dir/technology/framework_react.txt" || true

        # Generate technology summary
        cat > "$output_dir/technology/summary.txt" <<EOF
Technology Detection Summary
============================

Total Hosts Scanned: $(wc -l < "$output_dir/alive_subdomains_https.txt" 2>/dev/null || echo 0)
Unique Technologies: $(wc -l < "$output_dir/technology/unique_technologies.txt" 2>/dev/null || echo 0)

Web Servers:
$(wc -l < "$output_dir/technology/web_servers.txt" 2>/dev/null || echo 0) servers detected

Protocol Support:
- HTTP/2: $(wc -l < "$output_dir/technology/http2_support.txt" 2>/dev/null || echo 0) hosts
- Pipeline: $(wc -l < "$output_dir/technology/pipeline_support.txt" 2>/dev/null || echo 0) hosts
- WebSocket: $(wc -l < "$output_dir/technology/websocket_support.txt" 2>/dev/null || echo 0) hosts

CMS Detected:
- WordPress: $(wc -l < "$output_dir/technology/cms_wordpress.txt" 2>/dev/null || echo 0) sites
- Joomla: $(wc -l < "$output_dir/technology/cms_joomla.txt" 2>/dev/null || echo 0) sites
- Drupal: $(wc -l < "$output_dir/technology/cms_drupal.txt" 2>/dev/null || echo 0) sites

Frameworks:
- ASP.NET: $(wc -l < "$output_dir/technology/framework_aspnet.txt" 2>/dev/null || echo 0) sites
- Laravel: $(wc -l < "$output_dir/technology/framework_laravel.txt" 2>/dev/null || echo 0) sites
- React: $(wc -l < "$output_dir/technology/framework_react.txt" 2>/dev/null || echo 0) sites

Top 10 Technologies:
$(cat "$output_dir/technology/unique_technologies.txt" 2>/dev/null | head -10 || echo "No data")
EOF

        echo -e "${GREEN}[✓]${NC} Technology categorization complete"
        log_msg "Tech categorization complete"
    else
        echo -e "${YELLOW}[!]${NC} jq not found or JSON file missing/empty. Skipping detailed analysis."
        log_msg "Phase 10 process: jq missing or JSON empty — detailed analysis skipped"
    fi

    # Display summary
    local total_hosts unique_techs http2_count wordpress_count
    total_hosts=$(wc -l < "$output_dir/alive_subdomains_https.txt" 2>/dev/null || echo 0)
    unique_techs=$(wc -l < "$output_dir/technology/unique_technologies.txt" 2>/dev/null || echo 0)
    http2_count=$(wc -l < "$output_dir/technology/http2_support.txt" 2>/dev/null || echo 0)
    wordpress_count=$(wc -l < "$output_dir/technology/cms_wordpress.txt" 2>/dev/null || echo 0)

    echo -e "${GREEN}[✓]${NC} Technology Detection Summary:"
    echo -e "  • Total Hosts: ${GREEN}$total_hosts${NC}"
    echo -e "  • Unique Technologies: ${GREEN}$unique_techs${NC}"
    echo -e "  • HTTP/2 Support: ${GREEN}$http2_count${NC}"
    echo -e "  • WordPress Sites: ${GREEN}$wordpress_count${NC}"
    log_msg "Tech summary: hosts=$total_hosts techs=$unique_techs http2=$http2_count wp=$wordpress_count"
}


phase_parameter_discovery() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 11]${NC} Parameter Discovery"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 11 START: Parameter Discovery ==="

    mkdir -p "$output_dir/parameters"

    # ---- Source 1: Extract all parameters from collected URLs ----
    if [ -s "$output_dir/all_urls.txt" ]; then
        echo -e "${YELLOW}[>]${NC} Extracting parameters from collected URLs..."
        
        grep -oP '\?[^[:space:]]+' "$output_dir/all_urls.txt" 2>/dev/null | \
            tr '&' '\n' | \
            cut -d'=' -f1 | \
            tr -d '?' | \
            sort -u > "$output_dir/parameters/url_params.txt" || true
        
        local url_param_count
        url_param_count=$(wc -l < "$output_dir/parameters/url_params.txt" 2>/dev/null || echo 0)
        echo -e "${GREEN}[✓]${NC} Extracted $url_param_count unique parameters from URLs"
        log_msg "URL params extracted: $url_param_count"
    fi

    # ---- Source 2: Extract parameters from JS endpoints ----
    if [ -s "$output_dir/javascript/endpoints.txt" ]; then
        echo -e "${YELLOW}[>]${NC} Extracting parameters from JavaScript endpoints..."
        
        grep -oP '\?[^[:space:]\"\'"'"']+' "$output_dir/javascript/endpoints.txt" 2>/dev/null | \
            tr '&' '\n' | \
            cut -d'=' -f1 | \
            tr -d '?' | \
            sort -u > "$output_dir/parameters/js_params.txt" || true
        
        local js_param_count
        js_param_count=$(wc -l < "$output_dir/parameters/js_params.txt" 2>/dev/null || echo 0)
        echo -e "${GREEN}[✓]${NC} Extracted $js_param_count unique parameters from JS"
        log_msg "JS params extracted: $js_param_count"
    fi

    # ---- Source 3: Merge all discovered parameters ----
    cat "$output_dir/parameters/"*_params.txt 2>/dev/null | \
        sort -u | \
        grep -v '^$' > "$output_dir/parameters/unique_params.txt" || true

    local total_params
    total_params=$(wc -l < "$output_dir/parameters/unique_params.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓]${NC} Total unique parameters discovered: ${YELLOW}$total_params${NC}"
    log_msg "Total unique params: $total_params"

    # ---- Categorize parameters by type ----
    if [ -s "$output_dir/parameters/unique_params.txt" ]; then
        echo -e "${YELLOW}[>]${NC} Categorizing parameters by vulnerability type..."

        # 1. Redirect-related parameters
        grep -iE "redirect|url|uri|link|next|return|goto|callback|continue|dest|target|view|redir|forward|jump|navigate" \
            "$output_dir/parameters/unique_params.txt" > "$output_dir/parameters/cat_redirect.txt" 2>/dev/null || touch "$output_dir/parameters/cat_redirect.txt"

        # 2. File/Path-related parameters
        grep -iE "file|path|dir|folder|page|doc|document|template|include|load|read|download|upload|attachment" \
            "$output_dir/parameters/unique_params.txt" > "$output_dir/parameters/cat_file_path.txt" 2>/dev/null || touch "$output_dir/parameters/cat_file_path.txt"

        # 3. IDOR / ID-related parameters
        grep -iE "^id$|user|account|profile|uid|userid|username|email|key|token|session|ref|reference|order|item" \
            "$output_dir/parameters/unique_params.txt" > "$output_dir/parameters/cat_idor.txt" 2>/dev/null || touch "$output_dir/parameters/cat_idor.txt"

        # 4. Injection-prone parameters
        grep -iE "search|query|q|cmd|exec|command|code|script|eval|json|xml|data|input|filter|sort|order|by" \
            "$output_dir/parameters/unique_params.txt" > "$output_dir/parameters/cat_injection.txt" 2>/dev/null || touch "$output_dir/parameters/cat_injection.txt"

        # 5. API / Debug parameters
        grep -iE "api|debug|dev|test|admin|config|setting|option|mode|env|log|trace|verbose|format|output|response" \
            "$output_dir/parameters/unique_params.txt" > "$output_dir/parameters/cat_api_debug.txt" 2>/dev/null || touch "$output_dir/parameters/cat_api_debug.txt"

        # ---- Generate test URLs with discovered parameters ----
        echo -e "${YELLOW}[>]${NC} Generating test URLs with parameters..."
        
        if [ -s "$output_dir/alive_subdomains_https.txt" ]; then
            local base_url
            base_url=$(head -1 "$output_dir/alive_subdomains_https.txt")
            
            > "$output_dir/parameters/param_urls.txt"
            while IFS= read -r param; do
                [ -z "$param" ] && continue
                echo "${base_url}?${param}=TEST" >> "$output_dir/parameters/param_urls.txt"
            done < "$output_dir/parameters/unique_params.txt"
            log_msg "Param URLs generated with base=$base_url"
        fi

        # ---- Summary ----
        local cat_redir_n cat_file_n cat_idor_n cat_inject_n cat_api_n
        cat_redir_n=$(wc -l < "$output_dir/parameters/cat_redirect.txt" 2>/dev/null || echo 0)
        cat_file_n=$(wc -l < "$output_dir/parameters/cat_file_path.txt" 2>/dev/null || echo 0)
        cat_idor_n=$(wc -l < "$output_dir/parameters/cat_idor.txt" 2>/dev/null || echo 0)
        cat_inject_n=$(wc -l < "$output_dir/parameters/cat_injection.txt" 2>/dev/null || echo 0)
        cat_api_n=$(wc -l < "$output_dir/parameters/cat_api_debug.txt" 2>/dev/null || echo 0)

        echo -e "${GREEN}[✓]${NC} Parameter Categorization:"
        echo -e "  • Redirect params:     ${YELLOW}${cat_redir_n}${NC}  → cat_redirect.txt"
        echo -e "  • File/Path params:    ${YELLOW}${cat_file_n}${NC}  → cat_file_path.txt"
        echo -e "  • IDOR / ID params:    ${YELLOW}${cat_idor_n}${NC}  → cat_idor.txt"
        echo -e "  • Injection params:    ${YELLOW}${cat_inject_n}${NC}  → cat_injection.txt"
        echo -e "  • API/Debug params:    ${YELLOW}${cat_api_n}${NC}  → cat_api_debug.txt"
        echo -e "  • Ready-to-test URLs:  $(wc -l < "$output_dir/parameters/param_urls.txt" 2>/dev/null || echo 0) → param_urls.txt"

        log_msg "Param categories: redir=$cat_redir_n file=$cat_file_n idor=$cat_idor_n inject=$cat_inject_n api=$cat_api_n"
    else
        echo -e "${YELLOW}[!]${NC} No parameters found to categorize"
        log_msg "Phase 11: no params to categorize"
    fi

    log_msg "=== PHASE 11 DONE ==="
}

phase_enhanced_parameter_fuzzing() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 12]${NC} Enhanced Parameter Fuzzing"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 12 START: Enhanced Parameter Fuzzing ==="

    if [ ! -s "$output_dir/alive_subdomains_https.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive hosts for parameter fuzzing"
        log_msg "Phase 12 SKIP: no alive hosts"
        return
    fi

    # Check if arjun is installed
    if ! command_exists arjun; then
        echo -e "${YELLOW}[!]${NC} Arjun not found. Skipping parameter fuzzing."
        log_msg "Phase 12 SKIP: arjun not installed"
        return
    fi

    mkdir -p "$output_dir/param_fuzzing"

    echo -e "${YELLOW}[>]${NC} Running Arjun parameter fuzzing (passive mode)..."
    echo -e "${YELLOW}[*]${NC} Testing top 10 hosts for hidden parameters..."

    # Limit to first 10 hosts to avoid excessive scan time
    head -10 "$output_dir/alive_subdomains_https.txt" > "$output_dir/param_fuzzing/hosts_to_fuzz.txt"

    # Run arjun in passive mode
    run_cmd_with_retry \
        "arjun -i $output_dir/param_fuzzing/hosts_to_fuzz.txt -oT $output_dir/param_fuzzing/arjun_params.txt" \
        "Arjun Parameter Fuzzing" \
        "$error_log" \
        1 \
        0

    # Parse results
    if [ -f "$output_dir/param_fuzzing/arjun_params.txt" ] && [ -s "$output_dir/param_fuzzing/arjun_params.txt" ]; then
        local param_count
        param_count=$(wc -l < "$output_dir/param_fuzzing/arjun_params.txt")
        echo -e "${GREEN}[✓]${NC} Arjun discovered $param_count hidden parameters"
        log_msg "Arjun params found: $param_count"

        # Merge with existing parameters
        if [ -s "$output_dir/parameters/unique_params.txt" ]; then
            cat "$output_dir/parameters/unique_params.txt" \
                "$output_dir/param_fuzzing/arjun_params.txt" | \
                sort -u > "$output_dir/parameters/all_params_merged.txt"
            
            local merged_count
            merged_count=$(wc -l < "$output_dir/parameters/all_params_merged.txt")
            echo -e "${GREEN}[✓]${NC} Merged parameter list: $merged_count total unique parameters"
        fi
    else
        echo -e "${BLUE}[i]${NC} No additional parameters found by Arjun"
    fi

    log_msg "=== PHASE 12 DONE ==="
}

# NEW PHASE: CORS Misconfiguration Testing
phase_cors_testing() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 13]${NC} CORS Misconfiguration Testing"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 13 START: CORS Testing ==="

    if [ ! -s "$output_dir/alive_subdomains_https.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive hosts for CORS testing"
        log_msg "Phase 13 SKIP: no alive hosts"
        return
    fi

    mkdir -p "$output_dir/cors_testing"

    echo -e "${YELLOW}[>]${NC} Testing for CORS misconfigurations..."
    echo -e "${YELLOW}[*]${NC} Testing top 1000 hosts..."

    # Limit to first 1000 hosts
    head -1000 "$output_dir/alive_subdomains_https.txt" > "$output_dir/cors_testing/hosts_to_test.txt"

    > "$output_dir/cors_testing/cors_vulnerable.txt"
    > "$output_dir/cors_testing/cors_results.txt"

    local curl_proxy=$(get_curl_proxy)
    local vuln_count=0
    while IFS= read -r url; do
        echo "Testing: $url" >> "$output_dir/cors_testing/cors_results.txt"
        
        response=$(curl -s -I $curl_proxy -H "Origin: https://evil.com" "$url" 2>/dev/null || true)
        
        # Check for vulnerable CORS headers
        if echo "$response" | grep -iq "access-control-allow-origin.*evil.com"; then
            echo "[VULN] $url - Reflects arbitrary origin" | tee -a "$output_dir/cors_testing/cors_vulnerable.txt"
            vuln_count=$((vuln_count + 1))
        elif echo "$response" | grep -iq "access-control-allow-origin.*\*"; then
            if echo "$response" | grep -iq "access-control-allow-credentials.*true"; then
                echo "[VULN] $url - Wildcard with credentials" | tee -a "$output_dir/cors_testing/cors_vulnerable.txt"
                vuln_count=$((vuln_count + 1))
            fi
        fi
        
        echo "$response" >> "$output_dir/cors_testing/cors_results.txt"
        echo "---" >> "$output_dir/cors_testing/cors_results.txt"
    done < "$output_dir/cors_testing/hosts_to_test.txt"

    if [ "$vuln_count" -gt 0 ]; then
        echo -e "${RED}[!]${NC} Found $vuln_count CORS misconfigurations!"
        log_msg "CORS vulnerabilities: $vuln_count"
    else
        echo -e "${GREEN}[✓]${NC} No CORS misconfigurations detected"
        log_msg "CORS: no vulnerabilities"
    fi

    log_msg "=== PHASE 13 DONE ==="
}

phase_quick_checks() {
    local output_dir=$1
    local error_log="$output_dir/errors.log"

    echo -e "\n${BLUE}[PHASE 14]${NC} Quick Bug Hunting Checks"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== PHASE 14 START: Quick Bug Hunting Checks ==="

    if [ ! -s "$output_dir/alive_subdomains.txt" ]; then
        echo -e "${YELLOW}[!]${NC} No alive subdomains for quick checks"
        log_msg "Phase 14 SKIP: no alive subdomains"
        return
    fi

    local httpx_proxy=$(get_httpx_proxy)
    echo -e "${YELLOW}[>]${NC} Checking for exposed .git directories"
    run_cmd_with_retry \
        "cat $output_dir/alive_subdomains.txt | sed 's#\$#/.git/HEAD#g' | httpx -silent -content-length -status-code 200,301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 20 $httpx_proxy -title 2>/dev/null | sort -u > $output_dir/git_exposed.txt" \
        "Git Exposed Check" \
        "$error_log"

    local git_count
    git_count=$(wc -l < "$output_dir/git_exposed.txt" 2>/dev/null || echo 0)
    if [ "$git_count" -gt 0 ]; then
        echo -e "${RED}[!]${NC} Found $git_count exposed .git directories!"
    fi

    local curl_proxy=$(get_curl_proxy)
    echo -e "${YELLOW}[>]${NC} Checking for open redirects"
    if [ -f "$output_dir/vulnerability_scan/redirect.txt" ] && [ -s "$output_dir/vulnerability_scan/redirect.txt" ]; then
        local redirect_count=0
        while read -r url; do
            if curl -Is $curl_proxy "$url" 2>/dev/null | grep -q "Location: https://evil.com"; then
                echo "VULN! $url" >> "$output_dir/vulnerability_scan/open_redirect_results.txt"
                redirect_count=$((redirect_count + 1))
            fi
        done < "$output_dir/vulnerability_scan/redirect.txt"
        echo -e "${GREEN}[✓]${NC} Found $redirect_count potential open redirects"
        log_msg "Quick checks: $redirect_count open redirects"
    fi

    echo -e "${GREEN}[✓]${NC} Quick checks completed"
    log_msg "=== PHASE 14 DONE ==="
}

# ===============================================================
# REPORTING AND PIPELINE ORCHESTRATION
# ===============================================================

generate_report() {
    local domain=$1
    local output_dir=$2
    local scan_type=$3
    local reports_dir="$output_dir/reports"

    echo -e "\n${BLUE}[REPORTING]${NC} Generating Enhanced HTML Report"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    log_msg "=== REPORT GENERATION START ==="

    # Collect statistics
    local subdomain_count alive_count port_count url_count screenshot_count js_count git_exposed_count
    subdomain_count=$(wc -l < "$output_dir/all_subdomains.txt" 2>/dev/null || echo 0)
    alive_count=$(wc -l < "$output_dir/alive_subdomains.txt" 2>/dev/null || echo 0)
    port_count=0
    [ -f "$output_dir/portscan/all_results.txt" ] && port_count=$(wc -l < "$output_dir/portscan/all_results.txt" 2>/dev/null || echo 0)
    url_count=$(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo 0)
    screenshot_count=$(find "$output_dir/gowitness_screenshots" -name "*.jpeg" 2>/dev/null | wc -l)
    js_count=$(wc -l < "$output_dir/javascript/js_urls.txt" 2>/dev/null || echo 0)
    git_exposed_count=$(wc -l < "$output_dir/git_exposed.txt" 2>/dev/null || echo 0)
    
    # Nuclei statistics
    local nuclei_count nuclei_critical nuclei_high nuclei_medium
    nuclei_count=0
    nuclei_critical=0
    nuclei_high=0
    nuclei_medium=0
    
    if [ -f "$output_dir/nuclei_scan/nuclei_findings.txt" ]; then
        nuclei_count=$(wc -l < "$output_dir/nuclei_scan/nuclei_findings.txt" 2>/dev/null || echo 0)
    fi
    if [ -f "$output_dir/nuclei_scan/critical.txt" ]; then
        nuclei_critical=$(wc -l < "$output_dir/nuclei_scan/critical.txt" 2>/dev/null || echo 0)
    fi
    if [ -f "$output_dir/nuclei_scan/high.txt" ]; then
        nuclei_high=$(wc -l < "$output_dir/nuclei_scan/high.txt" 2>/dev/null || echo 0)
    fi
    if [ -f "$output_dir/nuclei_scan/medium.txt" ]; then
        nuclei_medium=$(wc -l < "$output_dir/nuclei_scan/medium.txt" 2>/dev/null || echo 0)
    fi

    # API and Cloud statistics
    local api_count cloud_s3 cloud_azure cloud_gcs
    api_count=$(wc -l < "$output_dir/api_discovery/api_endpoints.txt" 2>/dev/null || echo 0)
    cloud_s3=$(wc -l < "$output_dir/cloud_assets/s3_buckets.txt" 2>/dev/null || echo 0)
    cloud_azure=$(wc -l < "$output_dir/cloud_assets/azure_blobs.txt" 2>/dev/null || echo 0)
    cloud_gcs=$(wc -l < "$output_dir/cloud_assets/gcs_buckets.txt" 2>/dev/null || echo 0)

    # Technology detection statistics
    local tech_total tech_wordpress tech_joomla tech_drupal tech_aspnet tech_laravel tech_react tech_http2
    tech_total=$(wc -l < "$output_dir/technology/unique_technologies.txt" 2>/dev/null || echo 0)
    tech_wordpress=$(wc -l < "$output_dir/technology/cms_wordpress.txt" 2>/dev/null || echo 0)
    tech_joomla=$(wc -l < "$output_dir/technology/cms_joomla.txt" 2>/dev/null || echo 0)
    tech_drupal=$(wc -l < "$output_dir/technology/cms_drupal.txt" 2>/dev/null || echo 0)
    tech_aspnet=$(wc -l < "$output_dir/technology/framework_aspnet.txt" 2>/dev/null || echo 0)
    tech_laravel=$(wc -l < "$output_dir/technology/framework_laravel.txt" 2>/dev/null || echo 0)
    tech_react=$(wc -l < "$output_dir/technology/framework_react.txt" 2>/dev/null || echo 0)
    tech_http2=$(wc -l < "$output_dir/technology/http2_support.txt" 2>/dev/null || echo 0)

    # Calculate vulnerability counts
    declare -A vuln_counts
    local gf_patterns=("xss" "sqli" "lfi" "ssrf" "rce" "redirect" "ssti" "idor")

    for pattern in "${gf_patterns[@]}"; do
        vuln_counts[$pattern]=$(wc -l < "$output_dir/vulnerability_scan/${pattern}.txt" 2>/dev/null || echo 0)
    done

    # Create reports directory
    mkdir -p "$reports_dir"
    
    # Generate HTML Report
    cat > "$reports_dir/report.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Recon Report - $domain</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f23; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: #1a1a2e; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; border-radius: 10px 10px 0 0; text-align: center; }
        .header h1 { color: white; font-size: 2.5em; margin-bottom: 10px; }
        .header p { color: #f0f0f0; font-size: 1.2em; }
        .content { padding: 40px; }
        .section { margin-bottom: 30px; background: #16213e; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }
        .section h2 { color: #667eea; margin-bottom: 15px; font-size: 1.8em; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
        .stat-card { background: #0f0f23; padding: 15px; border-radius: 8px; border: 1px solid #667eea; }
        .stat-card h3 { color: #667eea; font-size: 0.9em; margin-bottom: 8px; }
        .stat-card .value { font-size: 2em; color: #4ade80; font-weight: bold; }
        .stat-card.warning .value { color: #fbbf24; }
        .stat-card.critical .value { color: #ef4444; }
        .vuln-list { list-style: none; margin-top: 10px; }
        .vuln-list li { padding: 8px; background: #0f0f23; margin-bottom: 5px; border-radius: 4px; display: flex; justify-content: space-between; }
        .vuln-list .vuln-name { color: #e0e0e0; }
        .vuln-list .vuln-count { color: #fbbf24; font-weight: bold; }
        .footer { text-align: center; padding: 20px; color: #999; border-top: 1px solid #667eea; }
        .timestamp { color: #999; font-size: 0.9em; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Bug Bounty Reconnaissance Report</h1>
            <p>Target: <strong>$domain</strong></p>
            <p class="timestamp">Generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="stat-grid">
                    <div class="stat-card">
                        <h3>Subdomains Discovered</h3>
                        <div class="value">$subdomain_count</div>
                    </div>
                    <div class="stat-card">
                        <h3>Live Web Services</h3>
                        <div class="value">$alive_count</div>
                    </div>
                    <div class="stat-card">
                        <h3>Open Ports</h3>
                        <div class="value">$port_count</div>
                    </div>
                    <div class="stat-card">
                        <h3>URLs Collected</h3>
                        <div class="value">$url_count</div>
                    </div>
                    <div class="stat-card">
                        <h3>JavaScript Files</h3>
                        <div class="value">$js_count</div>
                    </div>
                    <div class="stat-card">
                        <h3>Screenshots</h3>
                        <div class="value">$screenshot_count</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>🔍 Vulnerability Assessment</h2>
                <div class="stat-grid">
EOF

    # Add Nuclei findings if available
    if [ "$nuclei_count" -gt 0 ]; then
        cat >> "$reports_dir/report.html" <<EOF
                    <div class="stat-card critical">
                        <h3>Nuclei Findings (Critical)</h3>
                        <div class="value">$nuclei_critical</div>
                    </div>
                    <div class="stat-card warning">
                        <h3>Nuclei Findings (High)</h3>
                        <div class="value">$nuclei_high</div>
                    </div>
                    <div class="stat-card warning">
                        <h3>Nuclei Findings (Medium)</h3>
                        <div class="value">$nuclei_medium</div>
                    </div>
                    <div class="stat-card">
                        <h3>Total Nuclei Findings</h3>
                        <div class="value">$nuclei_count</div>
                    </div>
EOF
    fi

    cat >> "$reports_dir/report.html" <<EOF
                </div>
                <ul class="vuln-list">
EOF

    # Add vulnerability patterns
    for pattern in "${gf_patterns[@]}"; do
        local count="${vuln_counts[$pattern]}"
        cat >> "$reports_dir/report.html" <<EOF
                    <li>
                        <span class="vuln-name">$pattern</span>
                        <span class="vuln-count">$count findings</span>
                    </li>
EOF
    done

    cat >> "$reports_dir/report.html" <<EOF
                </ul>
            </div>

            <div class="section">
                <h2>☁️ API Endpoints & Cloud Patterns (Lightweight)</h2>
                <p style="color: #fbbf24; font-size: 0.9em; margin-bottom: 15px;">
                    ⚠️ Cloud values are PATTERN MATCHES from CT logs - not confirmed assets. 
                    For thorough cloud enumeration, run separate dedicated scan.
                </p>
                <div class="stat-grid">
                    <div class="stat-card">
                        <h3>API Endpoints</h3>
                        <div class="value">$api_count</div>
                    </div>
                    <div class="stat-card">
                        <h3>S3 Patterns</h3>
                        <div class="value">$cloud_s3</div>
                    </div>
                    <div class="stat-card">
                        <h3>Azure Patterns</h3>
                        <div class="value">$cloud_azure</div>
                    </div>
                    <div class="stat-card">
                        <h3>GCS Patterns</h3>
                        <div class="value">$cloud_gcs</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>🔧 Technology Stack Detection</h2>
                <div class="stat-grid">
                    <div class="stat-card">
                        <h3>Total Technologies</h3>
                        <div class="value">$tech_total</div>
                    </div>
                    <div class="stat-card">
                        <h3>HTTP/2 Support</h3>
                        <div class="value">$tech_http2</div>
                    </div>
                    <div class="stat-card">
                        <h3>WordPress Sites</h3>
                        <div class="value">$tech_wordpress</div>
                    </div>
                    <div class="stat-card">
                        <h3>Joomla Sites</h3>
                        <div class="value">$tech_joomla</div>
                    </div>
                    <div class="stat-card">
                        <h3>Drupal Sites</h3>
                        <div class="value">$tech_drupal</div>
                    </div>
                    <div class="stat-card">
                        <h3>ASP.NET</h3>
                        <div class="value">$tech_aspnet</div>
                    </div>
                    <div class="stat-card">
                        <h3>Laravel</h3>
                        <div class="value">$tech_laravel</div>
                    </div>
                    <div class="stat-card">
                        <h3>React</h3>
                        <div class="value">$tech_react</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>📁 Output Files</h2>
                <ul class="vuln-list">
                    <li><span class="vuln-name">Subdomains</span><span class="vuln-count">all_subdomains.txt</span></li>
                    <li><span class="vuln-name">Live Hosts</span><span class="vuln-count">alive_subdomains.txt</span></li>
                    <li><span class="vuln-name">Port Scan</span><span class="vuln-count">portscan/all_results.txt</span></li>
                    <li><span class="vuln-name">URLs</span><span class="vuln-count">all_urls.txt</span></li>
                    <li><span class="vuln-name">JavaScript</span><span class="vuln-count">javascript/</span></li>
                    <li><span class="vuln-name">Screenshots</span><span class="vuln-count">gowitness_screenshots/</span></li>
                    <li><span class="vuln-name">Technologies</span><span class="vuln-count">technology/summary.txt</span></li>
                    <li><span class="vuln-name">API Endpoints</span><span class="vuln-count">api_discovery/api_endpoints.txt</span></li>
                    <li><span class="vuln-name">Cloud Patterns (Lightweight)</span><span class="vuln-count">cloud_assets/README.txt</span></li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>Generated by Bug Bounty Recon Pipeline v5.0 (Enhanced)</p>
            <p>Created by: Shakibul (Shakibul_Cybersec)</p>
        </div>
    </div>
</body>
</html>
EOF

    echo -e "${GREEN}[✓]${NC} HTML report created: ${BLUE}$reports_dir/report.html${NC}"

    echo -e "${GREEN}[✓]${NC} Report generation completed"
    log_msg "Report generated with enhanced statistics"
}

show_domain_summary() {
    local output_dir=$1
    local domain=$2

    local subdomain_count alive_count port_count url_count screenshot_count js_count git_exposed_count
    subdomain_count=$(wc -l < "$output_dir/all_subdomains.txt" 2>/dev/null || echo 0)
    alive_count=$(wc -l < "$output_dir/alive_subdomains.txt" 2>/dev/null || echo 0)
    port_count=0
    [ -f "$output_dir/portscan/all_results.txt" ] && port_count=$(wc -l < "$output_dir/portscan/all_results.txt" 2>/dev/null || echo 0)
    url_count=$(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo 0)
    screenshot_count=$(find "$output_dir/gowitness_screenshots" -name "*.jpeg" 2>/dev/null | wc -l)
    js_count=$(wc -l < "$output_dir/javascript/js_urls.txt" 2>/dev/null || echo 0)
    git_exposed_count=$(wc -l < "$output_dir/git_exposed.txt" 2>/dev/null || echo 0)

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
    echo -e "• Parameters Discovered:    ${GREEN}$(wc -l < "$output_dir/parameters/unique_params.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "• Technologies Detected:    ${GREEN}$(wc -l < "$output_dir/technology/unique_technologies.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "• API Endpoints Found:      ${GREEN}$(wc -l < "$output_dir/api_discovery/api_endpoints.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "• Cloud Patterns (Light):   ${YELLOW}$(wc -l < "$output_dir/cloud_assets/ct_cloud_patterns.txt" 2>/dev/null || echo 0)${NC} ${CYAN}${NC}"
    
    # Nuclei findings
    if [ -f "$output_dir/nuclei_scan/nuclei_findings.txt" ]; then
        echo -e "• Nuclei Findings:          ${GREEN}$(wc -l < "$output_dir/nuclei_scan/nuclei_findings.txt" 2>/dev/null || echo 0)${NC}"
    fi

    local gf_patterns=("xss" "sqli" "lfi" "ssrf" "rce" "redirect" "ssti" "idor")
    echo -e "• Vulnerability Patterns:"
    for pattern in "${gf_patterns[@]}"; do
        local count
        count=$(wc -l < "$output_dir/vulnerability_scan/${pattern}.txt" 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            echo -e "   - ${pattern}: ${YELLOW}${count}${NC} potential findings"
        else
            echo -e "   - ${pattern}: ${GREEN}${count}${NC} potential findings"
        fi
    done

    echo -e "\n${GREEN}[+]${NC} Full Results: ${BLUE}$output_dir/${NC}"
    echo -e "${GREEN}[+]${NC} Log File:     ${BLUE}$GLOBAL_LOG${NC}"
    echo -e "${PURPLE}[+]${NC} Created by: Shakibul (Shakibul_Cybersec) - Enhanced v5.0${NC}"
}

configure_scan() {
    echo -e "${CYAN}[*]${NC} Configuration"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"
    echo -e "${PURPLE}[i]${NC} Script by: Shakibul (Shakibul_Cybersec) - Enhanced v5.0${NC}"
    echo -e "${YELLOW}────────────────────────────────────────────────────${NC}"

    # Nuclei scan option
    echo -e "${YELLOW}[?]${NC} Run Nuclei vulnerability scan? (Recommended but slower)"
    echo "    Nuclei is a powerful vulnerability scanner that checks for:"
    echo "    - CVEs and security misconfigurations"
    echo "    - Exposed panels and sensitive files"
    echo "    - Web vulnerabilities"
    echo "    Note: You can press Ctrl+C during the scan to skip it."
    read -p "Run Nuclei? (y/n): " nuclei_choice
    if [[ $nuclei_choice =~ ^[Yy]$ ]]; then
        RUN_NUCLEI=1
        echo -e "${GREEN}[+]${NC} Nuclei scan enabled"
    else
        RUN_NUCLEI=0
        echo -e "${YELLOW}[!]${NC} Nuclei scan disabled"
    fi

    # Scan mode
    echo -e "\n${YELLOW}Select scan mode:${NC}"
    echo "1. Root domain only (fast)"
    echo "2. Full reconnaissance (comprehensive)"
    read -p "Mode (1/2): " mode_choice

    case $mode_choice in
        1) scan_type="root" ;;
        2) scan_type="full" ;;
        *) scan_type="full" ;;
    esac

    exclude_list=""
    wordlist="$DEFAULT_WORDLIST"
    resolvers="$DEFAULT_RESOLVERS"
    fingerprint="$DEFAULT_FINGERPRINT"
    
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

check_resume_option() {
    # Check if there are any existing recon directories with resume state
    local resume_dirs
    resume_dirs=$(find . -maxdepth 2 -type d -name "$STATE_DIR" 2>/dev/null)

    if [ -n "$resume_dirs" ]; then
        echo -e "${YELLOW}[!]${NC} Found incomplete reconnaissance sessions:"
        echo ""

        local count=1
        declare -A dir_map

        while IFS= read -r state_dir; do
            local parent_dir
            parent_dir=$(dirname "$state_dir")
            local checkpoint_file="$state_dir/$CHECKPOINT_FILE"

            if [ -f "$checkpoint_file" ]; then
                # Safe defaults before source
                PHASE=0
                DOMAIN=""
                STATUS="UNKNOWN"
                LAST_UPDATE="N/A"
                # shellcheck source=/dev/null
                if source "$checkpoint_file" 2>/dev/null; then
                    echo -e "  ${count}. ${CYAN}$parent_dir${NC}"
                    echo -e "     Domain: ${YELLOW}$DOMAIN${NC}"
                    echo -e "     Last Phase: ${YELLOW}$PHASE${NC} | Status: ${YELLOW}$STATUS${NC}"
                    echo -e "     Last Update: ${YELLOW}$LAST_UPDATE${NC}"
                    echo ""
                    dir_map[$count]="$parent_dir"
                    count=$((count + 1))
                else
                    echo -e "  ${RED}[!]${NC} Skipping corrupted checkpoint: $parent_dir"
                fi
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

# ===============================================================
# MAIN PIPELINE ORCHESTRATOR
# ===============================================================

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
    log_msg "Pipeline START: domain=$domain output=$output_dir scan_type=$scan_type"

    # Create directory structure with new phase directories
    mkdir -p "$output_dir"/{reports,portscan,urls,javascript,vulnerability_scan,network,filtered-url-extention,technology,parameters,nuclei_scan,api_discovery,cloud_assets,param_fuzzing,cors_testing,waf_detection}

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

    # ---- Phase 0: Root domain check ----
    if [ "$scan_type" == "root" ]; then
        echo "$domain" > "$output_dir/all_subdomains.txt"
        echo -e "${YELLOW}[*]${NC} Running in root domain only mode"
        save_checkpoint "$output_dir" "0" "$domain" "COMPLETED"
    else
        # ---- Phase 1: Subdomain Enumeration ----
        if should_run_phase 1 $resume_phase "$resume_status"; then
            save_checkpoint "$output_dir" "1" "$domain" "RUNNING"
            phase_subdomain_enum "$domain" "$output_dir" "$wordlist" "$resolvers" || {
                echo -e "${YELLOW}[!]${NC} Phase 1 encountered errors — continuing pipeline"
            }
            mark_phase_complete "$output_dir" "1" "$domain"
        fi
    fi

    # ---- Phase 2: Port Scanning ----
    if should_run_phase 2 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "2" "$domain" "RUNNING"
        phase_port_scanning "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 2 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "2" "$domain"
    fi

    # ---- Phase 3: Web Discovery ----
    if should_run_phase 3 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "3" "$domain" "RUNNING"
        phase_web_discovery "$domain" "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 3 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "3" "$domain"
    fi

    # ---- Phase 4: URL Collection ----
    if should_run_phase 4 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "4" "$domain" "RUNNING"
        phase_url_collection "$domain" "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 4 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "4" "$domain"
    fi

    # ---- Phase 5: JavaScript Analysis ----
    if should_run_phase 5 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "5" "$domain" "RUNNING"
        phase_js_analysis "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 5 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "5" "$domain"
    fi

    # ---- Phase 5.5: API Discovery ----
    if should_run_phase 5.5 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "5.5" "$domain" "RUNNING"
        phase_api_discovery "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 5.5 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "5.5" "$domain"
    fi

    # ---- Phase 5.6: Cloud Discovery ----
    if should_run_phase 5.6 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "5.6" "$domain" "RUNNING"
        phase_cloud_discovery "$domain" "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 5.6 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "5.6" "$domain"
    fi

    # ---- Phase 5.7: WAF Detection ----
    if should_run_phase 5.7 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "5.7" "$domain" "RUNNING"
        phase_waf_detection "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 5.7 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "5.7" "$domain"
    fi

    # ---- Phase 6: Nuclei Scanning (NEW - with interactive skip) ----
    if should_run_phase 6 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "6" "$domain" "RUNNING"
        phase_nuclei_scanning "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 6 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "6" "$domain"
    fi

    # ---- Phase 7: Vulnerability Pattern Matching ----
    if should_run_phase 7 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "7" "$domain" "RUNNING"
        phase_vulnerability_scanning "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 7 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "7" "$domain"
    fi

    # ---- Phase 8: DNS Reconnaissance ----
    if should_run_phase 8 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "8" "$domain" "RUNNING"
        phase_dns_recon "$domain" "$output_dir" "$fingerprint" || {
            echo -e "${YELLOW}[!]${NC} Phase 8 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "8" "$domain"
    fi

    # ---- Phase 9: Screenshots ----
    if should_run_phase 9 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "9" "$domain" "RUNNING"
        phase_screenshots "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 9 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "9" "$domain"
    fi

    # ---- Phase 10: Technology Detection ----
    if should_run_phase 10 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "10" "$domain" "RUNNING"
        phase_technology_detection "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 10 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "10" "$domain"
    fi

    # ---- Phase 11: Parameter Discovery ----
    if should_run_phase 11 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "11" "$domain" "RUNNING"
        phase_parameter_discovery "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 11 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "11" "$domain"
    fi

    # ---- Phase 12: Enhanced Parameter Fuzzing ----
    if should_run_phase 12 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "12" "$domain" "RUNNING"
        phase_enhanced_parameter_fuzzing "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 12 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "12" "$domain"
    fi

    # ---- Phase 13: CORS Testing ----
    if should_run_phase 13 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "13" "$domain" "RUNNING"
        phase_cors_testing "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 13 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "13" "$domain"
    fi

    # ---- Phase 14: Quick Checks ----
    if should_run_phase 14 $resume_phase "$resume_status"; then
        save_checkpoint "$output_dir" "14" "$domain" "RUNNING"
        phase_quick_checks "$output_dir" || {
            echo -e "${YELLOW}[!]${NC} Phase 14 encountered errors — continuing pipeline"
        }
        mark_phase_complete "$output_dir" "14" "$domain"
    fi

    # Generate report
    echo -e "\n${CYAN}[*]${NC} Generating final report..."
    generate_report "$domain" "$output_dir" "$scan_type"

    # Mark scan as complete
    save_checkpoint "$output_dir" "15" "$domain" "COMPLETE"

    # Final summary
    show_domain_summary "$output_dir" "$domain"

    # Cleanup temporary files
    cleanup_temp_files "$output_dir"
    
    # Cleanup resume state
    cleanup_resume_state "$output_dir"
    log_msg "Pipeline COMPLETE: domain=$domain"
}

# ===============================================================
# MAIN EXECUTION
# ===============================================================

main() {
    # Parse --verbose flag
    local args=()
    for arg in "$@"; do
        if [[ "$arg" == "--verbose" ]] || [[ "$arg" == "-v" ]]; then
            VERBOSE=1
        else
            args+=("$arg")
        fi
    done

    show_banner

    if [ "$VERBOSE" -eq 1 ]; then
        echo -e "${CYAN}[*]${NC} Verbose mode enabled"
    fi

    check_tools

    prompt_tor_usage

    check_resources $MEMORY_THRESHOLD || true

    # Check for resume option
    resume_dir=""
    if check_resume_option; then
        if [ -f "$resume_dir/$STATE_DIR/$CHECKPOINT_FILE" ]; then
            PHASE=0
            DOMAIN=""
            STATUS="UNKNOWN"
            TIMESTAMP=0
            LAST_UPDATE="N/A"
            
            # Manually parse checkpoint file instead of sourcing (more secure)
            while IFS='=' read -r key value; do
                key=$(echo "$key" | xargs)
                value=$(echo "$value" | xargs)
                
                case "$key" in
                    PHASE)
                        if [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                            PHASE="$value"
                        fi
                        ;;
                    DOMAIN)
                        DOMAIN="$value"
                        ;;
                    TIMESTAMP)
                        if [[ "$value" =~ ^[0-9]+$ ]]; then
                            TIMESTAMP="$value"
                        fi
                        ;;
                    STATUS)
                        STATUS="$value"
                        ;;
                    LAST_UPDATE)
                        LAST_UPDATE="$value"
                        ;;
                esac
            done < "$resume_dir/$STATE_DIR/$CHECKPOINT_FILE"
            
            local domain_to_resume="$DOMAIN"

            GLOBAL_LOG="$resume_dir/recon.log"
            log_msg "=== RESUMED SESSION ==="

            echo -e "${CYAN}[*]${NC} Loading previous configuration..."

            scan_type="full"
            wordlist="$DEFAULT_WORDLIST"
            resolvers="$DEFAULT_RESOLVERS"
            fingerprint="$DEFAULT_FINGERPRINT"

            local domain_start=$SECONDS
            run_recon_pipeline "$domain_to_resume" "$resume_dir" "$scan_type" "$wordlist" "$resolvers" "$fingerprint" ""
            local domain_time=$((SECONDS - domain_start))

            echo -e "\n${GREEN}[✓]${NC} Resumed scan completed in ${domain_time}s"
            exit 0
        fi
    fi

    # Get target
    if [ -z "${args[0]:-}" ]; then
        read -p "Enter target domain or path to target file: " target_input
    else
        target_input="${args[0]}"
    fi

    if [ -z "$target_input" ]; then
        echo -e "${RED}[!] No target provided${NC}"
        exit 1
    fi

    # Configuration
    configure_scan

    # Create output directory
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local main_output_dir="recon_${timestamp}"
    mkdir -p "$main_output_dir"

    GLOBAL_LOG="$main_output_dir/recon.log"
    log_msg "=== NEW SESSION START ==="
    log_msg "Target: $target_input | Scan type: $scan_type | Nuclei: $RUN_NUCLEI"

    # Process targets
    local target_count=0
    local total_start=$SECONDS

    if [ -f "$target_input" ]; then
        echo -e "${GREEN}[+]${NC} Loading targets from file: $target_input"
        mapfile -t targets < "$target_input"
    else
        targets=("$target_input")
    fi

    for domain in "${targets[@]}"; do
        domain=$(echo "$domain" | sed 's/[[:space:]]*$//' | xargs)
        [ -z "$domain" ] && continue
        [[ "$domain" =~ ^#.* ]] && continue

        target_count=$((target_count + 1))

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
        sleep 2
    done

    local total_time=$((SECONDS - total_start))

    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} ALL RECONNAISSANCE COMPLETE ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "• Targets Processed:  ${target_count}"
    echo -e "• Total Time:         ${total_time} seconds"
    echo -e "• Output Directory:   ${main_output_dir}/"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Happy Hunting! 🚀 (Enhanced v5.0 by Shakibul)${NC}"
}

# Run main
main "$@"
