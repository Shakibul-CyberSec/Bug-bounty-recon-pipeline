#!/bin/bash

# Default values
input_file=""
output_dir="js_file"
max_parallel=30
timeout=15
connect_timeout=5
retry_count=2

# Parse command-line options
while getopts ":u:o:p:t:r:" opt; do
  case $opt in
    u)
      input_file="$OPTARG"
      ;;
    o)
      output_dir="$OPTARG"
      ;;
    p)
      max_parallel="$OPTARG"
      ;;
    t)
      timeout="$OPTARG"
      ;;
    r)
      retry_count="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Check if input file was provided
if [[ -z "$input_file" ]]; then
  echo "Usage: $0 -u <input_file> [-o <output_dir>] [-p <parallel_jobs>] [-t <timeout>] [-r <retry_count>]"
  echo "Example: $0 -u js_urls.txt -o js_file -p 30 -t 15 -r 2"
  exit 1
fi

if [[ ! -f "$input_file" ]]; then
  echo "[-] File not found: $input_file"
  exit 1
fi

# Create output directories
mkdir -p "$output_dir"
mkdir -p "$output_dir/success"
mkdir -p "$output_dir/failed"
mkdir -p "$output_dir/archive"

# Log files
log_file="$output_dir/download.log"
failed_file="$output_dir/failed_urls.txt"
stats_file="$output_dir/stats.txt"

# Clear log files
> "$log_file"
> "$failed_file"

echo "[*] Starting parallel JavaScript downloader"
echo "    Input file: $input_file"
echo "    Output dir: $output_dir"
echo "    Parallel jobs: $max_parallel"
echo "    Timeout: ${timeout}s"
echo "    Retry count: ${retry_count}"
echo "    Log file: $log_file"
echo -e "──────────────────────────────────────────────\n"

# Count total URLs
total_urls=$(wc -l < "$input_file" 2>/dev/null | tr -d '[:space:]' || echo 0)
echo "[*] Found $total_urls URLs to process"
start_time=$(date +%s)

# Function to generate safe filename
generate_filename() {
    local url="$1"
    
    # Remove protocol and basic sanitization
    local filename
    filename=$(echo "$url" | sed '
        s|^https\?://||;
        s|^www\.||;
        s|[?&=]|_|g;
        s|/|_|g;
        s|:|_|g;
        s|+|_|g;
        s|%|_|g;
    ')
    
    # Remove any trailing underscores
    filename="${filename%_}"
    
    # Add .js extension if not present
    [[ "$filename" != *.js ]] && filename="${filename}.js"
    
    # If still empty, use hash
    if [[ -z "$filename" ]] || [[ "$filename" == ".js" ]]; then
        filename="url_$(echo -n "$url" | sha256sum | cut -c1-8).js"
    fi
    
    echo "$filename"
}

# Function to check if content is JavaScript
is_javascript() {
  local file="$1"
  if [[ ! -f "$file" ]] || [[ ! -s "$file" ]]; then
    return 1
  fi
  
  # Check using file command (if available)
  if command -v file &> /dev/null; then
    file_output=$(file -b "$file" 2>/dev/null)
    if echo "$file_output" | grep -qi -E "(javascript|text|json|ecmascript|ascii)"; then
      return 0
    fi
  fi
  
  # Check common JS patterns
  if head -10 "$file" 2>/dev/null | grep -q -E "(function|var |const |let |=>|//|/\*|\.js|jQuery|\"use strict\")"; then
    return 0
  fi
  
  # Check for JS file extension
  if [[ "$file" == *.js ]]; then
    return 0
  fi
  
  # Check for JSON
  if head -2 "$file" 2>/dev/null | grep -q '^{'; then
    return 0
  fi
  
  return 1
}

# Function to download from Wayback Machine
download_from_archive() {
  local url="$1"
  local output_file="$2"
  
  # Try direct archive access first
  local archive_urls=(
    "https://web.archive.org/web/2/$url"
    "https://web.archive.org/web/0/$url"
    "https://web.archive.org/web/2024/$url"
    "https://web.archive.org/web/2023/$url"
  )
  
  for archive_url in "${archive_urls[@]}"; do
    if curl -s -L -m 8 --connect-timeout 3 \
      -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      -o "$output_file.tmp" \
      "$archive_url" 2>/dev/null && [[ -s "$output_file.tmp" ]]; then
      
      if is_javascript "$output_file.tmp"; then
        mv "$output_file.tmp" "$output_file"
        return 0
      fi
      rm -f "$output_file.tmp"
    fi
  done
  
  return 1
}

# Function to process a single URL
process_url() {
    local url="$1"
    local output_dir="$2"
    local timeout="$3"
    local connect_timeout="$4"
    local retry_count="$5"
    
    # Clean URL
    url=$(echo "$url" | sed 's/[[:space:]]*$//')
    
    # Skip if URL is empty
    [[ -z "$url" ]] && return 1
    
    # Generate filename
    local filename
    filename=$(generate_filename "$url")
    local live_file="$output_dir/success/$filename"
    local archive_file="$output_dir/archive/$filename"
    
    # Skip if already exists and has content
    if [[ -f "$live_file" ]] && [[ -s "$live_file" ]]; then
        echo "Skipping (already exists): $url" >> "$log_file"
        return 0
    fi
    
    local downloaded=0
    local source=""
    
    # Try live download first
    for ((i=0; i<retry_count; i++)); do
        if curl -f -s -L -m "$timeout" --connect-timeout "$connect_timeout" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            -H "Accept: */*" \
            -H "Accept-Language: en-US,en;q=0.9" \
            -o "$live_file.tmp" \
            "$url" 2>/dev/null; then
            
            if [[ -s "$live_file.tmp" ]] && is_javascript "$live_file.tmp"; then
                # FIX: Properly handle file size calculation
                local file_size
                file_size=$(wc -c < "$live_file.tmp" 2>/dev/null)
                file_size=${file_size//[^0-9]/}  # Remove non-numeric characters
                file_size=${file_size:-0}  # Default to 0 if empty
                
                # Convert to integer and check
                if [[ "$file_size" =~ ^[0-9]+$ ]] && (( file_size > 10 )); then
                    mv "$live_file.tmp" "$live_file"
                    echo "SUCCESS_LIVE: $url ($file_size bytes)" >> "$log_file"
                    downloaded=1
                    source="live"
                    break
                fi
            fi
            rm -f "$live_file.tmp"
        fi
        
        # Small delay before retry
        sleep 0.05
    done
    
    # If live download failed, try archive
    if [[ $downloaded -eq 0 ]]; then
        if download_from_archive "$url" "$archive_file"; then
            # FIX: Properly handle file size calculation for archive files
            local file_size
            file_size=$(wc -c < "$archive_file" 2>/dev/null)
            file_size=${file_size//[^0-9]/}  # Remove non-numeric characters
            file_size=${file_size:-0}  # Default to 0 if empty
            
            echo "SUCCESS_ARCHIVE: $url ($file_size bytes)" >> "$log_file"
            downloaded=1
            source="archive"
            
            # Copy to success directory
            cp "$archive_file" "$live_file" 2>/dev/null || true
        fi
    fi
    
    # If both failed
    if [[ $downloaded -eq 0 ]]; then
        echo "FAILED: $url" >> "$log_file"
        echo "$url" >> "$failed_file"
        return 1
    fi
    
    return 0
}

# Clean input file
echo "[*] Cleaning input file..."
clean_input="/tmp/cleaned_urls_$$.txt"
sort -u "$input_file" | grep -v '^[[:space:]]*$' | head -500 > "$clean_input"
unique_urls=$(wc -l < "$clean_input" 2>/dev/null | tr -d '[:space:]')
unique_urls=${unique_urls:-0}  # Default to 0 if empty
echo "[*] Found $unique_urls unique URLs"

# Process URLs in parallel
echo "[*] Using GNU parallel for parallel processing"

# FIX: Create a wrapper script for parallel execution to avoid quoting issues
parallel_wrapper="/tmp/parallel_wrapper_$$.sh"
cat > "$parallel_wrapper" << 'EOF'
#!/bin/bash
# Wrapper script for parallel execution
url="$1"
output_dir="$2"
timeout="$3"
connect_timeout="$4"
retry_count="$5"

# Source the functions if needed, but we'll just call the main script
exec "$0" --process-url "$url" "$output_dir" "$timeout" "$connect_timeout" "$retry_count"
EOF

chmod +x "$parallel_wrapper"

# Export functions for parallel
export -f process_url is_javascript download_from_archive generate_filename
export output_dir timeout connect_timeout retry_count log_file failed_file

# FIX: Use a safer approach for parallel execution
# Create a function that will be called by parallel
parallel_process() {
    local url="$1"
    # Escape quotes and special characters in URL
    url=$(printf "%q" "$url")
    bash -c "process_url $url \"$output_dir\" \"$timeout\" \"$connect_timeout\" \"$retry_count\""
}
export -f parallel_process

# Process with parallel using a safer method
if command -v parallel &> /dev/null; then
    # Use parallel if available
    cat "$clean_input" | parallel -j "$max_parallel" \
        --progress \
        --bar \
        --eta \
        --timeout "$((timeout * retry_count + 10))" \
        --delay 0.05 \
        parallel_process '{}'
else
    # Fallback to sequential processing if parallel not available
    echo "[!] GNU parallel not found, falling back to sequential processing"
    while IFS= read -r url || [[ -n "$url" ]]; do
        process_url "$url" "$output_dir" "$timeout" "$connect_timeout" "$retry_count"
    done < "$clean_input"
fi

# Clean up temp files
rm -f "$clean_input" "$parallel_wrapper" 2>/dev/null

# Calculate statistics
end_time=$(date +%s)
duration=$((end_time - start_time))

# Count results - FIX: Handle empty log files properly
success_live=0
success_archive=0
failed_count=0
skipped_count=0

if [[ -f "$log_file" ]]; then
    success_live=$(grep -c "^SUCCESS_LIVE:" "$log_file" 2>/dev/null || echo 0)
    success_archive=$(grep -c "^SUCCESS_ARCHIVE:" "$log_file" 2>/dev/null || echo 0)
    failed_count=$(grep -c "^FAILED:" "$log_file" 2>/dev/null || echo 0)
    skipped_count=$(grep -c "^Skipping" "$log_file" 2>/dev/null || echo 0)
fi

# FIX: Ensure all counts are integers
success_live=${success_live:-0}
success_archive=${success_archive:-0}
failed_count=${failed_count:-0}
skipped_count=${skipped_count:-0}

total_success=$((success_live + success_archive))

# Calculate success rate - FIX: Handle division by zero
if [[ $unique_urls -gt 0 ]] && [[ $unique_urls =~ ^[0-9]+$ ]]; then
    success_rate=$(awk -v success="$total_success" -v total="$unique_urls" 'BEGIN {printf "%.2f", (success * 100 / total)}' 2>/dev/null || echo "0.00")
else
    success_rate="0.00"
fi

# Save stats
cat > "$stats_file" << EOF
JavaScript Download Statistics
──────────────────────────────
Total unique URLs: $unique_urls
Success (Live): $success_live
Success (Archive): $success_archive
Total Success: $total_success
Failed: $failed_count
Skipped (duplicates): $skipped_count
Success Rate: ${success_rate}%
Time: ${duration} seconds
Parallel Jobs: $max_parallel
EOF

# Final summary
echo -e "\n──────────────────────────────────────────────"
echo "[*] DOWNLOAD COMPLETED"
echo "    Total unique URLs: $unique_urls"
echo "    Successfully downloaded: $total_success"
if [[ $skipped_count -gt 0 ]]; then
    echo "    Skipped (duplicates): $skipped_count"
fi
echo "      ├─ From live: $success_live"
echo "      └─ From archive: $success_archive"
echo "    Failed: $failed_count"
echo "    Success rate: ${success_rate}%"
echo "    Time elapsed: ${duration}s"
echo "    Output: $output_dir/success/"
if [[ $success_archive -gt 0 ]]; then
    echo "    Archived files: $output_dir/archive/"
fi
echo "    Failed URLs: $failed_file"
echo -e "──────────────────────────────────────────────\n"

# Post-processing
echo "[*] Running post-processing..."

# Remove empty files
find "$output_dir/success" -name "*.js" -type f -size 0 -delete 2>/dev/null || true
find "$output_dir/archive" -name "*.js" -type f -size 0 -delete 2>/dev/null || true

# Remove .tmp files
find "$output_dir" -name "*.tmp" -type f -delete 2>/dev/null || true

# Count final files
final_count_success=$(find "$output_dir/success" -name "*.js" -type f 2>/dev/null | wc -l | tr -d '[:space:]')
final_count_archive=$(find "$output_dir/archive" -name "*.js" -type f 2>/dev/null | wc -l | tr -d '[:space:]')

final_count_success=${final_count_success:-0}
final_count_archive=${final_count_archive:-0}

echo "[*] Final count:"
echo "    Success directory: $final_count_success JavaScript files"
if [[ $final_count_archive -gt 0 ]]; then
    echo "    Archive directory: $final_count_archive JavaScript files"
fi

# Display sample files (just names, no permissions)
echo -e "\n[*] Sample downloaded files:"
find "$output_dir/success" -name "*.js" -type f 2>/dev/null | head -5 | while read -r file; do
    basename "$file"
done

# Summary
if [[ $success_archive -gt 0 ]]; then
    echo -e "\n[*] Note: $success_archive files were retrieved from archive.org"
    echo "    (Files that couldn't be downloaded live)"
fi