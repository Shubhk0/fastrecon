#!/bin/bash

# Bug Bounty Automation Script (Comprehensive with Auto-Wordlist Download)
#
# This script automates highly automatable tasks for web application bug bounties,
# focusing on comprehensive reconnaissance and initial vulnerability scanning.
#
# IMPORTANT:
# - This script is for AUTHORIZED bug bounty engagements ONLY.
# - It is NOT a replacement for manual testing, critical thinking, or deep analysis.
# - Always review the output manually.
# - Configure wordlist paths and adjust concurrency/rate limits carefully.
# - Wordlists will be automatically downloaded if not found at specified paths.
#
# Usage: ./bug_bounty_automation.sh -d <target_domain> [options]
# Example: ./bug_bounty_automation.sh -d example.com -p http://127.0.0.1:8080 -v

# --- Configuration & Defaults ---
TARGET_DOMAIN=""

# Default Wordlist Paths (Script will attempt to download these if not found)
WORDLIST_COMMON_PATHS="${HOME}/.bugbounty_wordlists/directory-list-2.3-small.txt"
WORDLIST_COMMON_FILES="${HOME}/.bugbounty_wordlists/raft-small-files.txt"

# Default Wordlist Download URLs
DOWNLOAD_URL_COMMON_PATHS="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt"
DOWNLOAD_URL_COMMON_FILES="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt"
WORDLISTS_DIR="${HOME}/.bugbounty_wordlists" # Directory where wordlists will be stored

PROXY_ADDRESS="" # Optional: http://127.0.0.1:8080 for Burp Suite
VERBOSE=0 # Set to 1 for verbose output during execution
SKIP_CLEANUP=0 # Set to 1 to keep intermediate files for debugging

# Concurrency & Rate Limiting (Adjust these carefully for stealth and target robustness)
SUBFINDER_THREADS=10
HTTPX_CONCURRENCY=50

GAU_CONCURRENCY=10 # Concurrency for gau
GAU_RESOLVE_TIMEOUT=5 # Timeout for each domain resolution for gau

WAYBACKURLS_CONCURRENCY=10 # Concurrency for waybackurls

KATANA_DEPTH=3
KATANA_THREADS=10
KATANA_RATE=50        # Requests per second for katana

FFUF_THREADS=20
FFUF_RATE=25          # Requests per second for ffuf
FFUF_MIN_DELAY_MS=200 # Minimum delay in milliseconds for ffuf
FFUF_MAX_DELAY_MS=1000 # Maximum delay in milliseconds for ffuf

NUCLEI_CONCURRENCY=20
NUCLEI_RATE=10        # Requests per second for nuclei
NUCLEI_MIN_DELAY_S=1  # Minimum delay in seconds for nuclei
NUCLEI_MAX_DELAY_S=3  # Maximum delay in seconds for nuclei

DALFOX_THREADS=10
DALFOX_MIN_DELAY_S=1  # Minimum delay in seconds for DalFox
DALFOX_MAX_DELAY_S=3  # Maximum delay in seconds for DalFox

# Output Directories & Files (will be created under REPORTS_DIR)
REPORTS_DIR="" # Will be set dynamically
LOG_FILE="" # Will be set dynamically

# --- Functions ---

usage() {
    echo "Usage: $0 -d <target_domain> [OPTIONS]"
    echo ""
    echo "  -d <domain>        Target domain (e.g., example.com)"
    echo "  -w <path>          Path to common paths wordlist (default: $WORDLIST_COMMON_PATHS). Auto-downloads if not found."
    echo "  -f <path>          Path to common files wordlist (default: $WORDLIST_COMMON_FILES). Auto-downloads if not found."
    echo "  -p <proxy_addr>    HTTP proxy address (e.g., http://127.0.0.1:8080)"
    echo "  -v                 Enable verbose output"
    echo "  -s                 Skip cleanup of temporary files at the end"
    echo "  -h                 Display this help message"
    echo ""
    echo "Concurrency & Rate Limit Options (adjust carefully for stealth):"
    echo "  --sub-threads <num>    Subfinder threads (default: $SUBFINDER_THREADS)"
    echo "  --httpx-concurrency <num> HTTPLX concurrency (default: $HTTPX_CONCURRENCY)"
    echo "  --gau-concurrency <num> GAU concurrency (default: $GAU_CONCURRENCY)"
    echo "  --wayback-concurrency <num> Waybackurls concurrency (default: $WAYBACKURLS_CONCURRENCY)"
    echo "  --katana-depth <num>   Katana crawl depth (default: $KATANA_DEPTH)"
    echo "  --katana-threads <num> Katana threads (default: $KATANA_THREADS)"
    echo "  --katana-rate <num>    Katana requests/sec (default: $KATANA_RATE)"
    echo "  --ffuf-threads <num>   FFUF threads (default: $FFUF_THREADS)"
    echo "  --ffuf-rate <num>      FFUF requests/sec (default: $FFUF_RATE)"
    echo "  --nuclei-concurrency <num> Nuclei concurrency (default: $NUCLEI_CONCURRENCY)"
    echo "  --nuclei-rate <num>    Nuclei requests/sec (default: $NUCLEI_RATE)"
    echo "  --dalfox-threads <num> DalFox threads (default: $DALFOX_THREADS)"
    echo ""
}

log_message() {
    local type="$1" # INFO, WARN, ERROR
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$type] $message" | tee -a "$LOG_FILE"
    if [ "$type" == "ERROR" ]; then
        exit 1
    fi
}

check_tool() {
    local tool_name="$1"
    command -v "$tool_name" >/dev/null 2>&1 || { log_message "ERROR" "$tool_name not found. Please install it."; }
    log_message "INFO" "$tool_name found."
}

ensure_wordlist_exists() {
    local file_path="$1"
    local download_url="$2"
    local friendly_name="$3"

    if [ -s "$file_path" ]; then
        log_message "INFO" "Wordlist '$friendly_name' found at '$file_path'."
        return 0
    fi

    log_message "WARN" "Wordlist '$friendly_name' not found at '$file_path'. Attempting to download from '$download_url'..."
    mkdir -p "$WORDLISTS_DIR" # Ensure wordlists directory exists

    if curl -sSL -o "$file_path" "$download_url"; then
        if [ -s "$file_path" ]; then
            log_message "INFO" "Successfully downloaded '$friendly_name' to '$file_path'."
            return 0
        else
            log_message "ERROR" "Downloaded '$friendly_name' is empty or corrupted. Please check your network or download it manually."
        fi
    else
        log_message "ERROR" "Failed to download '$friendly_name' from '$download_url'. Please check your network or download it manually."
    fi
    return 1 # Indicate failure
}


run_subdomain_enum() {
    local output_file="$1"
    log_message "INFO" "Starting Subdomain Enumeration for $TARGET_DOMAIN..."
    log_message "INFO" "  Using subfinder and assetfinder."

    # Run subfinder and assetfinder in parallel, pipe output to sort -u
    (
        subfinder_cmd="subfinder -d \"$TARGET_DOMAIN\" -t \"$SUBFINDER_THREADS\" -silent"
        [ "$VERBOSE" -eq 1 ] && log_message "INFO" "  Executing: $subfinder_cmd"
        eval "$subfinder_cmd"
        if [ $? -ne 0 ]; then log_message "WARN" "subfinder encountered issues."; fi

        assetfinder_cmd="assetfinder --subs-only \"$TARGET_DOMAIN\""
        [ "$VERBOSE" -eq 1 ] && log_message "INFO" "  Executing: $assetfinder_cmd"
        eval "$assetfinder_cmd"
        if [ $? -ne 0 ]; then log_message "WARN" "assetfinder encountered issues."; fi
    ) | sort -u > "$output_file"
    
    if [ ! -s "$output_file" ]; then # Check if the output file is empty
        log_message "WARN" "Subdomain enumeration completed, but no subdomains found or tool(s) failed."
        touch "$output_file" # Ensure file exists for next step
    fi
    log_message "INFO" "  Found $(wc -l < "$output_file") unique subdomains."
}

run_httpx_probe() {
    local input_file="$1"
    local output_file="$2"
    log_message "INFO" "Probing Live HTTP/S Hosts..."
    log_message "INFO" "  Using httpx with $HTTPX_CONCURRENCY concurrency."

    httpx_cmd="cat \"$input_file\" | httpx -silent -threads \"$HTTPX_CONCURRENCY\" -o \"$output_file\""
    [ "$PROXY_ADDRESS" != "" ] && httpx_cmd="$httpx_cmd -x \"$PROXY_ADDRESS\"" # httpx uses -x for proxy
    [ "$VERBOSE" -eq 1 ] && log_message "INFO" "  Executing: $httpx_cmd"
    eval "$httpx_cmd"

    if [ $? -ne 0 ]; then
        log_message "WARN" "httpx failed. Live host probing might be incomplete."
        touch "$output_file" # Ensure file exists
    fi
    log_message "INFO" "  Found $(wc -l < "$output_file") live hosts."
}

run_passive_url_collection() {
    local input_file="$1" # Live hosts file
    local gau_output_file="$2"
    local waybackurls_output_file="$3"
    log_message "INFO" "Collecting Passive URLs with gau and waybackurls..."

    # Run gau
    log_message "INFO" "  Running gau with $GAU_CONCURRENCY concurrency and $GAU_RESOLVE_TIMEOUTs timeout."
    gau_cmd="cat \"$input_file\" | gau --threads \"$GAU_CONCURRENCY\" --resolve-timeout \"$GAU_RESOLVE_TIMEOUT\" --blacklist png,jpg,gif,svg,css,ttf,woff,woff2,eot,json,xml,js,webp --json"
    [ "$PROXY_ADDRESS" != "" ] && gau_cmd="$gau_cmd --proxy \"$PROXY_ADDRESS\""
    [ "$VERBOSE" -eq 1 ] && log_message "INFO" "  Executing gau: $gau_cmd | jq -r '.url' > \"$gau_output_file\""
    eval "$gau_cmd" | jq -r '.url' > "$gau_output_file"
    if [ $? -ne 0 ]; then log_message "WARN" "gau failed or produced no output."; touch "$gau_output_file"; fi
    log_message "INFO" "  Collected $(wc -l < "$gau_output_file") URLs from gau."

    # Run waybackurls
    log_message "INFO" "  Running waybackurls with $WAYBACKURLS_CONCURRENCY concurrency."
    waybackurls_cmd="cat \"$input_file\" | waybackurls -c \"$WAYBACKURLS_CONCURRENCY\" | grep -vE '\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|rar|7z|gz|xml|json)$'"
    [ "$VERBOSE" -eq 1 ] && log_message "INFO" "  Executing waybackurls: $waybackurls_cmd > \"$waybackurls_output_file\""
    eval "$waybackurls_cmd" > "$waybackurls_output_file"
    if [ $? -ne 0 ]; then log_message "WARN" "waybackurls failed or produced no output."; touch "$waybackurls_output_file"; fi
    log_message "INFO" "  Collected $(wc -l < "$waybackurls_output_file") URLs from waybackurls."
}

run_katana_discovery() {
    local input_file="$1"
    local output_file="$2"
    log_message "INFO" "Performing Comprehensive URL Discovery with Katana..."
    log_message "INFO" "  Using $KATANA_THREADS threads, depth $KATANA_DEPTH, and rate limit $KATANA_RATE RPS."

    katana_cmd="cat \"$input_file\" | katana -d \"$KATANA_DEPTH\" -t \"$KATANA_THREADS\" -rl \"$KATANA_RATE\" -o \"$output_file\" -silent -jc" # -jc for JS crawling
    [ "$PROXY_ADDRESS" != "" ] && katana_cmd="$katana_cmd -proxy \"$PROXY_ADDRESS\""
    
    [ "$VERBOSE" -eq 1 ] && log_message "INFO" "  Executing: $katana_cmd"
    eval "$katana_cmd"

    if [ $? -ne 0 ]; then
        log_message "WARN" "katana failed. URL discovery might be incomplete."
        touch "$output_file"
    fi
    log_message "INFO" "  Found $(wc -l < "$output_file") URLs with Katana."
}

run_ffuf_bruteforce() {
    local input_file="$1"
    local output_dir="$2"

    # Ensure wordlists exist before running ffuf
    ensure_wordlist_exists "$WORDLIST_COMMON_PATHS" "$DOWNLOAD_URL_COMMON_PATHS" "Common Paths" || return 1
    ensure_wordlist_exists "$WORDLIST_COMMON_FILES" "$DOWNLOAD_URL_COMMON_FILES" "Common Files" || return 1

    log_message "INFO" "Performing Directory and File Brute-Forcing with ffuf..."
    log_message "INFO" "  Using $FFUF_THREADS threads, rate limit of $FFUF_RATE RPS, and random delays ($FFUF_MIN_DELAY_MS-$FFUF_MAX_DELAY_MS ms)."

    while IFS= read -r host; do
        if [ -z "$host" ]; then continue; fi # Skip empty lines
        log_message "INFO" "    Fuzzing $host..."
        local sanitized_host=$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g') # Sanitize hostname for filename
        local current_ffuf_delay_ms=$(shuf -i "$FFUF_MIN_DELAY_MS"-"$FFUF_MAX_DELAY_MS" -n 1)

        # Fuzzing common paths
        local ffuf_paths_cmd="ffuf -u \"$host/FUZZ\" -w \"$WORDLIST_COMMON_PATHS\" -of csv -o \"$output_dir/${sanitized_host}_paths.csv\" \
         -t \"$FFUF_THREADS\" -rate \"$FFUF_RATE\" -c -sf -sa -delay \"$current_ffuf_delay_ms\""
        [ "$PROXY_ADDRESS" != "" ] && ffuf_paths_cmd="$ffuf_paths_cmd -x \"$PROXY_ADDRESS\""
        [ "$VERBOSE" -eq 1 ] && log_message "INFO" "      Executing (paths): $ffuf_paths_cmd"
        eval "$ffuf_paths_cmd" & # Run in background

        # Fuzzing common files
        local ffuf_files_cmd="ffuf -u \"$host/FUZZ\" -w \"$WORDLIST_COMMON_FILES\" -of csv -o \"$output_dir/${sanitized_host}_files.csv\" \
         -t \"$FFUF_THREADS\" -rate \"$FFUF_RATE\" -c -sf -sa -delay \"$current_ffuf_delay_ms\""
        [ "$PROXY_ADDRESS" != "" ] && ffuf_files_cmd="$ffuf_files_cmd -x \"$PROXY_ADDRESS\""
        [ "$VERBOSE" -eq 1 ] && log_message "INFO" "      Executing (files): $ffuf_files_cmd"
        eval "$ffuf_files_cmd" & # Run in background
    done < "$input_file"
    wait # Wait for all background ffuf processes to complete

    if [ $? -ne 0 ]; then
        log_message "WARN" "ffuf encountered issues. Directory brute-forcing might be incomplete."
    fi
    log_message "INFO" "    FFUF results saved to $output_dir"
}

run_nuclei_scan() {
    local input_file="$1"
    local output_file="$2"
    log_message "INFO" "Performing Initial Vulnerability Scan with Nuclei..."
    local random_delay_s=$(shuf -i "$NUCLEI_MIN_DELAY_S"-"$NUCLEI_MAX_DELAY_S" -n 1)
    log_message "INFO" "  Using $NUCLEI_CONCURRENCY concurrency, rate limit of $NUCLEI_RATE RPS, and random delay of $random_delay_s seconds per host."

    nuclei_cmd="nuclei -l \"$input_file\" -t vulnerabilities/ -t exposures/ -t misconfiguration/ -t default-logins/ -t cve/ \
                -c \"$NUCLEI_CONCURRENCY\" -rl \"$NUCLEI_RATE\" -d \"$random_delay_s\" -silent -json -o \"$output_file\""
    [ "$PROXY_ADDRESS" != "" ] && nuclei_cmd="$nuclei_cmd -proxy \"$PROXY_ADDRESS\""
    
    [ "$VERBOSE" -eq 1 ] && log_message "INFO" "  Executing: $nuclei_cmd"
    eval "$nuclei_cmd"

    if [ $? -ne 0 ]; then
        log_message "WARN" "Nuclei scan encountered issues. Results might be incomplete."
    fi
    log_message "INFO" "  Nuclei scan results saved to $output_file"
}

run_dalfox_scan() {
    local input_file="$1"
    local output_file="$2"
    log_message "INFO" "Performing XSS Scan with DalFox..."
    local random_delay_s=$(shuf -i "$DALFOX_MIN_DELAY_S"-"$DALFOX_MAX_DELAY_S" -n 1)
    log_message "INFO" "  Using $DALFOX_THREADS threads and a random delay of $random_delay_s seconds."

    # DalFox can consume URLs with parameters directly, filter for potential XSS candidates
    # Using 'grep -E' for basic parameter detection to focus dalfox on relevant URLs
    dalfox_cmd="cat \"$input_file\" | grep -E '\?|=' | dalfox url --skip-grepping -w \"$DALFOX_THREADS\" -d \"$random_delay_s\" -o \"$output_file\""
    [ "$PROXY_ADDRESS" != "" ] && dalfox_cmd="$dalfox_cmd -x \"$PROXY_ADDRESS\"" # DalFox uses -x for proxy
    
    [ "$VERBOSE" -eq 1 ] && log_message "INFO" "  Executing: $dalfox_cmd"
    eval "$dalfox_cmd"

    if [ $? -ne 0 ]; then
        log_message "WARN" "DalFox scan encountered issues. Results might be incomplete."
    fi
    log_message "INFO" "  DalFox XSS scan results saved to $output_file"
}

run_subzy_scan() {
    local input_file="$1"
    local output_file="$2"
    log_message "INFO" "Performing Subdomain Takeover Check with Subzy..."
    subzy_cmd="subzy -targets \"$input_file\" --hide_fails --output \"$output_file\""
    
    [ "$VERBOSE" -eq 1 ] && log_message "INFO" "  Executing: $subzy_cmd"
    eval "$subzy_cmd"

    if [ $? -ne 0 ]; then
        log_message "WARN" "Subzy scan encountered issues. Results might be incomplete."
    fi
    log_message "INFO" "  Subzy results saved to $output_file"
}


# --- Main Script Logic ---

# Parse command-line arguments
PARSED_ARGUMENTS=$(getopt -o d:w:f:p:vsh --longoptions sub-threads:,httpx-concurrency:,gau-concurrency:,wayback-concurrency:,katana-depth:,katana-threads:,katana-rate:,ffuf-threads:,ffuf-rate:,nuclei-concurrency:,nuclei-rate:,dalfox-threads: -- "$@")
VALID_ARGUMENTS=$?
if [ "$VALID_ARGUMENTS" -ne 0 ]; then
  usage
  exit 1
fi

eval set -- "$PARSED_ARGUMENTS"
while :
do
  case "$1" in
    -d) TARGET_DOMAIN="$2"       ; shift 2 ;;
    -w) WORDLIST_COMMON_PATHS="$2" ; shift 2 ;;
    -f) WORDLIST_COMMON_FILES="$2" ; shift 2 ;;
    -p) PROXY_ADDRESS="$2"     ; shift 2 ;;
    -v) VERBOSE=1              ; shift ;;
    -s) SKIP_CLEANUP=1         ; shift ;;
    -h) usage                  ; exit 0 ;;
    --sub-threads) SUBFINDER_THREADS="$2" ; shift 2 ;;
    --httpx-concurrency) HTTPX_CONCURRENCY="$2" ; shift 2 ;;
    --gau-concurrency) GAU_CONCURRENCY="$2" ; shift 2 ;;
    --wayback-concurrency) WAYBACKURLS_CONCURRENCY="$2" ; shift 2 ;;
    --katana-depth) KATANA_DEPTH="$2" ; shift 2 ;;
    --katana-threads) KATANA_THREADS="$2" ; shift 2 ;;
    --katana-rate) KATANA_RATE="$2" ; shift 2 ;;
    --ffuf-threads) FFUF_THREADS="$2" ; shift 2 ;;
    --ffuf-rate) FFUF_RATE="$2" ; shift 2 ;;
    --nuclei-concurrency) NUCLEI_CONCURRENCY="$2" ; shift 2 ;;
    --nuclei-rate) NUCLEI_RATE="$2" ; shift 2 ;;
    --dalfox-threads) DALFOX_THREADS="$2" ; shift 2 ;;
    --) shift; break ;;
    *) log_message "ERROR" "Unexpected option: $1" ; usage ; exit 1 ;;
  esac
done

if [ -z "$TARGET_DOMAIN" ]; then
    log_message "ERROR" "Target domain (-d) is required."
fi

REPORTS_DIR="bugbounty_reports_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$REPORTS_DIR/script_log.txt"

mkdir -p "$REPORTS_DIR"
mkdir -p "$REPORTS_DIR/ffuf_raw_results" # Separate dir for ffuf raw outputs

echo "--- Starting Bug Bounty Automation for $TARGET_DOMAIN ---" | tee -a "$LOG_FILE"
echo "Results will be stored in: $REPORTS_DIR" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# --- Tool Checks ---
log_message "INFO" "Checking for required tools..."
check_tool "subfinder"
check_tool "assetfinder"
check_tool "httpx"
check_tool "gau"
check_tool "waybackurls"
check_tool "katana"
check_tool "ffuf"
check_tool "nuclei"
check_tool "dalfox"
check_tool "subzy"
check_tool "sort" # For deduplication
check_tool "jq" # For parsing gau JSON output
check_tool "grep" # Used in DalFox and waybackurls filtering
check_tool "curl" # Used for wordlist download

# --- Define Output Files ---
SUBDOMAINS_DEDUP_FILE="$REPORTS_DIR/subdomains_deduplicated.txt"
LIVE_HOSTS_DEDUP_FILE="$REPORTS_DIR/live_hosts_deduplicated.txt"
GAU_URLS_RAW_FILE="$REPORTS_DIR/gau_urls_raw.txt"
WAYBACKURLS_URLS_RAW_FILE="$REPORTS_DIR/waybackurls_urls_raw.txt" # New output file for waybackurls
KATANA_URLS_RAW_FILE="$REPORTS_DIR/katana_urls_raw.txt"
ALL_URLS_DEDUP_FILE="$REPORTS_DIR/all_urls_deduplicated.txt"
FFUF_RESULTS_DIR="$REPORTS_DIR/ffuf_raw_results"
NUCLEI_RESULTS_FILE="$REPORTS_DIR/nuclei_results.json"
DALFOX_RESULTS_FILE="$REPORTS_DIR/dalfox_results.txt"
SUBZY_RESULTS_FILE="$REPORTS_DIR/subzy_results.txt"


# --- Execution Steps ---

# Step 1: Subdomain Enumeration (Combines subfinder and assetfinder)
run_subdomain_enum "$SUBDOMAINS_DEDUP_FILE" # Output directly to deduplicated file
if [ ! -s "$SUBDOMAINS_DEDUP_FILE" ]; then
    log_message "WARN" "No subdomains found after enumeration, aborting."
    exit 0
fi
echo ""

# Step 2: Live Host Probe
run_httpx_probe "$SUBDOMAINS_DEDUP_FILE" "$LIVE_HOSTS_DEDUP_FILE" # Output directly to deduplicated file
if [ ! -s "$LIVE_HOSTS_DEDUP_FILE" ]; then
    log_message "WARN" "No live hosts found after probing, aborting."
    exit 0
fi
echo ""

# Step 3: Subdomain Takeover Check
run_subzy_scan "$SUBDOMAINS_DEDUP_FILE" "$SUBZY_RESULTS_FILE"
echo ""

# Step 4: Passive URL Collection (gau and waybackurls)
run_passive_url_collection "$LIVE_HOSTS_DEDUP_FILE" "$GAU_URLS_RAW_FILE" "$WAYBACKURLS_URLS_RAW_FILE"
echo ""

# Step 5: Active URL Discovery (Katana)
run_katana_discovery "$LIVE_HOSTS_DEDUP_FILE" "$KATANA_URLS_RAW_FILE"
echo ""

# Step 6: Consolidate & Deduplicate All URLs for further scanning
log_message "INFO" "Consolidating and deduplicating all collected URLs (Gau + Waybackurls + Katana + Live Hosts)..."
cat "$GAU_URLS_RAW_FILE" "$WAYBACKURLS_URLS_RAW_FILE" "$KATANA_URLS_RAW_FILE" "$LIVE_HOSTS_DEDUP_FILE" | sort -u > "$ALL_URLS_DEDUP_FILE"
log_message "INFO" "  Total $(wc -l < "$ALL_URLS_DEDUP_FILE") unique URLs for further scanning."
echo ""

# Step 7: Directory and File Brute-Forcing
run_ffuf_bruteforce "$LIVE_HOSTS_DEDUP_FILE" "$FFUF_RESULTS_DIR"
echo ""

# Step 8: Initial Vulnerability Scan with Nuclei
# Nuclei can take a list of URLs, so we feed it all unique URLs found
run_nuclei_scan "$ALL_URLS_DEDUP_FILE" "$NUCLEI_RESULTS_FILE"
echo ""

# Step 9: XSS Scan with DalFox
# DalFox can take a list of URLs, filtering for params helps focus
run_dalfox_scan "$ALL_URLS_DEDUP_FILE" "$DALFOX_RESULTS_FILE"
echo ""

# --- Cleanup ---
if [ "$SKIP_CLEANUP" -eq 0 ]; then
    log_message "INFO" "Cleaning up raw intermediate files..."
    rm -f "$GAU_URLS_RAW_FILE" "$WAYBACKURLS_URLS_RAW_FILE" "$KATANA_URLS_RAW_FILE"
    log_message "INFO" "Cleanup complete."
fi

echo "--- Automation Script Finished ---" | tee -a "$LOG_FILE"
echo "Review the detailed results in: $REPORTS_DIR" | tee -a "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
echo "Remember, this is just the beginning. Manual testing and deeper analysis are essential!" | tee -a "$LOG_FILE"
