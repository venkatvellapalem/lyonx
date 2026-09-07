#!/bin/bash
# ============================================================
# HUNTER v2 - Automated Bug Bounty Pipeline
# Usage: ./hunter.sh <domain> [options]
# Options:
#   --recon-only      Stop after recon phase
#   --skip-fuzz       Skip content fuzzing
#   --skip-nuclei     Skip nuclei scan
#   --threads N       Concurrency (default: 25)
#   --depth N         Crawl depth (default: 3)
#   --aggressive      Enable aggressive scanning (more payloads)
# ============================================================
set -uo pipefail

# ============================================================
# CONFIG
# ============================================================
DOMAIN="${1:?Usage: ./hunter.sh <domain> [--recon-only] [--threads N]}"
shift
THREADS=25
CRAWL_DEPTH=3
AGGRESSIVE=false
RECON_ONLY=false
SKIP_FUZZ=false
SKIP_NUCLEI=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --recon-only) RECON_ONLY=true; shift ;;
        --skip-fuzz) SKIP_FUZZ=true; shift ;;
        --skip-nuclei) SKIP_NUCLEI=true; shift ;;
        --threads) THREADS="$2"; shift 2 ;;
        --depth) CRAWL_DEPTH="$2"; shift 2 ;;
        --aggressive) AGGRESSIVE=true; shift ;;
        *) shift ;;
    esac
done

BASE_DIR="$HOME/Hunter/results/$DOMAIN"
DATE=$(date +%Y%m%d_%H%M%S)
REPORT="$BASE_DIR/report.md"
MANUAL="$BASE_DIR/manual_targets.md"
LOG="$BASE_DIR/hunter.log"

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; NC='\033[0m'

banner()  { echo -e "\n${B}[$(date +%H:%M:%S)]${NC} ${G}▶ $1${NC}" | tee -a "$LOG"; }
info()    { echo -e "  ${C}[*]${NC} $1" | tee -a "$LOG"; }
success() { echo -e "  ${G}[+]${NC} $1" | tee -a "$LOG"; }
warn()    { echo -e "  ${Y}[!]${NC} $1" | tee -a "$LOG"; }
err()     { echo -e "  ${R}[-]${NC} $1" | tee -a "$LOG"; }
count()   { wc -l < "$1" 2>/dev/null || echo 0; }

# ============================================================
# SETUP
# ============================================================
mkdir -p "$BASE_DIR"/{subdomains,ports,urls,js,params,fuzz,vulns,secrets,screenshots,headers,cors,redirects,takeover}
cd "$BASE_DIR"

echo -e "${B}"
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo "  ║              HUNTER v2 — Bug Bounty Pipeline             ║"
echo "  ║  Target: $DOMAIN"
echo "  ║  Threads: $THREADS | Depth: $CRAWL_DEPTH | Aggressive: $AGGRESSIVE"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "Started: $(date)" > "$LOG"

# ============================================================
# PHASE 1: SUBDOMAIN ENUMERATION
# ============================================================
banner "PHASE 1: Subdomain Enumeration"

info "Running subfinder (passive)..."
subfinder -d "$DOMAIN" -silent -all -o subdomains/subfinder.txt 2>/dev/null
success "subfinder: $(count subdomains/subfinder.txt) subs"

info "Running assetfinder..."
assetfinder --subs-only "$DOMAIN" 2>/dev/null | sort -u > subdomains/assetfinder.txt
success "assetfinder: $(count subdomains/assetfinder.txt) subs"

info "Extracting subs from gau/wayback..."
gau --subs "$DOMAIN" 2>/dev/null | unfurl -u domains 2>/dev/null | sort -u > subdomains/gau.txt
success "gau: $(count subdomains/gau.txt) subs"

info "Running asnmap for related ranges..."
echo "$DOMAIN" | asnmap -silent 2>/dev/null | sort -u > subdomains/asnmap.txt
success "asnmap: $(count subdomains/asnmap.txt) ranges"

# Merge
cat subdomains/subfinder.txt subdomains/assetfinder.txt subdomains/gau.txt 2>/dev/null | sort -u > subdomains/all.txt
success "Unique subdomains: $(count subdomains/all.txt)"

# Permutation
info "Generating permutations with alterx..."
alterx -list subdomains/all.txt -silent 2>/dev/null | sort -u > subdomains/permutations.txt
cat subdomains/all.txt subdomains/permutations.txt 2>/dev/null | sort -u > subdomains/final.txt
success "With permutations: $(count subdomains/final.txt) subs"

# ============================================================
# PHASE 2: DNS RESOLUTION
# ============================================================
banner "PHASE 2: DNS Resolution"

info "Resolving subdomains..."
dnsx -l subdomains/final.txt -silent -a -aaaa -cname -resp -o subdomains/resolved_full.txt 2>/dev/null
dnsx -l subdomains/final.txt -silent -o subdomains/resolved.txt 2>/dev/null
grep -oP '\d+\.\d+\.\d+\.\d+' subdomains/resolved_full.txt 2>/dev/null | sort -u > subdomains/resolved_ips.txt
success "Resolved: $(count subdomains/resolved.txt) subs | IPs: $(count subdomains/resolved_ips.txt)"

# Check for subdomain takeover
info "Checking for subdomain takeover candidates..."
grep -iE 'amazonaws|herokuapp|github\.io|azure|shopify|fastly|pantheon|ghost\.io|surge\.sh|bitbucket|wordpress\.com|tumblr' subdomains/resolved_full.txt 2>/dev/null > takeover/candidates.txt
if [ -s takeover/candidates.txt ]; then
    warn "Possible takeover candidates: $(count takeover/candidates.txt)"
fi

# ============================================================
# PHASE 3: HTTP PROBING
# ============================================================
banner "PHASE 3: HTTP Probing"

info "Probing live HTTP hosts..."
httpx -l subdomains/resolved.txt -silent \
  -status-code -title -tech-detect -cdn -ip -cname -server \
  -follow-redirects -threads "$THREADS" \
  -o urls/alive_full.txt 2>/dev/null

# Extract clean URLs
grep -oP 'https?://[^\s\[\]]+' urls/alive_full.txt 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | sort -u > urls/live_urls.txt
success "Live HTTP hosts: $(count urls/live_urls.txt)"

# Extract tech stack
info "Extracting technology fingerprints..."
grep -oP '\[.*?\]' urls/alive_full.txt 2>/dev/null | sort | uniq -c | sort -rn | head -20 > urls/tech_stack.txt
success "Technologies detected: $(count urls/tech_stack.txt)"

# ============================================================
# PHASE 4: PORT SCANNING
# ============================================================
banner "PHASE 4: Port Scanning"

info "Scanning top 1000 ports with naabu..."
naabu -list subdomains/resolved.txt -silent -top-ports 1000 -exclude-cdn \
  -o ports/naabu_all.txt -c "$THREADS" 2>/dev/null || true

# Extract interesting ports
info "Identifying interesting services..."
grep -E ':21|:22|:23|:25|:53|:110|:143|:443|:445|:993|:995|:1433|:1521|:3306|:3389|:5432|:5900|:6379|:8080|:8443|:9090|:27017' ports/naabu_all.txt 2>/dev/null > ports/interesting.txt
success "Open ports: $(count ports/naabu_all.txt) | Interesting: $(count ports/interesting.txt)"

# ============================================================
# PHASE 5: URL & ENDPOINT DISCOVERY
# ============================================================
banner "PHASE 5: URL & Endpoint Discovery"

info "Fetching from gau (AlienVault, OTX, Wayback, CommonCrawl)..."
gau "$DOMAIN" --threads 10 2>/dev/null | sort -u > urls/gau_urls.txt
success "gau: $(count urls/gau_urls.txt) URLs"

info "Fetching from waybackurls..."
waybackurls "$DOMAIN" 2>/dev/null | sort -u > urls/wayback_urls.txt
success "waybackurls: $(count urls/wayback_urls.txt) URLs"

info "Crawling with katana (depth=$CRAWL_DEPTH)..."
katana -u "$DOMAIN" -d "$CRAWL_DEPTH" -silent -jc -xhr -headless 2>/dev/null | sort -u > urls/katana_urls.txt
success "katana: $(count urls/katana_urls.txt) URLs"

# Merge all
cat urls/gau_urls.txt urls/wayback_urls.txt urls/katana_urls.txt 2>/dev/null | sort -u > urls/all_urls.txt
success "Total unique URLs: $(count urls/all_urls.txt)"

# ============================================================
# PHASE 6: PARAMETER & ENDPOINT EXTRACTION
# ============================================================
banner "PHASE 6: Parameter & Endpoint Extraction"

# URLs with parameters
grep '?' urls/all_urls.txt 2>/dev/null | sort -u > urls/with_params.txt
success "URLs with parameters: $(count urls/with_params.txt)"

# Extract unique parameters
info "Extracting unique parameters..."
grep -oP '[?&]([a-zA-Z0-9_-]+)=' urls/with_params.txt 2>/dev/null | sed 's/[?&]//;s/=//' | sort | uniq -c | sort -rn > params/param_frequency.txt
success "Unique parameters: $(count params/param_frequency.txt)"

# Extract endpoints (paths without extensions)
info "Extracting API endpoints..."
grep -oP 'https?://[^/]+(/[^?\s#]+)' urls/all_urls.txt 2>/dev/null | grep -oP '/[^?\s#]+$' | sort -u > urls/endpoints.txt
success "Unique endpoints: $(count urls/endpoints.txt)"

# Find potential API endpoints
grep -iE '/api/|/v[0-9]|/rest/|/graphql|/swagger|/docs|/json|/xml' urls/all_urls.txt 2>/dev/null | sort -u > urls/api_endpoints.txt
success "API endpoints: $(count urls/api_endpoints.txt)"

# ============================================================
# PHASE 7: JAVASCRIPT ANALYSIS
# ============================================================
banner "PHASE 7: JavaScript Analysis"

info "Extracting JS file URLs..."
grep -iE '\.js(\?|$)' urls/all_urls.txt 2>/dev/null | sort -u > js/js_urls.txt
grep -iE '\.js(\?|$)' urls/alive_full.txt 2>/dev/null | grep -oP 'https?://[^\s\[\]]+' | sed 's/\x1b\[[0-9;]*m//g' | sort -u >> js/js_urls.txt
sort -u js/js_urls.txt -o js/js_urls.txt
success "JS files found: $(count js/js_urls.txt)"

info "Downloading and analyzing JS files for secrets/endpoints..."
> js/js_secrets.txt
> js/js_endpoints.txt
> js/js_api_keys.txt

# Process up to 100 JS files
head -100 js/js_urls.txt | while read -r jsurl; do
    content=$(curl -sL --max-time 10 "$jsurl" 2>/dev/null)
    if [ -n "$content" ]; then
        # Extract API endpoints from JS
        echo "$content" | grep -oP '["'"'"'](/api/[^"'"'"'\s]+)["'"'"']' >> js/js_endpoints.txt 2>/dev/null
        echo "$content" | grep -oP '["'"'"'](https?://[^"'"'"'\s]+)["'"'"']' >> js/js_endpoints.txt 2>/dev/null
        # Extract secrets/tokens
        echo "$content" | grep -oiE '(api[_-]?key|apikey|secret|token|password|auth|bearer|aws[_-]?access|private[_-]?key)["\x27]?\s*[:=]\s*["\x27][A-Za-z0-9+/=_-]{8,}["\x27]' >> js/js_secrets.txt 2>/dev/null
        # Extract URLs with parameters
        echo "$content" | grep -oP 'https?://[^\s"'"'"']+\?[^\s"'"'"']+' >> js/js_endpoints.txt 2>/dev/null
    fi
done

sort -u js/js_endpoints.txt -o js/js_endpoints.txt 2>/dev/null
sort -u js/js_secrets.txt -o js/js_secrets.txt 2>/dev/null
success "JS endpoints: $(count js/js_endpoints.txt) | JS secrets: $(count js/js_secrets.txt)"

# ============================================================
# PHASE 8: HEADER ANALYSIS
# ============================================================
banner "PHASE 8: Security Header Analysis"

info "Checking security headers on live hosts..."
> headers/missing_headers.txt

head -50 urls/live_urls.txt | while read -r url; do
    resp=$(curl -sI -L --max-time 10 "$url" 2>/dev/null)
    if [ -n "$resp" ]; then
        host=$(echo "$url" | unfurl -u domains 2>/dev/null)
        # Check for missing security headers
        for header in "Strict-Transport-Security" "X-Content-Type-Options" "X-Frame-Options" "Content-Security-Policy" "X-XSS-Protection" "Referrer-Policy" "Permissions-Policy"; do
            if ! echo "$resp" | grep -qi "$header"; then
                echo "$host | Missing: $header" >> headers/missing_headers.txt
            fi
        done
        # Check for info disclosure headers
        echo "$resp" | grep -iE '^server:|^x-powered-by:|^x-aspnet|^x-generator' >> headers/info_disclosure.txt 2>/dev/null
    fi
done

success "Missing headers issues: $(count headers/missing_headers.txt)"
success "Info disclosure headers: $(count headers/info_disclosure.txt)"

# ============================================================
# PHASE 9: CORS MISCONFIGURATION CHECK
# ============================================================
banner "PHASE 9: CORS Misconfiguration Check"

info "Testing CORS on live hosts..."
> cors/vulnerable.txt

head -30 urls/live_urls.txt | while read -r url; do
    # Test with evil origin
    cors_resp=$(curl -sI -H "Origin: https://evil.com" --max-time 5 "$url" 2>/dev/null)
    if echo "$cors_resp" | grep -qi "Access-Control-Allow-Origin: https://evil.com"; then
        echo "$url | Reflects arbitrary origin" >> cors/vulnerable.txt
    elif echo "$cors_resp" | grep -qi "Access-Control-Allow-Origin: \*"; then
        echo "$url | Wildcard origin (*)" >> cors/vulnerable.txt
    fi
    # Test null origin
    cors_null=$(curl -sI -H "Origin: null" --max-time 5 "$url" 2>/dev/null)
    if echo "$cors_null" | grep -qi "Access-Control-Allow-Origin: null"; then
        echo "$url | Accepts null origin" >> cors/vulnerable.txt
    fi
done

success "CORS issues: $(count cors/vulnerable.txt)"

# ============================================================
# PHASE 10: OPEN REDIRECT DETECTION
# ============================================================
banner "PHASE 10: Open Redirect Detection"

info "Testing URLs with redirect parameters..."
> redirects/vulnerable.txt

REDIRECT_PARAMS="url|redirect|next|return|goto|target|dest|destination|redir|redirect_uri|return_url|return_to|continue|forward|feed|img|image|file|path|page|link|href|to"

grep -iE "[?&]($REDIRECT_PARAMS)=" urls/with_params.txt 2>/dev/null | head -100 | while read -r url; do
    # Test with external URL
    test_url=$(echo "$url" | sed -E "s/([?&]($REDIRECT_PARAMS)=)[^&]*/\1https:\/\/evil.com/gi")
    resp=$(curl -sI -L --max-time 5 "$test_url" 2>/dev/null)
    if echo "$resp" | grep -qi "Location:.*evil.com"; then
        echo "$url | OPEN REDIRECT" >> redirects/vulnerable.txt
    fi
done

success "Open redirects: $(count redirects/vulnerable.txt)"

# ============================================================
# PHASE 11: CONTENT DISCOVERY (FUZZING)
# ============================================================
if [ "$SKIP_FUZZ" = false ]; then
    banner "PHASE 11: Content Discovery (Fuzzing)"

    WL="$HOME/Hunter/wordlists/discovery/common.txt"
    if [ -f "$WL" ]; then
        info "Fuzzing $(count urls/live_urls.txt) live URLs for hidden paths..."
        FUZZ_COUNT=0
        while read -r url; do
            FUZZ_COUNT=$((FUZZ_COUNT + 1))
            safe_name=$(echo "$url" | sed 's|https\?://||;s|/|_|g;s|[^a-zA-Z0-9._-]|_|g')
            ffuf -u "$url/FUZZ" -w "$WL" -t "$THREADS" -mc 200,301,302,403,401 \
              -fs 0 -o "fuzz/${safe_name}.json" -of json -s 2>/dev/null || true
            # Progress every 20 URLs
            [ $((FUZZ_COUNT % 20)) -eq 0 ] && info "  Fuzzed $FUZZ_COUNT URLs..."
        done < urls/live_urls.txt

        # Merge all fuzz results
        find fuzz/ -name "*.json" -exec cat {} \; 2>/dev/null | jq -r '.results[]?.url // empty' 2>/dev/null | sort -u > fuzz/all_found.txt
        success "Fuzzing complete. Found: $(count fuzz/all_found.txt) paths"
    else
        warn "Wordlist not found, skipping fuzzing"
    fi
else
    info "Skipping fuzzing (--skip-fuzz)"
fi

# ============================================================
# PHASE 12: SQLMAP ON PARAMETERS
# ============================================================
banner "PHASE 12: SQL Injection Testing (sqlmap)"

info "Running sqlmap on URLs with parameters..."
SQLMAP_DIR="$BASE_DIR/vulns/sqlmap"
mkdir -p "$SQLMAP_DIR"

# Extract URLs with injectable-looking parameters
grep -iE '[?&](id|user|uid|pid|cat|item|page|search|query|name|email|order|sort|type|ref|lang|file|path|include|cmd|exec|run|ping|host|ip|url|uri|callback|jsonp)=' urls/with_params.txt 2>/dev/null | head -100 > params/injectable_candidates.txt
success "SQLi candidate URLs: $(count params/injectable_candidates.txt)"

SQLMAP_COUNT=0
while read -r url; do
    SQLMAP_COUNT=$((SQLMAP_COUNT + 1))
    safe_name=$(echo "$url" | md5sum | cut -c1-12)
    sqlmap -u "$url" --batch --level=2 --risk=2 --threads=4 \
      --output-dir="$SQLMAP_DIR/$safe_name" \
      --forms --crawl=0 --smart --timeout=10 --retries=1 \
      2>/dev/null >> "$SQLMAP_DIR/sqlmap.log" || true
    [ $((SQLMAP_COUNT % 10)) -eq 0 ] && info "  sqlmap tested $SQLMAP_COUNT URLs..."
done < params/injectable_candidates.txt

# Extract findings
grep -r "is vulnerable" "$SQLMAP_DIR/" 2>/dev/null > vulns/sqlmap_findings.txt || true
success "SQLi testing complete. Findings: $(count vulns/sqlmap_findings.txt)"

# ============================================================
# PHASE 13: DALFOX XSS SCANNING
# ============================================================
banner "PHASE 13: XSS Scanning (dalfox)"

info "Running dalfox on URLs with parameters..."
DALFOX_DIR="$BASE_DIR/vulns/dalfox"
mkdir -p "$DALFOX_DIR"

# Run dalfox on all URLs with params
cat urls/with_params.txt | dalfox pipe --silence --skip-bav -o "$DALFOX_DIR/dalfox_results.txt" 2>/dev/null || true

success "XSS scanning complete. Findings: $(count $DALFOX_DIR/dalfox_results.txt)"

# ============================================================
# PHASE 14: NUCLEI VULNERABILITY SCAN
# ============================================================
if [ "$SKIP_NUCLEI" = false ]; then
    banner "PHASE 14: Nuclei Vulnerability Scan"

    info "Running nuclei on all live URLs..."
    nuclei -l urls/alive_full.txt -severity critical,high,medium,low \
      -o vulns/nuclei_results.txt -c "$THREADS" \
      -silent -stats 2>/dev/null || true

    # Separate by severity
    grep -i 'critical' vulns/nuclei_results.txt 2>/dev/null > vulns/critical.txt || true
    grep -i 'high' vulns/nuclei_results.txt 2>/dev/null > vulns/high.txt || true
    grep -i 'medium' vulns/nuclei_results.txt 2>/dev/null > vulns/medium.txt || true
    grep -i 'low' vulns/nuclei_results.txt 2>/dev/null > vulns/low.txt || true

    success "Nuclei findings: Critical=$(count vulns/critical.txt) High=$(count vulns/high.txt) Medium=$(count vulns/medium.txt) Low=$(count vulns/low.txt)"

    # Also scan JS files
    info "Running nuclei on JS files..."
    nuclei -l js/js_urls.txt -tags js -o vulns/nuclei_js.txt -c "$THREADS" -silent 2>/dev/null || true
    success "JS nuclei findings: $(count vulns/nuclei_js.txt)"
else
    info "Skipping nuclei (--skip-nuclei)"
fi

# ============================================================
# PHASE 15: SECRET SCANNING
# ============================================================
banner "PHASE 15: Secret & Credential Scanning"

info "Running gitleaks..."
gitleaks detect --source="$DOMAIN" --no-git -r secrets/gitleaks.json 2>/dev/null || true

info "Scanning URLs for exposed files..."
grep -iE '\.env|\.git|\.svn|\.htaccess|\.htpasswd|wp-config|config\.php|settings\.py|database\.yml|secrets\.yml|credentials|\.aws|\.ssh|\.docker' urls/all_urls.txt 2>/dev/null > secrets/exposed_files.txt
success "Exposed files: $(count secrets/exposed_files.txt)"

info "Scanning for .git exposure..."
head -50 urls/live_urls.txt | while read -r url; do
    resp=$(curl -sI "${url}/.git/config" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -q "200 OK"; then
        echo "$url/.git/config | EXPOSED GIT" >> secrets/git_exposed.txt
    fi
done
success "Git exposures: $(count secrets/git_exposed.txt 2>/dev/null || echo 0)"

# ============================================================
# PHASE 16: PRIORITIZED MANUAL TARGETS
# ============================================================
banner "PHASE 16: Generating Manual Testing Targets"

cat > "$MANUAL" << MANUALHEADER
# Manual Testing Targets for $DOMAIN
Generated: $(date)
Pipeline: Hunter v2

## Priority Legend
🔴 HIGH = Likely exploitable, test first
🟡 MEDIUM = Interesting, test after high priority
🟢 LOW = Informational, test when bored

---

## 🔴 HIGH PRIORITY — Test These First

### Nuclei Critical/High Findings
$(cat vulns/critical.txt 2>/dev/null || echo "None found")
$(cat vulns/high.txt 2>/dev/null || echo "")

### SQLi Candidates (sqlmap found these injectable)
$(cat vulns/sqlmap_findings.txt 2>/dev/null || echo "None found")

### XSS Candidates (dalfox found these)
$(cat vulns/dalfox_results.txt 2>/dev/null || echo "None found")

### CORS Misconfigurations
$(cat cors/vulnerable.txt 2>/dev/null || echo "None found")

### Open Redirects
$(cat redirects/vulnerable.txt 2>/dev/null || echo "None found")

### Exposed Git Repos
$(cat secrets/git_exposed.txt 2>/dev/null || echo "None found")

### Exposed Sensitive Files
$(head -20 secrets/exposed_files.txt 2>/dev/null || echo "None found")

### Subdomain Takeover Candidates
$(cat takeover/candidates.txt 2>/dev/null || echo "None found")

---

## 🟡 MEDIUM PRIORITY — Test Next

### Interesting Open Ports
$(cat ports/interesting.txt 2>/dev/null || echo "None found")

### API Endpoints (test for auth bypass, IDOR)
$(head -30 urls/api_endpoints.txt 2>/dev/null || echo "None found")

### URLs with Parameters (test for IDOR, injection)
$(head -50 urls/with_params.txt 2>/dev/null || echo "None found")

### JS Extracted Endpoints (test for hidden APIs)
$(head -30 js/js_endpoints.txt 2>/dev/null || echo "None found")

### Missing Security Headers
$(sort -u headers/missing_headers.txt 2>/dev/null | head -20 || echo "None found")

---

## 🟢 LOW PRIORITY — Test When Bored

### All Live URLs (manual crawling)
$(head -100 urls/live_urls.txt 2>/dev/null || echo "None found")

### Technology Stack
$(cat urls/tech_stack.txt 2>/dev/null || echo "None found")

### Fuzzing Results (hidden paths)
$(head -30 fuzz/all_found.txt 2>/dev/null || echo "None found")

---

## 📊 Statistics
| Metric | Count |
|--------|-------|
| Subdomains found | $(count subdomains/all.txt) |
| Live HTTP hosts | $(count urls/live_urls.txt) |
| Open ports | $(count ports/naabu_all.txt 2>/dev/null || echo 0) |
| URLs discovered | $(count urls/all_urls.txt) |
| URLs with params | $(count urls/with_params.txt) |
| JS files | $(count js/js_urls.txt) |
| API endpoints | $(count urls/api_endpoints.txt) |
| Nuclei findings | $(count vulns/nuclei_results.txt 2>/dev/null || echo 0) |
| SQLi findings | $(count vulns/sqlmap_findings.txt 2>/dev/null || echo 0) |
| XSS findings | $(count vulns/dalfox_results.txt 2>/dev/null || echo 0) |
| CORS issues | $(count cors/vulnerable.txt 2>/dev/null || echo 0) |
| Open redirects | $(count redirects/vulnerable.txt 2>/dev/null || echo 0) |
| Exposed files | $(count secrets/exposed_files.txt 2>/dev/null || echo 0) |
MANUALHEADER

success "Manual targets saved to: $MANUAL"

# ============================================================
# PHASE 17: FINAL REPORT
# ============================================================
banner "PHASE 17: Final Report"

cat > "$REPORT" << REPORTHEADER
# Bug Bounty Report: $DOMAIN
**Date:** $(date)
**Pipeline:** Hunter v2 Automated Pipeline

---

## Executive Summary
| Category | Count | Status |
|----------|-------|--------|
| Subdomains | $(count subdomains/all.txt) | $([ $(count subdomains/all.txt) -gt 0 ] && echo "✅" || echo "⚠️") |
| Live Hosts | $(count urls/live_urls.txt) | $([ $(count urls/live_urls.txt) -gt 0 ] && echo "✅" || echo "⚠️") |
| Open Ports | $(count ports/naabu_all.txt 2>/dev/null || echo 0) | ✅ |
| URLs Found | $(count urls/all_urls.txt) | ✅ |
| Parameters | $(count urls/with_params.txt) | ✅ |
| JS Files | $(count js/js_urls.txt) | ✅ |
| **Critical Vulns** | $(count vulns/critical.txt 2>/dev/null || echo 0) | $([ $(count vulns/critical.txt 2>/dev/null || echo 0) -gt 0 ] && echo "🔴" || echo "✅") |
| **High Vulns** | $(count vulns/high.txt 2>/dev/null || echo 0) | $([ $(count vulns/high.txt 2>/dev/null || echo 0) -gt 0 ] && echo "🟠" || echo "✅") |
| Medium Vulns | $(count vulns/medium.txt 2>/dev/null || echo 0) | ✅ |
| Low Vulns | $(count vulns/low.txt 2>/dev/null || echo 0) | ✅ |

## Critical Findings
$(cat vulns/critical.txt 2>/dev/null || echo "None found")

## High Findings
$(cat vulns/high.txt 2>/dev/null || echo "None found")

## SQLi Findings
$(cat vulns/sqlmap_findings.txt 2>/dev/null || echo "None found")

## XSS Findings
$(cat vulns/dalfox_results.txt 2>/dev/null || echo "None found")

## CORS Issues
$(cat cors/vulnerable.txt 2>/dev/null || echo "None found")

## Open Redirects
$(cat redirects/vulnerable.txt 2>/dev/null || echo "None found")

## Exposed Files
$(head -20 secrets/exposed_files.txt 2>/dev/null || echo "None found")

## Subdomain Takeover Candidates
$(cat takeover/candidates.txt 2>/dev/null || echo "None found")

## Information Disclosure
$(sort -u headers/info_disclosure.txt 2>/dev/null || echo "None found")

---

## Files & Data
| File | Description |
|------|-------------|
| \`manual_targets.md\` | **PRIORITY LIST — Start here** |
| \`subdomains/final.txt\` | All subdomains |
| \`urls/alive_full.txt\` | Live hosts with tech detection |
| \`urls/all_urls.txt\` | All discovered URLs |
| \`urls/with_params.txt\` | URLs with parameters |
| \`urls/api_endpoints.txt\` | API endpoints |
| \`js/js_urls.txt\` | JavaScript files |
| \`js/js_endpoints.txt\` | JS extracted endpoints |
| \`ports/naabu_all.txt\` | Open ports |
| \`vulns/nuclei_results.txt\` | Nuclei findings |
| \`vulns/sqlmap_findings.txt\` | SQLi findings |
| \`vulns/dalfox_results.txt\` | XSS findings |
| \`cors/vulnerable.txt\` | CORS issues |
| \`redirects/vulnerable.txt\` | Open redirects |
| \`secrets/\` | Exposed files and secrets |
| \`fuzz/\` | Content discovery results |
REPORTHEADER

success "Report saved to: $REPORT"

# ============================================================
# DONE
# ============================================================
echo ""
echo -e "${B}  ╔═══════════════════════════════════════════════════════════╗"
echo -e "  ║              HUNTER v2 — SCAN COMPLETE                   ║"
echo -e "  ╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
success "Results: $BASE_DIR/"
success "Report:  $REPORT"
success "Manual targets: $MANUAL"
echo ""
info "Next steps:"
echo "  1. Read manual_targets.md — it's prioritized for you"
echo "  2. Start with 🔴 HIGH PRIORITY items"
echo "  3. Test API endpoints for IDOR/auth bypass"
echo "  4. Check parameter manipulation on URLs with params"
echo "  5. Look at JS files for hidden API endpoints"
echo ""
info "Scan completed at $(date)"
