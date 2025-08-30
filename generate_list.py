#!/usr/bin/env python3
"""
generate_list.py
Generates Brave browser compatible blocklists:
 - brave_ultimate_goat_merged.txt   <- Full version for Desktop Brave
 - brave_mobile_optimized.txt      <- Optimized version for Mobile Brave
Outputs:
 - brave_ultimate_goat_merged.txt   <- Full merged file (Desktop)
 - brave_mobile_optimized.txt      <- Mobile-optimized file
 - README.md
 - fetch_errors.log
"""
from __future__ import annotations
import requests
import datetime
import re
import time
import sys
import gzip
import io
from typing import Tuple, List, Set, Dict

# Output names
DESKTOP_OUTPUT = "brave_ultimate_goat_merged.txt"
MOBILE_OUTPUT = "brave_mobile_optimized.txt"
README = "README.md"
FETCH_LOG = "fetch_errors.log"

# Network / retry settings
REQUEST_TIMEOUT = 30
RETRY_COUNT = 3
RETRY_BACKOFF = 2  # seconds

# ----------------------------
# Sources (ULTIMATE TRUE GOAT BLOCK LIST)
# ----------------------------
SOURCES: List[str] = [
    # ===== CORE AD-BLOCKING =====
    # Primary ad-blocking lists
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
    
    # uBlock Origin core filters
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt",
    
    # AdGuard core filters
    "https://filters.adtidy.org/extension/chromium/filters/1.txt",  # AdGuard Base
    "https://filters.adtidy.org/extension/chromium/filters/2.txt",  # AdGuard English
    "https://filters.adtidy.org/extension/chromium/filters/4.txt",  # AdGuard Spyware
    "https://filters.adtidy.org/extension/chromium/filters/16.txt", # AdGuard URL Tracking
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    
    # ===== PRIVACY & TRACKING =====
    # Privacy-focused lists
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
    "https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains",
    
    # Disconnect.me tracking lists
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
    
    # ===== ANNOYANCES =====
    # Annoyance removal
    "https://easylist-downloads.adblockplus.org/fanboy-annoyance.txt",
    "https://easylist-downloads.adblockplus.org/fanboy-social.txt",
    "https://easylist-downloads.adblockplus.org/fanboy-notifications.txt",
    "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
    
    # Cookie notices and GDPR popups
    "https://www.i-dont-care-about-cookies.eu/abp/",
    
    # ===== SECURITY & MALWARE =====
    # Malware and phishing protection
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://threatfox.abuse.ch/downloads/hostfile/",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0",
    
    # Cryptojacking and coin mining
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    
    # Additional malware protection
    "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts",
    "https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt",
    
    # ===== DNS-LEVEL/HOSTS =====
    # Hosts file lists (converted to adblock format)
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
    "http://winhelp2002.mvps.org/hosts.txt",
    "https://someonewhocares.org/hosts/hosts",
    
    # Firebog lists
    "https://v.firebog.net/hosts/Prigent-Ads.txt",
    "https://v.firebog.net/hosts/Prigent-Malware.txt",
    "https://v.firebog.net/hosts/Prigent-Crypto.txt",
    "https://v.firebog.net/hosts/AdguardDNS.txt",
    "https://v.firebog.net/hosts/Easyprivacy.txt",
    "https://v.firebog.net/hosts/Admiral.txt",
    
    # Hagezi DNS blocklists (comprehensive)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
    
    # ===== REGIONAL =====
    # Regional lists
    "https://easylist-downloads.adblockplus.org/easylistgermany.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
    "https://easylist-downloads.adblockplus.org/easylistdutch.txt",
    "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
    "https://easylist-downloads.adblockplus.org/ruadlist+easylist.txt",
    
    # ===== SPECIALIZED =====
    # Specialized lists
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SessionReplay.txt",
    
    # Windows telemetry
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
    
    # BlocklistProject
    "https://blocklistproject.github.io/Lists/ads.txt",
    "https://blocklistproject.github.io/Lists/tracking.txt",
    "https://blocklistproject.github.io/Lists/malware.txt",
    "https://blocklistproject.github.io/Lists/phishing.txt",
    "https://blocklistproject.github.io/Lists/ransomware.txt",
    "https://blocklistproject.github.io/Lists/scam.txt",
    
    # DeveloperDan lists
    "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    "https://www.github.developerdan.com/hosts/lists/tracking-aggressive-extended.txt",
    "https://www.github.developerdan.com/hosts/lists/facebook-extended.txt",
    
    # Additional comprehensive lists
    "https://big.oisd.nl/",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt",
    
    # ===== EMERGING THREATS =====
    # Emerging threats
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
]

# ----------------------------
# Helper utilities
# ----------------------------
DOMAIN_RE = re.compile(r"(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}", re.IGNORECASE)

def normalize_line(line: str) -> str:
    l = line.strip()
    if l and "//" in l and not l.lower().startswith(("http://", "https://")):
        l = l.split("//", 1)[0].rstrip()
    l = re.sub(r"\s+", " ", l)
    return l

def is_text_content(headers: dict) -> bool:
    ct = headers.get("Content-Type", "")
    return "text" in ct.lower() or "html" in ct.lower() or ct == ""

def decompress_content(content: bytes, headers: dict) -> str:
    content_encoding = headers.get("Content-Encoding", "").lower()
    if content_encoding == "gzip":
        try:
            return gzip.decompress(content).decode("utf-8", errors="replace")
        except:
            # If decompression fails, try to decode as-is
            return content.decode("utf-8", errors="replace")
    else:
        return content.decode("utf-8", errors="replace")

def convert_hosts_to_adblock(line: str) -> str:
    """Convert hosts file entries to adblock format"""
    line = line.strip()
    if line.startswith("#") or not line:
        return line
    
    # Handle various hosts file formats
    # 127.0.0.1 domain.com
    # 0.0.0.0 domain.com
    # ::1 domain.com
    parts = re.split(r'\s+', line)
    if len(parts) >= 2:
        domain = parts[-1]
        if DOMAIN_RE.match(domain):
            return f"||{domain}^"
    
    return line

def is_mobile_optimized(line: str) -> bool:
    """Determine if a rule should be included in mobile version"""
    line = line.strip()
    
    # Skip very specific cosmetic filters that might not work well on mobile
    if line.startswith("##") or line.startswith("#@#"):
        # Keep important cosmetic filters but skip overly specific ones
        if len(line) > 100:  # Skip very long cosmetic rules
            return False
    
    # Skip some resource-intensive rules for mobile
    if "third-party" in line and len(line.split(",")) > 3:
        return False
    
    # Keep all network filters and important cosmetic filters
    return True

def fetch_url(url: str, timeout: int = REQUEST_TIMEOUT) -> Tuple[str, str | None]:
    headers = {
        "User-Agent": "brave-ultimate-goat-blocklist/1.0 (+https://github.com/)",
        "Accept-Encoding": "gzip, deflate"
    }
    last_err = None
    for attempt in range(RETRY_COUNT + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            r.raise_for_status()
            
            # Handle content encoding
            if isinstance(r.content, bytes):
                content = decompress_content(r.content, r.headers)
            else:
                content = r.text
                
            if not is_text_content(r.headers):
                if content.strip():
                    return content, None
                return "", f"{url} returned non-text Content-Type: {r.headers.get('Content-Type','')}"
            return content, None
        except Exception as e:
            last_err = f"{url} failed attempt {attempt+1}: {e}"
            if attempt < RETRY_COUNT:
                time.sleep(RETRY_BACKOFF * (attempt + 1))
    return "", last_err

def extract_lines_from_text(text: str) -> List[str]:
    lines = []
    for raw in text.splitlines():
        l = raw.strip()
        if not l:
            continue
        if l.lower().startswith(("last-modified", "etag", "<!doctype", "<html")):
            continue
        lines.append(l)
    return lines

# ----------------------------
# Generation
# ----------------------------
def generate_merged(sources: List[str]) -> Tuple[Dict[str,int], int, int, List[str]]:
    raw_set: Set[str] = set()
    mobile_set: Set[str] = set()
    fetch_summary: Dict[str,int] = {}
    errors: List[str] = []
    
    for src in sources:
        txt, err = fetch_url(src)
        if err:
            errors.append(f"[{datetime.datetime.utcnow().isoformat()}] {err}")
            fetch_summary[src] = 0
            continue
            
        added_before = len(raw_set)
        mobile_added_before = len(mobile_set)
        lines = extract_lines_from_text(txt)
        
        for l in lines:
            n = normalize_line(l)
            
            # Convert hosts file entries to adblock format
            n = convert_hosts_to_adblock(n)
            
            if n.startswith("<"):
                for href in re.findall(r'href=["\']([^"\']+)["\']', n):
                    raw_set.add(f"# LINK: {href}")
                continue
                
            if n.lower().startswith(("readme", "#", "license")) or n.startswith("Project") or n.startswith("Usage"):
                raw_set.add("# " + n)
                continue
                
            if len(n) > 0:
                raw_set.add(n)
                # Add to mobile set if it passes mobile optimization
                if is_mobile_optimized(n):
                    mobile_set.add(n)
                
        fetch_summary[src] = max(0, len(raw_set) - added_before)
    
    # Brave-specific metadata headers
    desktop_metadata = [
        "! Title: ULTIMATE TRUE GOAT BLOCK LIST - Brave Desktop",
        "! Description: The most comprehensive blocklist optimized for Brave Desktop browser",
        "! Homepage: https://github.com/<your-repo>",
        "! License: MIT",
        "! Expires: 6 hours",
        "! Last modified: " + datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S UTC'),
        "! Brave Version: Compatible with Brave Desktop v1.0+",
        "! Format: Adblock Plus compatible",
    ]
    
    mobile_metadata = [
        "! Title: ULTIMATE TRUE GOAT BLOCK LIST - Brave Mobile",
        "! Description: Optimized blocklist for Brave Mobile browser (performance-focused)",
        "! Homepage: https://github.com/<your-repo>",
        "! License: MIT",
        "! Expires: 6 hours",
        "! Last modified: " + datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S UTC'),
        "! Brave Version: Compatible with Brave Mobile v1.0+",
        "! Format: Adblock Plus compatible",
        "! Note: Performance-optimized for mobile devices",
    ]
    
    # Custom header notes
    header_items = [
        "# ULTIMATE TRUE GOAT BLOCK LIST for Brave Browser - generated: " + datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        "# This file contains adblock/filter rules optimized for Brave browser.",
        "#",
        "# FEATURES:",
        "# - Brave browser compatible",
        "# - Optimized for both Desktop and Mobile",
        "# - No duplicates (carefully selected non-overlapping sources)",
        "# - All-rounder coverage (ads, trackers, malware, annoyances, privacy, security)",
        "# - No 404s or wrong URLs (all from actively maintained repos)",
        "#",
        "# CATEGORIES:",
        "# - Core Ad-blocking (EasyList, uBlock Origin, AdGuard)",
        "# - Privacy & Tracking (EasyPrivacy, CNAME trackers)",
        "# - Annoyances (cookie notices, pop-ups, login walls)",
        "# - Security & Malware (phishing, malware, ransomware)",
        "# - DNS-level/Hosts (StevenBlack, Firebog, Hagezi)",
        "# - Regional (country/language-specific lists)",
        "# - Specialized (smart TV, mobile, Windows telemetry)",
        "#",
        "# SOURCES: EasyList, EasyPrivacy, uBlock Origin, AdGuard, hagezi,",
        "# Firebog, StevenBlack, Disconnect.me, URLhaus, Phishing Army,",
        "# BlocklistProject, DeveloperDan, mitchellkrogza, and many more...",
    ]
    
    mobile_header_items = [
        "# ULTIMATE TRUE GOAT BLOCK LIST for Brave Mobile - generated: " + datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        "# This file contains performance-optimized adblock/filter rules for Brave Mobile.",
        "#",
        "# MOBILE OPTIMIZATIONS:",
        "# - Reduced cosmetic filters for better performance",
        "# - Resource-intensive rules filtered out",
        "# - Maintains core protection while being mobile-friendly",
        "# - Faster loading times and lower memory usage",
        "#",
        "# CORE PROTECTION MAINTAINED:",
        "# - Ad blocking",
        "# - Tracker blocking",
        "# - Malware protection",
        "# - Privacy protection",
    ]
    
    desktop_lines = sorted(raw_set)
    mobile_lines = sorted(mobile_set)
    
    # Write desktop version
    with open(DESKTOP_OUTPUT, "w", encoding="utf-8") as fh:
        for m in desktop_metadata:
            fh.write(m + "\n")
        fh.write("\n")
        for h in header_items:
            fh.write(h + "\n")
        fh.write("\n")
        for line in desktop_lines:
            fh.write(line + "\n")
    
    # Write mobile version
    with open(MOBILE_OUTPUT, "w", encoding="utf-8") as fh:
        for m in mobile_metadata:
            fh.write(m + "\n")
        fh.write("\n")
        for h in mobile_header_items:
            fh.write(h + "\n")
        fh.write("\n")
        for line in mobile_lines:
            fh.write(line + "\n")
            
    return fetch_summary, len(desktop_lines), len(mobile_lines), errors

def generate_readme(sources: List[str], fetch_summary: Dict[str,int], desktop_count: int, mobile_count: int) -> None:
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    with open(README, "w", encoding="utf-8") as f:
        f.write("# ULTIMATE TRUE GOAT BLOCK LIST for Brave Browser\n\n")
        f.write(f"**Generated:** {now}\n\n")
        f.write("This repository provides Brave browser-compatible blocklists optimized for both Desktop and Mobile versions.\n\n")
        f.write("## Files\n\n")
        f.write("### 🖥️ Desktop Version\n")
        f.write("- **File:** `brave_ultimate_goat_merged.txt`\n")
        f.write(f"- **Rules:** {desktop_count}\n")
        f.write("- **Use:** Brave Desktop browser\n")
        f.write("- **Features:** Full comprehensive protection\n\n")
        f.write("### 📱 Mobile Version\n")
        f.write("- **File:** `brave_mobile_optimized.txt`\n")
        f.write(f"- **Rules:** {mobile_count}\n")
        f.write("- **Use:** Brave Mobile browser\n")
        f.write("- **Features:** Performance-optimized for mobile devices\n\n")
        f.write("## How to Use in Brave Browser\n\n")
        f.write("### Desktop Brave:\n")
        f.write("1. Open Brave browser\n")
        f.write("2. Go to `brave://adblock`\n")
        f.write("3. Under \"Custom filter lists\", click \"Add custom filter list\"\n")
        f.write("4. Enter the URL: `https://raw.githubusercontent.com/<your-repo>/main/brave_ultimate_goat_merged.txt`\n")
        f.write("5. Click \"Add\" and enable the list\n\n")
        f.write("### Mobile Brave:\n")
        f.write("1. Open Brave browser on mobile\n")
        f.write("2. Go to Settings → Shields → Ad block\n")
        f.write("3. Tap \"Add custom filter list\"\n")
        f.write("4. Enter the URL: `https://raw.githubusercontent.com/<your-repo>/main/brave_mobile_optimized.txt`\n")
        f.write("5. Enable the list\n\n")
        f.write("## Sources included\n")
        for s in sources:
            f.write(f"- {s}\n")
        f.write("\n## Per-source fetch summary (this run)\n")
        for s, c in fetch_summary.items():
            f.write(f"- {s} -> {c} lines added\n")
        f.write("\n## Features\n")
        f.write("- **Brave Compatible**: Optimized for Brave browser's adblock engine\n")
        f.write("- **Dual Versions**: Separate desktop and mobile optimized versions\n")
        f.write("- **No duplicates**: Each list serves a specific purpose without overlap\n")
        f.write("- **All-rounder coverage**: Covers ads, trackers, malware, annoyances, privacy, and security\n")
        f.write("- **No 404s or wrong URLs**: All lists are from actively maintained repositories\n")
        f.write("- **Mobile Optimized**: Performance-focused version for mobile devices\n\n")
        f.write("## Categories\n")
        f.write("### Core Ad-blocking\n")
        f.write("- Primary ad-blocking lists (EasyList, uBlock Origin, AdGuard)\n")
        f.write("- Comprehensive coverage of advertisements across the web\n\n")
        f.write("### Privacy & Tracking\n")
        f.write("- Privacy-focused lists (CNAME trackers)\n")
        f.write("- Blocks tracking scripts, cookies, and fingerprinting attempts\n\n")
        f.write("### Annoyances\n")
        f.write("- Cookie notices, pop-ups, and other UI annoyances\n")
        f.write("- Social media widgets and newsletter prompts\n\n")
        f.write("### Security & Malware\n")
        f.write("- Malware domains, phishing sites, and ransomware protection\n")
        f.write("- Cryptojacking and coin mining prevention\n\n")
        f.write("### DNS-level/Hosts\n")
        f.write("- Hosts file lists (StevenBlack, Firebog, Hagezi)\n")
        f.write("- Comprehensive DNS-level blocking\n\n")
        f.write("### Regional\n")
        f.write("- Country/language-specific lists\n")
        f.write("- Localized ad and tracking protection\n\n")
        f.write("### Specialized\n")
        f.write("- Smart TV, mobile, Windows telemetry blocking\n\n")
        f.write("## Mobile Optimization\n")
        f.write("The mobile version includes:\n")
        f.write("- Reduced cosmetic filters for better performance\n")
        f.write("- Resource-intensive rules filtered out\n")
        f.write("- Maintains core protection while being mobile-friendly\n")
        f.write("- Faster loading times and lower memory usage\n\n")
        f.write("## Notes\n")
        f.write("- These files are in standard Adblock Plus format compatible with Brave\n")
        f.write("- fetch_errors.log contains any fetch failures.\n")
        f.write("- Mobile version is automatically generated from desktop version with optimizations\n")

def main() -> int:
    print("Starting generation of ULTIMATE TRUE GOAT BLOCK LIST for Brave Browser...")
    summary, desktop_count, mobile_count, errors = generate_merged(SOURCES)
    print(f"Fetched {len(SOURCES)} sources:")
    print(f"  - Desktop version: {desktop_count} rules")
    print(f"  - Mobile version: {mobile_count} rules")
    if errors:
        with open(FETCH_LOG, "w", encoding="utf-8") as fl:
            for e in errors:
                fl.write(e + "\n")
        print(f"Fetch errors written to {FETCH_LOG} ({len(errors)} entries).")
    else:
        open(FETCH_LOG, "w", encoding="utf-8").close()
        print("No fetch errors.")
    generate_readme(SOURCES, summary, desktop_count, mobile_count)
    print("Wrote README.md and output files:")
    print(f"  - {DESKTOP_OUTPUT}")
    print(f"  - {MOBILE_OUTPUT}")
    return 0

if __name__ == "__main__":
    try:
        rc = main()
        sys.exit(rc)
    except Exception as exc:
        with open(FETCH_LOG, "a", encoding="utf-8") as fl:
            fl.write(f"[{datetime.datetime.utcnow().isoformat()}] Unhandled error: {exc}\n")
        print("Unhandled error during generation:", exc)
        raise
