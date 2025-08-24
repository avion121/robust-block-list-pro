import requests
import re
import time
from urllib.parse import urlparse
from datetime import datetime

# Curated blocklist sources (updated as of August 24, 2025)

BLOCKLIST_URLS = [
    # Core ad & privacy
    "https://easylist.to/easylist/easylist.txt",  # EasyList
    "https://easylist.to/easylist/easyprivacy.txt",  # EasyPrivacy
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",  # uBlock Origin Filters
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",  # uBlock Origin Badware
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",  # uBlock Origin Resource Abuse
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",  # uBlock Origin Privacy
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/anti-adblock.txt",  # uBlock Origin Anti-Adblock
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/lantern.txt",  # uBlock Origin Lantern
    # Fanboy extras
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",  # Fanboy’s Annoyance
    "https://secure.fanboy.co.nz/fanboy-social.txt",  # Fanboy’s Social
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",  # EasyList Anti-Adblock
    "https://www.fanboy.co.nz/enhancedstats.txt",  # Fanboy’s Enhanced Tracking
    # Crypto miners
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",  # NoCoin
    "https://zerodot1.gitlab.io/CoinBlockerLists/list_browser.txt",  # CoinBlockerLists
    # Hosts-format sources
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",  # Yoyo.org Ad Servers
    "https://adaway.org/hosts.txt",  # Adaway
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",  # StevenBlack Hosts
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",  # AnudeepND Adservers
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",  # Frogeye First-Party Trackers
    "https://o0.pages.dev/Lite/hosts",  # 1Hosts (Lite)
    # Security-focused
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",  # Phishing Army
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",  # Blocklist Project Malware
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",  # Blocklist Project Phishing
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",  # Dandelion Sprout Anti-Malware
    "https://urlhaus.abuse.ch/downloads/hostfile/",  # URLHaus
    "https://v.firebog.net/hosts/AdguardDNS.txt",  # Firebog AdguardDNS
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",  # Hagezi Threat Intelligence Feeds
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",  # Hagezi Pro++
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/anti.piracy.txt",  # Hagezi Anti-Piracy
    # Regional EasyList
    "https://easylist-downloads.adblockplus.org/easylistgermany.txt",  # EasyList Germany
    "https://easylist-downloads.adblockplus.org/indianlist%2Beasylist.txt",  # EasyList India
    "https://easylist-downloads.adblockplus.org/liste_fr.txt",  # EasyList France
    "https://easylist-downloads.adblockplus.org/easylistitaly.txt",  # EasyList Italy
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",  # EasyList China
    "https://easylist-downloads.adblockplus.org/easylist_russia.txt",  # EasyList Russia
    "https://easylist-downloads.adblockplus.org/easylistspanish.txt",  # EasyList Spain
    "https://easylist-downloads.adblockplus.org/easylistdutch.txt",  # EasyList Dutch
    "https://easylist-downloads.adblockplus.org/easylistportuguese.txt",  # EasyList Portuguese
    "https://easylist-downloads.adblockplus.org/abp-filters-anti-cv.txt",  # EasyList Arabic (Anti-CV)
    "https://easylist-downloads.adblockplus.org/israellist.txt",  # EasyList Hebrew
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianList.txt",  # Dandelion Sprout Nordic
    # AdGuard extras
    "https://filters.adtidy.org/extension/ublock/filters/3.txt",  # AdGuard Tracking Protection
    "https://filters.adtidy.org/extension/ublock/filters/4.txt",  # AdGuard Social Media
    "https://filters.adtidy.org/extension/ublock/filters/10.txt",  # AdGuard Spyware
    "https://filters.adtidy.org/extension/ublock/filters/11.txt",  # AdGuard Mobile Ads
    "https://filters.adtidy.org/extension/ublock/filters/14.txt",  # AdGuard Annoyances
    # Gaming
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt",  # Dandelion Sprout Game Console
]

# Whitelist sources
WHITELIST_URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",  # uBlock Origin Unbreak
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",  # AnudeepND Whitelist
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",  # Dandelion Sprout Legitimate URL Shortener
    "https://filters.adtidy.org/extension/ublock/filters/17.txt",  # AdGuard Allowlist
]

OUTPUT_FILE = "robust_block_list_pro.txt"
LOG_FILE = "fetch_errors.log"
STALE_THRESHOLD = 30 * 24 * 60 * 60  # 30 days in seconds


def is_valid_url(url):
    """Validate URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_valid_entry(line, is_hosts=False):
    """Validate blocklist or whitelist entry."""
    line = line.strip()
    if not line or line.startswith(("#", "!")) or "localhost" in line:
        return False
    if is_hosts:
        return bool(re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+[a-zA-Z0-9-_\.]+$', line))
    # Basic Adblock Plus syntax check (supports ||, @@, cosmetic filters, etc.)
    return bool(re.match(r'^(\|\||@@)?[a-zA-Z0-9-_\./\*\$\^:]+', line))


def parse_last_modified(header):
    """Parse Last-Modified header to timestamp."""
    try:
        return int(time.mktime(time.strptime(header, "%a, %d %b %Y %H:%M:%S GMT")))
    except:
        return None


def fetch_list(url, retries=3, backoff=2):
    """Fetch a list with retries, validate freshness, and log failures."""
    if not is_valid_url(url):
        with open(LOG_FILE, "a", encoding="utf-8") as log:
            log.write(f"[INVALID URL] {url}\n")
        return [], "Invalid URL"

    for attempt in range(retries):
        try:
            response = requests.get(url, headers={"Accept-Encoding": "identity"}, timeout=25)
            if response.status_code == 200:
                last_modified = response.headers.get("Last-Modified", "Unknown")
                last_modified_ts = parse_last_modified(last_modified) if last_modified != "Unknown" else None
                if last_modified_ts and (time.time() - last_modified_ts) > STALE_THRESHOLD:
                    with open(LOG_FILE, "a", encoding="utf-8") as log:
                        log.write(f"[STALE] {url} (Last-Modified: {last_modified})\n")
                return response.text.splitlines(), last_modified
            else:
                with open(LOG_FILE, "a", encoding="utf-8") as log:
                    log.write(f"[HTTP {response.status_code}] {url} (Attempt {attempt+1})\n")
        except Exception as e:
            with open(LOG_FILE, "a", encoding="utf-8") as log:
                log.write(f"[ERROR] {url} → {e} (Attempt {attempt+1})\n")
        time.sleep(backoff ** attempt)
    return [], "Failed"


def generate_combined_blocklist():
    """Generate deduplicated blocklist with metadata."""
    block_entries = set()
    whitelist_entries = set()
    source_metadata = []
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    version = datetime.utcnow().strftime("%Y%m%d%H%M")

    # Fetch blocklists
    for url in BLOCKLIST_URLS:
        lines, last_modified = fetch_list(url)
        is_hosts = "hosts" in url or "hostfile" in url
        for line in lines:
            line = line.strip()
            if is_valid_entry(line, is_hosts):
                block_entries.add(line.lower())
        source_metadata.append(f"! - {url} (Fetched: {last_modified})")

    # Fetch whitelists
    for url in WHITELIST_URLS:
        lines, last_modified = fetch_list(url)
        for line in lines:
            line = line.strip()
            if is_valid_entry(line, is_hosts=False):
                whitelist_entries.add(line.lower())
        source_metadata.append(f"! - {url} (Whitelist, Fetched: {last_modified})")

    # Apply whitelist
    final_entries = block_entries - whitelist_entries

    # Write output with metadata header
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"! Title: Robust Block List Pro\n")
        f.write(f"! Version: {version}\n")
        f.write(f"! Last modified: {current_time}\n")
        sources_text = "\n".join(source_metadata)
        f.write(f"! Sources:\n{sources_text}\n\n")
        f.write("\n".join(sorted(final_entries)))

    return len(final_entries)


if __name__ == "__main__":
    open(LOG_FILE, "w").close()  # Clear log file
    entry_count = generate_combined_blocklist()
    print(f"✅ Final blocklist: {entry_count} entries → {OUTPUT_FILE}")
    print(f"ℹ️ Errors (if any) logged in {LOG_FILE}")