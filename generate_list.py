#!/usr/bin/env python3
import os
import json
import requests
import gzip
from datetime import datetime

# Output files
FINAL_FILE = "robust_block_list_pro.txt"
LOG_FILE = "fetch_errors.log"
META_FILE = "fetch_meta.json"

# Blocklist sources
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/main/Lite/hosts.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://v.firebog.net/hosts/AdguardDNS.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/anti.piracy.txt",
    "https://easylist-downloads.adblockplus.org/easylistgermany.txt",
    "https://easylist-downloads.adblockplus.org/indianlist%2Beasylist.txt",
    "https://easylist-downloads.adblockplus.org/liste_fr.txt",
    "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylist_russia.txt",
    "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
    "https://easylist-downloads.adblockplus.org/easylistdutch.txt",
    "https://easylist-downloads.adblockplus.org/easylistportuguese.txt",
    "https://easylist-downloads.adblockplus.org/abp-filters-anti-cv.txt",
    "https://easylist-downloads.adblockplus.org/israellist.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianList.txt",
    "https://filters.adtidy.org/extension/ublock/filters/3.txt",
    "https://filters.adtidy.org/extension/ublock/filters/4.txt",
    "https://filters.adtidy.org/extension/ublock/filters/10.txt",
    "https://filters.adtidy.org/extension/ublock/filters/11.txt",
    "https://filters.adtidy.org/extension/ublock/filters/14.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://big.oisd.nl/",
    "https://dbl.oisd.nl/",
    "https://hosts.oisd.nl/",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
]

# Whitelists
WHITELIST_URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
    "https://filters.adtidy.org/extension/ublock/filters/17.txt",
]

# --------------------
# Helpers
# --------------------

def log_error(message: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.utcnow().isoformat()}] {message}\n")

def load_meta():
    if os.path.exists(META_FILE):
        try:
            with open(META_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}

def save_meta(meta):
    try:
        with open(META_FILE, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
    except Exception as e:
        log_error(f"[META WRITE ERROR] {e}")

def fetch_list(url):
    try:
        resp = requests.get(url, timeout=40, headers={"Accept-Encoding": "identity"})
        resp.raise_for_status()
        content = resp.content

        # Manual gzip handling if needed
        if content[:2] == b"\x1f\x8b":
            try:
                return gzip.decompress(content).decode("utf-8", errors="ignore").splitlines()
            except Exception as e:
                log_error(f"Manual gzip failed for {url}: {e}")
                return []

        return resp.text.splitlines()

    except Exception as e:
        log_error(f"Fetch failed for {url}: {e}")
        return []

# --------------------
# Main
# --------------------

def main():
    meta = load_meta()
    combined = set()
    whitelist = set()

    # Reset logs
    open(LOG_FILE, "w").close()

    # Load whitelist
    for url in WHITELIST_URLS:
        whitelist.update(fetch_list(url))

    # Load blocklists
    for url in BLOCKLIST_URLS:
        lines = fetch_list(url)
        if not lines:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", "@@")):
                continue

            # Hosts format
            if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1]
                    if domain not in whitelist:
                        combined.add(f"||{domain}^")

            # ABP/uBO format
            elif line.startswith(("||", "/", ".", "*")):
                if line not in whitelist:
                    combined.add(line)

            # Plain domains
            elif "." in line and " " not in line:
                if line not in whitelist:
                    combined.add(f"||{line}^")

    # Write output
    with open(FINAL_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Robust Block List Pro (Unified)\n")
        f.write(f"! Updated: {datetime.utcnow().isoformat()} UTC\n")
        for rule in sorted(combined):
            f.write(rule + "\n")

    # Save metadata
    meta["last_update"] = datetime.utcnow().isoformat()
    save_meta(meta)

if __name__ == "__main__":
    main()
