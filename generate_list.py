#!/usr/bin/env python3
import os
import json
import requests
import gzip
from datetime import datetime

# Output files
BALANCED_FILE = "robust_block_list_pro_balanced.txt"
MONSTER_FILE = "robust_block_list_pro_monster.txt"
LOG_FILE = "fetch_errors.log"
META_FILE = "fetch_meta.json"

# --------------------
# BLOCKLIST SOURCES
# --------------------

BALANCED_URLS = [
    # Core curated safe sources
    "https://big.oisd.nl/",  # OISD full
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/main/Lite/hosts.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://filters.adtidy.org/extension/ublock/filters/3.txt",   # Tracking
    "https://filters.adtidy.org/extension/ublock/filters/4.txt",   # Social
    "https://filters.adtidy.org/extension/ublock/filters/11.txt",  # Mobile ads
    "https://filters.adtidy.org/extension/ublock/filters/14.txt",  # Annoyances
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
]

MONSTER_URLS = BALANCED_URLS + [
    # Hagezi Ultimate Tiers
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/anti.piracy.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt",
    # Extra OISD sources
    "https://dbl.oisd.nl/",
    "https://hosts.oisd.nl/",
    # StevenBlack unified hosts
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    # 1Hosts Pro
    "https://raw.githubusercontent.com/badmojr/1Hosts/main/Pro/hosts.txt",
    # DandelionSprout extras
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt",
]

# --------------------
# WHITELIST SOURCES
# --------------------
WHITELIST_URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
    "https://filters.adtidy.org/extension/ublock/filters/17.txt",
]

# --------------------
# HELPERS
# --------------------

def fetch_url(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        if url.endswith(".gz"):
            return gzip.decompress(resp.content).decode("utf-8", errors="ignore")
        return resp.text
    except Exception as e:
        with open(LOG_FILE, "a") as log:
            log.write(f"[{datetime.utcnow().isoformat()}] Fetch failed for {url}: {e}\n")
        return ""

def process_list(urls):
    domains = set()
    for url in urls:
        text = fetch_url(url)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Extract domain from different formats
            if line.startswith(("0.0.0.0", "127.0.0.1")):
                parts = line.split()
                if len(parts) > 1:
                    domains.add(parts[1])
            elif line.startswith("||") and line.endswith("^"):
                domains.add(line[2:-1])
            elif line.startswith("||"):
                domains.add(line[2:])
            elif line.startswith("|http") or line.startswith("@@"):
                continue
            elif "/" in line or line.startswith("."):
                continue
            else:
                domains.add(line)
    return domains

def save_list(domains, whitelist, filename):
    final = sorted(domains - whitelist)
    with open(filename, "w") as f:
        f.write("\n".join(final))
    return len(final)

# --------------------
# MAIN
# --------------------
if __name__ == "__main__":
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    whitelist = process_list(WHITELIST_URLS)

    balanced = process_list(BALANCED_URLS)
    balanced_count = save_list(balanced, whitelist, BALANCED_FILE)

    monster = process_list(MONSTER_URLS)
    monster_count = save_list(monster, whitelist, MONSTER_FILE)

    meta = {
        "timestamp": datetime.utcnow().isoformat(),
        "balanced_entries": balanced_count,
        "monster_entries": monster_count,
        "balanced_file": BALANCED_FILE,
        "monster_file": MONSTER_FILE,
    }
    with open(META_FILE, "w") as f:
        json.dump(meta, f, indent=2)
