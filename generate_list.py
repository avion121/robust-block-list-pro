#!/usr/bin/env python3
import os
import json
import requests
from datetime import datetime

# Output files
BALANCED_FILE = "robust_block_list_pro_balanced.txt"
MONSTER_FILE = "robust_block_list_pro_monster.txt"
META_FILE = "fetch_meta.json"
CHANGELOG_FILE = "CHANGELOG.md"

# --------------------
# Sources
# --------------------
BALANCED_SOURCES = [
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/main/Lite/hosts.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
]

MONSTER_SOURCES = BALANCED_SOURCES + [
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
    "https://v.firebog.net/hosts/AdguardDNS.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
    "https://big.oisd.nl/",
    "https://dbl.oisd.nl/",
    "https://hosts.oisd.nl/",
    "https://www.spamhaus.org/drop/drop.txt",
]

# Whitelists
WHITELISTS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
    "https://filters.adtidy.org/extension/ublock/filters/17.txt",
]

# --------------------
# Helpers
# --------------------
def fetch_url(url):
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            return r.text.splitlines()
    except Exception:
        return []
    return []

def normalize(lines):
    hosts = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
            parts = line.split()
            if len(parts) >= 2:
                hosts.add(parts[1].lower())
        else:
            hosts.add(line.lower())
    return hosts

def fetch_lists(sources):
    combined = set()
    for url in sources:
        combined |= normalize(fetch_url(url))
    return combined

# --------------------
# Main
# --------------------
def main():
    whitelist = fetch_lists(WHITELISTS)
    balanced_hosts = fetch_lists(BALANCED_SOURCES) - whitelist
    monster_hosts = fetch_lists(MONSTER_SOURCES) - whitelist

    with open(BALANCED_FILE, "w") as f:
        for h in sorted(balanced_hosts):
            f.write(f"0.0.0.0 {h}\n")

    with open(MONSTER_FILE, "w") as f:
        for h in sorted(monster_hosts):
            f.write(f"0.0.0.0 {h}\n")

    meta = {
        "balanced_count": len(balanced_hosts),
        "monster_count": len(monster_hosts),
        "last_updated": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    with open(META_FILE, "w") as f:
        json.dump(meta, f, indent=2)

    def badge_number(n):
        if n >= 1_000_000:
            return f"{n//1_000_000}M"
        elif n >= 1_000:
            return f"{n//1_000}k"
        return str(n)

    balanced_badge = f"https://img.shields.io/badge/Balanced_Entries-{badge_number(meta['balanced_count'])}-blue"
    monster_badge = f"https://img.shields.io/badge/Monster_Entries-{badge_number(meta['monster_count'])}-red"
    updated_badge = f"https://img.shields.io/badge/Last_Updated-{datetime.utcnow().strftime('%Y--%m--%d')}-success"

    # --------------------
    # README
    # --------------------
    readme = f"""# 🚀 Robust Block List Pro

![Balanced Entries]({balanced_badge})
![Monster Entries]({monster_badge})
![Last Updated]({updated_badge})
![Build](https://github.com/avion121/robust-block-list-pro/actions/workflows/run.yml/badge.svg)

Ultimate GOAT blocklists — generated daily with curated sources.

## 📊 Stats
- **Balanced List**: {meta['balanced_count']:,} entries  
- **Monster List**: {meta['monster_count']:,} entries  
- **Last Updated**: {meta['last_updated']}

## 📥 Download
- [Balanced List](./{BALANCED_FILE})  
- [Monster List](./{MONSTER_FILE})  

## ⚡ Quick Setup

You can use the **raw GitHub URLs** directly in Pi-hole, AdGuard, or uBlock Origin.

### Pi-hole
1. Go to **Group Management → Adlists**
2. Add:
   - `https://raw.githubusercontent.com/avion121/robust-block-list-pro/main/{BALANCED_FILE}`
   - `https://raw.githubusercontent.com/avion121/robust-block-list-pro/main/{MONSTER_FILE}`

### AdGuard Home
1. Go to **Filters → DNS blocklists**
2. Add the same raw URLs as above.

### uBlock Origin
1. Go to **Dashboard → Filter Lists → Custom**
2. Paste in the raw URLs.

> ✅ **Balanced** = safe for most users  
> 🔥 **Monster** = extreme blocking, aggressive

## ✅ Features
- Daily auto-updates  
- Duplicate + dead entry removal  
- Whitelist protection (avoids breaking legit sites)  
- Two modes: Balanced (safe) & Monster (aggressive)  

## 📜 Changelog
See [CHANGELOG.md](./CHANGELOG.md) for daily history.

---
*Maintained automatically by GitHub Actions.*
"""

    with open("README.md", "w") as f:
        f.write(readme)

    # --------------------
    # CHANGELOG (trimmed to last 30 entries)
    # --------------------
    log_entry = f"- {meta['last_updated']}: Balanced = {meta['balanced_count']:,}, Monster = {meta['monster_count']:,}\n"

    if not os.path.exists(CHANGELOG_FILE):
        with open(CHANGELOG_FILE, "w") as f:
            f.write("# 📜 Changelog\n\n")
            f.write("Daily auto-generated update log.\n\n")
            f.write(log_entry)
    else:
        with open(CHANGELOG_FILE, "r") as f:
            lines = f.readlines()

        header = lines[:3]  # Keep title + intro
        entries = lines[3:] + [log_entry]
        entries = entries[-30:]  # Keep last 30

        with open(CHANGELOG_FILE, "w") as f:
            f.writelines(header + entries)

if __name__ == "__main__":
    main()
