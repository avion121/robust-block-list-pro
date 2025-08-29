#!/usr/bin/env python3
import hashlib
import requests
import datetime
import os

# --------------------------
# SOURCE LISTS
# --------------------------
BLOCKLISTS_MONSTER = [
    # General / Multi-Purpose
    "https://big.oisd.nl/",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/domains.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://block.energized.pro/blu/formats/hosts.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",

    # Ads / Tracking
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ads.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tracking.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt",

    # Malware / Security
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
    "https://feodotracker.abuse.ch/downloads/feodohosts.txt",
    "http://mirror.cedia.org.ec/malwaredomains/justdomains",
    "http://cybercrime-tracker.net/all.php",
    "https://filters.adtidy.org/extension/ublock/filters/15.txt",

    # Privacy / Telemetry
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus-lite.txt",
    "https://filters.adtidy.org/extension/ublock/filters/11.txt",
    "https://block.energized.pro/spark/formats/hosts.txt",

    # Regional / Special Purpose
    "https://adaway.org/hosts.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
    "https://v.firebog.net/hosts/Tick.txt",
    "https://v.firebog.net/hosts/Prigent-Ads.txt",
]

BLOCKLISTS_IOS_LITE = [
    "https://small.oisd.nl/",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus-lite.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
]

WHITELISTS = [
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/whitelist.txt"
]

# --------------------------
# HELPERS
# --------------------------
def fetch_list(url):
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            return r.text.splitlines()
        else:
            log_error(f"{url} returned {r.status_code}")
    except Exception as e:
        log_error(f"{url} failed: {e}")
    return []

def log_error(msg):
    with open("fetch_errors.log", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.datetime.utcnow()}] {msg}\n")

def normalize(lines):
    result = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
            line = line.split(" ", 1)[1]
        result.add(line.lower())
    return result

def save_list(domains, filename):
    with open(filename, "w", encoding="utf-8") as f:
        for d in sorted(domains):
            f.write(d + "\n")

def sha256sum(filename):
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# --------------------------
# MAIN
# --------------------------
def main():
    os.makedirs(".", exist_ok=True)

    # Reset fetch log
    open("fetch_errors.log", "w").close()

    # Fetch blocklists
    monster = set()
    ioslite = set()
    whitelist = set()

    for url in BLOCKLISTS_MONSTER:
        monster |= normalize(fetch_list(url))

    for url in BLOCKLISTS_IOS_LITE:
        ioslite |= normalize(fetch_list(url))

    for url in WHITELISTS:
        whitelist |= normalize(fetch_list(url))

    # Apply whitelist
    monster -= whitelist
    ioslite -= whitelist

    # Save outputs
    save_list(monster, "robust_block_list_pro_combined.txt")
    save_list(ioslite, "robust_block_list_ios_lite.txt")

    # Write changelog
    with open("CHANGELOG.md", "a", encoding="utf-8") as f:
        f.write(f"## {datetime.date.today()}\n")
        f.write(f"- Combined: {len(monster)} domains (sha256: {sha256sum('robust_block_list_pro_combined.txt')})\n")
        f.write(f"- iOS Lite: {len(ioslite)} domains (sha256: {sha256sum('robust_block_list_ios_lite.txt')})\n\n")

    # Generate README.md (always fresh)
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(README_TEMPLATE)

# --------------------------
# README TEMPLATE
# --------------------------
README_TEMPLATE = """# 🚀 Robust Block List Pro

Ultimate **privacy-first blocklist collection** for ads, trackers, malware, phishing, telemetry & spam.  
Two flavors are maintained automatically with daily updates.

---

## 🔥 Flavors

| List | Size | Recommended For | File |
|------|------|-----------------|------|
| ✅ **Monster Combined** (29 sources) | Millions of domains | Pi-hole, AdGuard, NextDNS, Brave/Firefox/Chrome (desktop) | [robust_block_list_pro_combined.txt](./robust_block_list_pro_combined.txt) |
| 📱 **iOS Lite (Crash-Free)** | ~50K domains | Brave iOS, Safari, mobile browsers (stable) | [robust_block_list_ios_lite.txt](./robust_block_list_ios_lite.txt) |

---

## 📦 Sources

### ✅ Monster (29 sources)
Includes **all major curated blocklists** for maximum coverage:

- OISD Big  
- HaGeZi Pro++  
- 1Hosts Pro  
- StevenBlack Hosts  
- Energized Blu  
- GoodbyeAds  
- Disconnect (Ads, Tracking)  
- Notracking  
- HaGeZi Ads / Tracking  
- 1Hosts Lite  
- URLHaus  
- Phishing Army  
- Zeus Tracker  
- Feodo Tracker  
- MalwareDomains  
- CyberCrime Tracker  
- AdGuard DNS Filter  
- HaGeZi Pro++ Lite  
- AdGuard Mobile  
- Energized Spark  
- AdAway  
- Yoyo  
- DandelionSprout Anti-Malware  
- KADhosts  
- Frogeye Trackers  
- Firebog Tick  
- Firebog Prigent-Ads  

### 📱 iOS Lite (Crash-Free Subset)
Selected for stability + smaller size:

- OISD Small  
- HaGeZi Pro++ Lite  
- 1Hosts Lite  
- Disconnect (Ads, Tracking)  
- Phishing Army  
- URLHaus  

---

## 📥 Downloads
- **Monster Combined** → [robust_block_list_pro_combined.txt](./robust_block_list_pro_combined.txt)  
- **iOS Lite** → [robust_block_list_ios_lite.txt](./robust_block_list_ios_lite.txt)  

---

## 🛠️ Metadata
- SHA256 hashes recorded in [`CHANGELOG.md`](./CHANGELOG.md)  
- Fetch errors (if any) stored in [`fetch_errors.log`](./fetch_errors.log)  
- Auto-updated **daily** via GitHub Actions  

---

## ⚡ Notes
- Use **Monster** for maximum protection (desktop / servers).  
- Use **iOS Lite** for Brave iOS & Safari (to avoid crashes).  
- Whitelists (AnudeepND, HaGeZi) are applied to minimize breakage.  

---

💡 Maintained with ❤️ by automation. Privacy first, always.
"""

if __name__ == "__main__":
    main()
