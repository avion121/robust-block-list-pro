#!/usr/bin/env python3
import requests
from datetime import datetime
import re
import json
# List of source URLs for block lists (your existing feeds plus two new ones)
URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/filters.txt   ",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/badware.txt   ",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/privacy.txt   ",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/quick-fixes.txt   ",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/unbreak.txt   ",
    "https://easylist.to/easylist/easylist.txt   ",
    "https://easylist.to/easylist/easyprivacy.txt   ",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt   ",
    "https://ransomwaretracker.abuse.ch/blocklist/   ",
    "https://urlhaus.abuse.ch/downloads/hostfile/   ",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext   ",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt   ",
    "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/alternates/fakenews-gambling/hosts   ",
    "https://big.oisd.nl   ",
    "https://o0.pages.dev/Lite/adblock.txt   ",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt   ",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt   ",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt   ",
    "https://phishing.army/download/phishing_army_blocklist.txt   ",
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt   ",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt   ",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/refs/heads/master/Dandelion%20Sprout   's%20Anti-Malware%20List.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/resource-abuse.txt   ",
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt   ",
    "https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt   ",
    "https://big.oisd.nl/porn.txt   ",
    "http://winhelp2002.mvps.org/hosts.txt   ",
    "https://hosts.adaway.org/hosts.txt   ",
    "https://v.firebog.net/hosts/static/w3kbl.txt   ",
    "https://v.firebog.net/hosts/Prigent-Phishing.txt   ",
    "https://v.firebog.net/hosts/Rejections.txt   ",
    "https://hosts-file.net/ad_servers.txt   ",
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt   ",
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt   ",
]
BASE_HEADER_LINES = [
    "! Title: Robust Block List Pro",
    "! Description: Combined block list from multiple sources"
]
SECRET_PATTERNS = [
    re.compile(r'[a-zA-Z0-9]{40,60}'),
    re.compile(r'apikey', re.IGNORECASE),
    re.compile(r'IBM', re.IGNORECASE),
]
def fetch_url(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.text
    except requests.RequestException:
        return ""
def extract_disconnect_domains(content):
    domains = set()
    try:
        data = json.loads(content)
        def recurse(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == 'domain' and isinstance(v, str):
                        domains.add(v)
                    else:
                        recurse(v)
            elif isinstance(obj, list):
                for item in obj:
                    recurse(item)
        recurse(data)
    except json.JSONDecodeError:
        pass
    return domains
def main():
    combined = set()
    filtered = []
    for url in URLS:
        content = fetch_url(url)
        if not content:
            continue
        if url.endswith('services.json'):
            for d in extract_disconnect_domains(content):
                line = f"0.0.0.0 {d}"
                if not any(p.search(line) for p in SECRET_PATTERNS):
                    combined.add(line)
                else:
                    filtered.append(line)
            continue
        for line in content.splitlines():
            l = line.strip()
            if not l or l in BASE_HEADER_LINES:
                continue
            if not any(p.search(l) for p in SECRET_PATTERNS):
                combined.add(l)
            else:
                filtered.append(l)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    header = BASE_HEADER_LINES + [
        f"! Total Blocked Items: {len(combined)}",
        f"! Updated: {now}"
    ]
    output = "\n".join(header) + "\n\n" + "\n".join(sorted(combined)) + "\n"
    with open("robust_block_list_pro.txt", "w", encoding="utf-8") as f:
        f.write(output)
    if filtered:
        print("Filtered potential secrets:")
        for fline in filtered:
            print(fline)
if __name__ == "__main__":
    main()
