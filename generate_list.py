#!/usr/bin/env python3
import requests
from datetime import datetime
import re
from tenacity import retry, stop_after_attempt, wait_fixed

# Validated list of block list sources (duplicates and 404s removed)
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://easylist.to/easylist/easylist.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://easylist-downloads.adblockplus.org/easylistbrazil.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
    "https://easylist-downloads.adblockplus.org/easylistgermany.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://v.firebog.net/hosts/Easyprivacy.txt",
    "https://raw.githubusercontent.com/quidsup/notrack-blocklists/master/notrack-blocklist.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
    "https://raw.githubusercontent.com/ktsaou/blocklists/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/quidsup/notrack-blocklists/master/notrack-malware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt",
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://easylist-downloads.adblockplus.org/fanboy-social.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
    "https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt",
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    "https://raw.githubusercontent.com/easylist/easylistjapan/master/easylistjapan.txt",
    "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
    "https://easylist-downloads.adblockplus.org/easylistfrench.txt",
    "https://easylist-downloads.adblockplus.org/easylistrussian.txt",
    "https://dbl.oisd.nl/",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
]

WHITELIST_URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
]

BASE_HEADER_LINES = [
    "! Title: Robust Block List Pro",
    "! Description: Combined block list from multiple sources for ultimate ad, tracker, and malware protection",
    "! Homepage: https://github.com/<your-repo>",  # Replace with your repo
]

SECRET_PATTERNS = [
    re.compile(r'[a-zA-Z0-9]{40,60}'),  # Generic long tokens
    re.compile(r'apikey', re.IGNORECASE),
    re.compile(r'IBM', re.IGNORECASE),
    re.compile(r'(AWS|AKIA)[A-Z0-9]{16,20}'),  # AWS keys
    re.compile(r'[0-9a-f]{32,128}'),  # Generic API tokens
    re.compile(r'oauth', re.IGNORECASE),  # OAuth tokens
]

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def fetch_url(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return ""

def main():
    # Fetch whitelist
    whitelist_lines = set()
    for url in WHITELIST_URLS:
        print(f"Fetching whitelist: {url}")
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line_clean = line.strip()
                if line_clean and not line_clean.startswith("!"):
                    whitelist_lines.add(line_clean)

    # Fetch and process blocklists
    combined_lines = set()
    filtered_lines = []

    for url in BLOCKLIST_URLS:
        print(f"Fetching: {url}")
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line_clean = line.strip()
                if line_clean and line_clean not in BASE_HEADER_LINES and not line_clean.startswith("!"):
                    if not any(pattern.search(line_clean) for pattern in SECRET_PATTERNS):
                        combined_lines.add(line_clean)
                    else:
                        filtered_lines.append(line_clean)

    # Remove whitelisted entries
    final_lines = [line for line in combined_lines if line not in whitelist_lines]
    total_count = len(final_lines)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Write single combined file
    header_lines = BASE_HEADER_LINES + [
        f"! Total Blocked Items: {total_count}",
        f"! Updated: {now}",
    ]
    header = "\n".join(header_lines)
    sorted_lines = sorted(final_lines)
    final_content = header + "\n\n" + "\n".join(sorted_lines) + "\n"

    try:
        with open("robust_block_list_pro.txt", "w", encoding="utf-8") as f:
            f.write(final_content)
        print("Generated robust_block_list_pro.txt successfully.")
    except IOError as e:
        print(f"Error writing to robust_block_list_pro.txt: {e}")

    if filtered_lines:
        print("Filtered lines (potential secrets):")
        for line in filtered_lines:
            print(line)

if __name__ == "__main__":
    main()
