#!/usr/bin/env python3
import requests
from datetime import datetime
import re
from tenacity import retry, stop_after_attempt, wait_fixed

# List of block list sources (core + vetted GOAT additions)
CATEGORIES = {
    "ads": [
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
        "https://easylist.to/easylist/easylist.txt",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
        "https://easylist-downloads.adblockplus.org/easylistbrazil.txt",
        "https://easylist-downloads.adblockplus.org/easylistindia.txt",
        "https://easylist-downloads.adblockplus.org/easylistchina.txt",
        "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
        "https://easylist-downloads.adblockplus.org/easylistgermany.txt",
        "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
        "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
        "https://adaway.org/hosts.txt",
        "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
        "https://filters.adtidy.org/extension/chromium/filters/224.txt",  # AdGuard Chinese
    ],
    "trackers": [
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
        "https://easylist.to/easylist/easyprivacy.txt",
        "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
        "https://raw.githubusercontent.com/EFForg/privacybadger/master/data/trackers.txt",
        "https://v.firebog.net/hosts/Easyprivacy.txt",
        "https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains",
        "https://raw.githubusercontent.com/quidsup/notrack-blocklists/master/notrack-blocklist.txt",
        "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
    ],
    "malware": [
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
        "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
        "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
        "https://raw.githubusercontent.com/ktsaou/blocklists/master/firehol_level1.netset",
        "https://raw.githubusercontent.com/ktsaou/blocklists/master/firehol_level2.netset",
        "https://raw.githubusercontent.com/ktsaou/blocklists/master/firehol_level3.netset",
        "https://talosintelligence.com/documents/ip-blacklist",
        "https://dbl.oisd.nl/extra/",  # OISD Extra for malvertising/scams
        "https://raw.githubusercontent.com/quidsup/notrack-blocklists/master/notrack-malware.txt",
    ],
    "annoyances": [
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt",
        "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
        "https://easylist-downloads.adblockplus.org/cookiemonster.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_AntiAnnoyances/filter.txt",
        "https://www.i-dont-care-about-cookies.eu/abp/",
        "https://raw.githubusercontent.com/yokoffing/WebAnnoyancesUltralist/main/ultralist.txt",
        "https://easylist-downloads.adblockplus.org/fanboy-social.txt",
    ],
    "anti_adblock": [
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
        "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
        "https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt",
        "https://raw.githubusercontent.com/bogachenko/fuck-anti-adblock/master/fuck-anti-adblock.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_AntiAdblock/filter.txt",
        "https://raw.githubusercontent.com/magnolia1234/bypass-paywalls-clean/master/filters.txt",
    ],
    "crypto": [
        "https://zerodot1.gitlab.io/CoinBlockerLists/list.txt",
        "https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/hosts",
        "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    ],
    "iot": [
        "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
        "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/IoT.txt",
        "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
    ],
    "regional": [
        "https://raw.githubusercontent.com/easylist/easylistjapan/master/easylistjapan.txt",
        "https://raw.githubusercontent.com/ABPindo/indonesianadblockfilters/master/subscriptions/indonesian-list.txt",
        "https://raw.githubusercontent.com/AdnanHussain/ArabList/master/ArabList.txt",
        "https://raw.githubusercontent.com/List-KR/List-KR/master/filter.txt",
        "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
        "https://easylist-downloads.adblockplus.org/easylistfrench.txt",
        "https://easylist-downloads.adblockplus.org/easylistrussian.txt",
    ],
    "ai_content": [
        "https://raw.githubusercontent.com/kalilinuxtutorials/ublock-origin-ublacklist-ai-blocklist/main/blocklist.txt",
    ],
    "gaming": [
        "https://raw.githubusercontent.com/hl2guide/curated-adblock-lists/main/lists/gaming.txt",
    ],
    "ultimate": [
        "https://dbl.oisd.nl/",  # OISD Full
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
        "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
        "https://block.energized.pro/ultimate/formats/hosts.txt",
    ],
}

# Whitelist to resolve conflicts
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
    # Fetch whitelist first
    whitelist_lines = set()
    for url in WHITELIST_URLS:
        print(f"Fetching whitelist: {url}")
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line_clean = line.strip()
                if line_clean and not line_clean.startswith("!"):
                    whitelist_lines.add(line_clean)

    # Fetch and process blocklists by category
    for category, urls in CATEGORIES.items():
        print(f"Processing category: {category}")
        combined_lines = set()
        filtered_lines = []

        for url in urls:
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

        # Write category-specific file
        header_lines = BASE_HEADER_LINES + [
            f"! Category: {category.capitalize()}",
            f"! Total Blocked Items: {total_count}",
            f"! Updated: {now}",
        ]
        header = "\n".join(header_lines)
        sorted_lines = sorted(final_lines)
        final_content = header + "\n\n" + "\n".join(sorted_lines) + "\n"

        try:
            with open(f"robust_block_list_pro_{category}.txt", "w", encoding="utf-8") as f:
                f.write(final_content)
            print(f"Generated robust_block_list_pro_{category}.txt successfully.")
        except IOError as e:
            print(f"Error writing to robust_block_list_pro_{category}.txt: {e}")

        if filtered_lines:
            print(f"Filtered lines in {category} (potential secrets):")
            for line in filtered_lines:
                print(line)

    # Generate a combined "ultimate" list
    combined_lines = set()
    for category, urls in CATEGORIES.items():
        for url in urls:
            content = fetch_url(url)
            if content:
                for line in content.splitlines():
                    line_clean = line.strip()
                    if line_clean and line_clean not in BASE_HEADER_LINES and not line_clean.startswith("!"):
                        if not any(pattern.search(line_clean) for pattern in SECRET_PATTERNS):
                            combined_lines.add(line_clean)

    # Remove whitelisted entries
    final_combined_lines = [line for line in combined_lines if line not in whitelist_lines]
    total_count = len(final_combined_lines)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    header_lines = BASE_HEADER_LINES + [
        "! Category: Combined Ultimate",
        f"! Total Blocked Items: {total_count}",
        f"! Updated: {now}",
    ]
    header = "\n".join(header_lines)
    sorted_lines = sorted(final_combined_lines)
    final_content = header + "\n\n" + "\n".join(sorted_lines) + "\n"

    try:
        with open("robust_block_list_pro.txt", "w", encoding="utf-8") as f:
            f.write(final_content)
        print("Generated robust_block_list_pro.txt successfully.")
    except IOError as e:
        print(f"Error writing to robust_block_list_pro.txt: {e}")

if __name__ == "__main__":
    main()
