#!/usr/bin/env python3
import requests
from datetime import datetime
import re

# List of block list sources (core + vetted GOAT additions)
URLS = [
    # uBlock Origin core filters
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/privacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/quick-fixes.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/unbreak.txt",

    # EasyList & EasyPrivacy
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",

    # Abuse.ch & Feodo Tracker
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",

    # Ad servers & hosts
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/alternates/fakenews-gambling/hosts",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",

    # Phishing & malware
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt",

    # Fanboy & Spyware
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/refs/heads/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",

    # Resource abuse & anti-adblock
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/resource-abuse.txt",
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
    "https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt",

    # CoinMiner & Anti-Coin
    "https://zerodot1.gitlab.io/CoinBlockerLists/list.txt",
    "https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/hosts",
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",

    # Other anti-adblock
    "https://raw.githubusercontent.com/bogachenko/fuck-anti-adblock/master/fuck-anti-adblock.txt",

    # Adguard filters
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_AntiAnnoyances/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_Mobile/filter.txt",

    # SmartTV & IoT
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
    "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",

    # Tracking & Privacy Badger
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://raw.githubusercontent.com/EFForg/privacybadger/master/data/trackers.txt",

    # Regional lists
    "https://raw.githubusercontent.com/easylist/easylistjapan/master/easylistjapan.txt",
    "https://raw.githubusercontent.com/ABPindo/indonesianadblockfilters/master/subscriptions/indonesian-list.txt",
    "https://raw.githubusercontent.com/AdnanHussain/ArabList/master/ArabList.txt",
    "https://easylist.to/easylist/easylistgermany.txt",

    # --- Vetted Supplemental GOAT Additions ---
    # Host-based ad & tracker blocks
    "https://hosts-file.net/ad_servers.txt",
    "https://v.firebog.net/hosts/Easyprivacy.txt",

    # Language/region-specific EasyLists
    "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
    "https://easylist-downloads.adblockplus.org/easylistfrench.txt",
    "https://easylist-downloads.adblockplus.org/easylistrussian.txt",

    # AdGuard Chinese ad server filters
    "https://filters.adtidy.org/extension/chromium/filters/224.txt",

    # Cookie pop-ups
    "https://easylist-downloads.adblockplus.org/cookiemonster.txt",

    # FireHOL IP blocklists
    "https://raw.githubusercontent.com/ktsaou/blocklists/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/ktsaou/blocklists/master/firehol_level2.netset",
    "https://raw.githubusercontent.com/ktsaou/blocklists/master/firehol_level3.netset",

    # Family & child-safe hosts
    "https://someonewhocares.org/hosts/hosts",

    # --- Additional GOAT Enhancements ---
    "https://dbl.oisd.nl/",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
    "https://talosintelligence.com/documents/ip-blacklist",
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
    "https://www.i-dont-care-about-cookies.eu/abp/",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "http://winhelp2002.mvps.org/hosts.txt"
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
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return ""

def main():
    combined_lines = set()
    filtered_lines = []

    for url in URLS:
        print(f"Fetching: {url}")
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line_clean = line.strip()
                if line_clean and line_clean not in BASE_HEADER_LINES:
                    if not any(pattern.search(line_clean) for pattern in SECRET_PATTERNS):
                        combined_lines.add(line_clean)
                    else:
                        filtered_lines.append(line_clean)

    total_count = len(combined_lines)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    header_lines = BASE_HEADER_LINES + [
        f"! Total Blocked Items: {total_count}",
        f"! Updated: {now}"
    ]
    header = "\n".join(header_lines)
    sorted_lines = sorted(combined_lines)
    final_content = header + "\n\n" + "\n".join(sorted_lines) + "\n"

    try:
        with open("robust_block_list_pro.txt", "w", encoding="utf-8") as f:
            f.write(final_content)
        print("List generated successfully.")
    except IOError as e:
        print(f"Error writing to file: {e}")

    if filtered_lines:
        print("Filtered lines (potential secrets):")
        for line in filtered_lines:
            print(line)

if __name__ == "__main__":
    main()
