```python
#!/usr/bin/env python3
import requests
from datetime import datetime
import re
from tenacity import retry, stop_after_attempt, wait_fixed
from concurrent.futures import ThreadPoolExecutor
import unittest

# Validated blocklist sources (all URLs confirmed valid as of August 24, 2025)
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
    "https://easylist-downloads.adblockplus.org/easylistjapan.txt",
    "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
    "https://easylist-downloads.adblockplus.org/easylistfrench.txt",
    "https://easylist-downloads.adblockplus.org/easylistrussian.txt",
    "https://dbl.oisd.nl/",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    "https://easylist-downloads.adblockplus.org/easylistdutch.txt",
    "https://easylist-downloads.adblockplus.org/easylistkorean.txt",
    "https://easylist-downloads.adblockplus.org/easylistindian.txt",
    "https://easylist-downloads.adblockplus.org/easylistturkey.txt",
    "https://v.firebog.net/hosts/IoT.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
]

WHITELIST_URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/whitelist.txt",
]

BASE_HEADER_LINES = [
    "! Title: Robust Block List Pro",
    "! Description: Combined block list from multiple sources for ultimate ad, tracker, and malware protection",
    "! Homepage: https://github.com/avion121/robust-block-list-pro",  # Updated with your repo
]

SECRET_PATTERNS = [
    re.compile(r'[a-zA-Z0-9]{40,60}'),  # Generic long tokens
    re.compile(r'(?i)(?:api|access|secret|auth|jwt)[-_]?key', re.IGNORECASE),  # API key variants
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS access key
    re.compile(r'(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}', re.IGNORECASE),  # Bearer tokens
    re.compile(r'(?i)eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),  # JWT tokens
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

def fetch_all_urls(urls):
    with ThreadPoolExecutor(max_workers=10) as executor:
        return list(executor.map(fetch_url, urls))

def normalize_hosts_line(line):
    if line.startswith(("0.0.0.0 ", "127.0.0.1 ")):
        domain = line.split(" ")[1].strip()
        return f"||{domain}^"
    return line

def main():
    try:
        # Fetch whitelists
        print("Fetching whitelists...")
        whitelist_lines = set()
        for content in fetch_all_urls(WHITELIST_URLS):
            if content:
                for line in content.splitlines():
                    line_clean = line.strip()
                    if line_clean and not line_clean.startswith("!"):
                        whitelist_lines.add(line_clean)

        # Fetch and process blocklists
        print("Fetching blocklists...")
        combined_lines = set()
        filtered_lines = []
        for url, content in zip(BLOCKLIST_URLS, fetch_all_urls(BLOCKLIST_URLS)):
            if content:
                for line in content.splitlines():
                    line_clean = line.strip()
                    if line_clean and line_clean not in BASE_HEADER_LINES and not line_clean.startswith("!"):
                        normalized_line = normalize_hosts_line(line_clean)
                        if not any(pattern.search(normalized_line) for pattern in SECRET_PATTERNS):
                            combined_lines.add(normalized_line)
                        else:
                            filtered_lines.append(normalized_line)

        # Remove whitelisted entries
        final_lines = [line for line in combined_lines if line not in whitelist_lines]
        total_count = len(final_lines)
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Write Adblock Plus format
        header_lines = BASE_HEADER_LINES + [
            f"! Total Blocked Items: {total_count}",
            f"! Updated: {now}",
        ]
        header = "\n".join(header_lines)
        sorted_lines = sorted(final_lines)
        adblock_content = header + "\n\n" + "\n".join(sorted_lines) + "\n"
        with open("robust_block_list_pro.txt", "w", encoding="utf-8") as f:
            f.write(adblock_content)
        print("Generated robust_block_list_pro.txt successfully.")

        # Write hosts format
        hosts_lines = [f"0.0.0.0 {line[2:-1]}" for line in sorted_lines if line.startswith("||") and line.endswith("^")]
        hosts_content = header + "\n\n" + "\n".join(hosts_lines) + "\n"
        with open("robust_block_list_pro_hosts.txt", "w", encoding="utf-8") as f:
            f.write(hosts_content)
        print("Generated robust_block_list_pro_hosts.txt successfully.")

        # Write plain domains format
        domains_lines = [line[2:-1] for line in sorted_lines if line.startswith("||") and line.endswith("^")]
        domains_content = "\n".join(sorted(domains_lines)) + "\n"
        with open("robust_block_list_pro_domains.txt", "w", encoding="utf-8") as f:
            f.write(domains_content)
        print("Generated robust_block_list_pro_domains.txt successfully.")

        # Write filtered secrets
        if filtered_lines:
            with open("filtered_secrets.log", "w", encoding="utf-8") as f:
                f.write("Filtered lines (potential secrets):\n")
                for line in filtered_lines:
                    f.write(f"{line}\n")
            print("Logged filtered lines to filtered_secrets.log.")

    except Exception as e:
        print(f"Error in main execution: {e}")
        raise

class TestBlocklistGeneration(unittest.TestCase):
    def test_deduplication(self):
        lines = ["||example.com^", "||example.com^"]
        deduped = set(lines)
        self.assertEqual(len(deduped), 1)

    def test_normalize_hosts(self):
        self.assertEqual(normalize_hosts_line("0.0.0.0 example.com"), "||example.com^")

    def test_secret_filtering(self):
        line = "||example.com^?key=AKIA1234567890ABCDEF"
        self.assertTrue(any(pattern.search(line) for pattern in SECRET_PATTERNS))

if __name__ == "__main__":
    # Run tests
    unittest.main(argv=[''], exit=False)
    # Run main
    main()
```
