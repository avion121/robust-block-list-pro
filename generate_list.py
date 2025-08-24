#!/usr/bin/env python3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import re
import requests
from tenacity import retry, stop_after_attempt, wait_fixed
import unittest

# Force plain text (avoid gzip decoding issues) and be a polite client
HEADERS = {
    "User-Agent": "robust-block-list-pro/1.0 (+https://github.com/avion121/robust-block-list-pro)",
    "Accept-Encoding": "identity",
}

# Curated, stable sources (as of Aug 24, 2025)
# Removed dead/fragile ones; trimmed IP/CIDR sets that don't map to Adblock/hosts
BLOCKLIST_URLS = [
    # Core ad & privacy
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",

    # Fanboy extras
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://easylist-downloads.adblockplus.org/fanboy-social.txt",
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",

    # Crypto miners
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",

    # Hosts-format sources
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",

    # Security-focused (domains/ABP)
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",

    # Hagezi (well-maintained DNS/adblock lists)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",

    # Regional EasyList examples that are currently reachable
    "https://easylist-downloads.adblockplus.org/easylistgermany.txt",
    "https://easylist-downloads.adblockplus.org/indianlist%2Beasylist.txt",  # combined example
]

WHITELIST_URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    # The former KADhosts whitelist.txt is not available anymore; omitted on purpose.
]

BASE_HEADER_LINES = [
    "! Title: Robust Block List Pro",
    "! Description: Combined block list from multiple sources for ultimate ad, tracker, and malware protection",
    "! Homepage: https://github.com/avion121/robust-block-list-pro",
]

SECRET_PATTERNS = [
    re.compile(r'[a-zA-Z0-9]{40,60}'),
    re.compile(r'(?i)(?:api|access|secret|auth|jwt)[-_]?key'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}'),
    re.compile(r'(?i)eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
]

DOMAIN_RE = re.compile(r'^\|\|([a-z0-9\-._*]+)\^$')
HOST_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-.]+)$')
IP_OR_CIDR_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$|^[0-9a-fA-F:]+(?:/\d{1,3})?$')

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def fetch_url(url: str) -> str:
    try:
        r = requests.get(url, headers=HEADERS, timeout=30, allow_redirects=True)
        r.raise_for_status()
        return r.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return ""

def fetch_all_urls(urls):
    with ThreadPoolExecutor(max_workers=10) as ex:
        return list(ex.map(fetch_url, urls))

def normalize_hosts_line(line: str) -> str:
    """Convert hosts line to Adblock domain rule, pass-through ABP lines, and ignore IP/CIDR noise."""
    s = line.strip()
    if not s or s.startswith(("!", "#", "[")):
        return ""
    # Skip obvious IP/CIDR rows (e.g., from ipsets)
    if IP_OR_CIDR_RE.match(s):
        return ""
    m = HOST_RE.match(s)
    if m:
        return f"||{m.group(1).strip()}^"
    # keep adblock-style domain rule
    if DOMAIN_RE.match(s):
        return s
    # Ignore non-domain filter syntax (selectors, scriptlets, etc.)
    return ""

def main():
    try:
        # 1) Fetch whitelists
        print("Fetching whitelists...")
        whitelist_lines = set()
        for content in fetch_all_urls(WHITELIST_URLS):
            if not content:
                continue
            for line in content.splitlines():
                s = line.strip()
                if s and not s.startswith(("!", "#")):
                    whitelist_lines.add(s)

        # 2) Fetch blocklists and build combined set
        print("Fetching blocklists...")
        combined = set()
        filtered_secret_lines = []

        for url, content in zip(BLOCKLIST_URLS, fetch_all_urls(BLOCKLIST_URLS)):
            if not content:
                continue
            for raw in content.splitlines():
                norm = normalize_hosts_line(raw)
                if not norm:
                    continue
                if any(p.search(norm) for p in SECRET_PATTERNS):
                    filtered_secret_lines.append(norm)
                    continue
                combined.add(norm)

        # 3) Apply whitelist (string exact match for adblock lines)
        final_lines = [line for line in combined if line not in whitelist_lines]
        total = len(final_lines)
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # 4) Write Adblock Plus format
        header = "\n".join(BASE_HEADER_LINES + [
            f"! Total Blocked Items: {total}",
            f"! Updated: {now}",
        ])
        sorted_abp = sorted(final_lines)
        with open("robust_block_list_pro.txt", "w", encoding="utf-8") as f:
            f.write(header + "\n\n" + "\n".join(sorted_abp) + "\n")
        print("Generated robust_block_list_pro.txt successfully.")

        # 5) Write hosts format
        hosts_lines = [f"0.0.0.0 {DOMAIN_RE.match(x).group(1)}"
                       for x in sorted_abp if DOMAIN_RE.match(x)]
        with open("robust_block_list_pro_hosts.txt", "w", encoding="utf-8") as f:
            f.write(header + "\n\n" + "\n".join(hosts_lines) + "\n")
        print("Generated robust_block_list_pro_hosts.txt successfully.")

        # 6) Write plain domains format
        domain_only = [DOMAIN_RE.match(x).group(1) for x in sorted_abp if DOMAIN_RE.match(x)]
        with open("robust_block_list_pro_domains.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(domain_only)) + "\n")
        print("Generated robust_block_list_pro_domains.txt successfully.")

        # 7) Write filtered potential secrets (rare)
        if filtered_secret_lines:
            with open("filtered_secrets.log", "w", encoding="utf-8") as f:
                f.write("Filtered lines (potential secrets):\n")
                for line in filtered_secret_lines:
                    f.write(line + "\n")
            print("Logged filtered lines to filtered_secrets.log.")

    except Exception as e:
        print(f"Error in main execution: {e}")
        raise

# --- tiny tests
class TestBlocklistGeneration(unittest.TestCase):
    def test_dedup(self):
        lines = ["||example.com^", "||example.com^"]
        self.assertEqual(len(set(lines)), 1)

    def test_hosts_normalize(self):
        self.assertEqual(normalize_hosts_line("0.0.0.0 example.com"), "||example.com^")

    def test_skip_ipset(self):
        self.assertEqual(normalize_hosts_line("1.2.3.0/24"), "")

    def test_secret_filter(self):
        suspicious = "||example.com^?key=AKIA1234567890ABCDEF"
        self.assertTrue(any(p.search(suspicious) for p in SECRET_PATTERNS))

if __name__ == "__main__":
    unittest.main(argv=[""], exit=False)
    main()
