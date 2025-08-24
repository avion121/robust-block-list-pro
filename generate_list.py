#!/usr/bin/env python3
"""
generate_list.py

Enhanced aggregator for Robust Block List Pro
- Parallel fetching with retries and caching
- Normalizes into three outputs: hosts, adblock (filters), ips
- Safer secret detection (redacts raw strings, writes hashed references to suspected_secrets.txt)
- Writes per-source attribution (SOURCES.md) and logs errors
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import json
import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ----------------------- Configuration -----------------------
CACHE_DIR = Path('.cache_fetch')
CACHE_TTL = timedelta(hours=6)  # do not re-fetch within 6 hours if cached
CACHE_DIR.mkdir(exist_ok=True)

OUTPUT_HOSTS = Path('robust_block_list_pro.hosts')
OUTPUT_ADBLOCK = Path('robust_block_list_pro.adblock.txt')
OUTPUT_IPS = Path('robust_block_list_pro.ips.txt')
OUTPUT_MERGED = Path('robust_block_list_pro.txt')
SOURCES_MD = Path('SOURCES.md')
ERROR_LOG = Path('errors.log')
SUSPECTED_SECRETS = Path('suspected_secrets.txt')

USER_AGENT = 'RobustBlockListPro/1.0 (+https://github.com/your/repo)'
MAX_WORKERS = 8

# ----------------------- URLs (expanded with recommended additions) -----------------------
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
    "https://raw.githubusercontent.com/CoinBlocker/CoinBlockerLists/master/hosts",
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

    # ----------------- Added high-value feeds -----------------
    # Spamhaus DROP (IP ranges)
    "https://www.spamhaus.org/drop/drop.txt",

    # Firebog hub (discover curated picks) — grab specific raw lists
    "https://v.firebog.net/hosts/lists.php",

    # OISD (choose big/small aggregated hosts) — direct download examples
    "https://oisd.nl/downloads/hosts/oisd-blocklist.txt",

    # DShield (attacking IPs)
    "https://feeds.dshield.org/block.txt",

    # MVPS hosts (classic)
    "https://winhelp2002.mvps.org/hosts.txt",

    # AdAway hosts
    "https://adaway.org/hosts.txt",

    # PhishTank / OpenPhish pointers (some require API access — included as guidance)
    # Note: PhishTank & OpenPhish provide API or downloadable feeds — check their sites for exact URLs and API keys
]

# ----------------------- Patterns for secret detection (conservative) -----------------------
SECRET_PATTERNS = [
    re.compile(r'ghp_[A-Za-z0-9]{36}'),           # GitHub personal access token
    re.compile(r'gho_[A-Za-z0-9]{36}'),
    re.compile(r'ghs_[A-Za-z0-9]{36}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),              # AWS Access Key ID
    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),       # Google API key (common prefix)
    re.compile(r'xox[baprs]-[A-Za-z0-9-]+'),      # Slack tokens
    re.compile(r'(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{16,}'),  # generic api key patterns
]

# Less aggressive heuristics for things that look like long secrets
LONG_HEX = re.compile(r'\b[0-9a-fA-F]{32,}\b')

# ----------------------- Helpers -----------------------

session = requests.Session()
retries = Retry(total=3, backoff_factor=0.6, status_forcelist=[429,500,502,503,504])
session.mount('https://', HTTPAdapter(max_retries=retries))
session.headers.update({'User-Agent': USER_AGENT})

ERROR_LOG.write_text('')
SUSPECTED_SECRETS.write_text('')


def cache_path_for(url: str) -> Path:
    name = hashlib.sha1(url.encode()).hexdigest() + '.cache'
    return CACHE_DIR / name


def load_from_cache(url: str):
    p = cache_path_for(url)
    if p.exists():
        try:
            meta = json.loads(p.read_text(encoding='utf-8'))
            ts = datetime.fromisoformat(meta.get('fetched'))
            if datetime.utcnow() - ts < CACHE_TTL:
                return meta.get('content', '')
        except Exception:
            pass
    return None


def save_to_cache(url: str, content: str):
    p = cache_path_for(url)
    meta = {'fetched': datetime.utcnow().isoformat(), 'content': content}
    p.write_text(json.dumps(meta), encoding='utf-8')


def fetch_url(url: str):
    # Try cache first
    cached = load_from_cache(url)
    if cached is not None:
        return cached

    try:
        r = session.get(url, timeout=15)
        r.raise_for_status()
        text = r.text
        save_to_cache(url, text)
        return text
    except Exception as e:
        # log concise error (no content)
        with ERROR_LOG.open('a', encoding='utf-8') as ef:
            ef.write(f"[{datetime.utcnow().isoformat()}] Error fetching {url}: {e}\n")
        return ''


# Normalizers: detect and convert lines into categories
HOSTS_IP_PATTERN = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+(.+)$')
IP_CIDR = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$')
ADBLOCK_SIGNS = re.compile(r'[\*\^\|@\$]')  # crude: adblock syntactic chars exist
DOMAIN_EXTRACT = re.compile(r'([A-Za-z0-9.-]+\.[A-Za-z]{2,63})')


def normalize_and_classify_line(line: str):
    """Return tuple (category, normalized_line)
    category in ('hosts', 'adblock', 'ip', 'other', None)
    """
    s = line.strip()
    if not s or s.startswith('!') or s.startswith('#') or s.startswith('//'):
        return None, None

    # Hosts lines like "0.0.0.0 domain" or "127.0.0.1 domain"
    m = HOSTS_IP_PATTERN.match(s)
    if m:
        domain = m.group(1).split()[0]
        # sanitize domain
        d = domain.strip().lower()
        if d:
            return 'hosts', f'0.0.0.0 {d}'

    # Plain host-only lines from some lists (just domain)
    mdom = DOMAIN_EXTRACT.search(s)
    if mdom and not ADBLOCK_SIGNS.search(s):
        dom = mdom.group(1).lower()
        return 'hosts', f'0.0.0.0 {dom}'

    # IP / CIDR lines
    if IP_CIDR.match(s):
        return 'ip', s

    # adblock-like lines (contain adblock special characters) or start with || or @@ or /regex/
    if s.startswith('||') or s.startswith('@@') or s.startswith('/') or ADBLOCK_SIGNS.search(s):
        return 'adblock', s

    # fallback: classify as other
    return 'other', s


# Secret handling

def hash_redact(raw: str) -> str:
    h = hashlib.sha256(raw.encode()).hexdigest()
    return f'[REDACTED-SHA256:{h}]'


# Main aggregator

def main():
    hosts_set = set()
    adblock_set = set()
    ips_set = set()
    other_set = set()
    sources_used = []
    suspected = []

    # Parallel fetch
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(fetch_url, url): url for url in URLS}
        for fut in as_completed(futures):
            url = futures[fut]
            content = ''
            try:
                content = fut.result()
            except Exception as e:
                with ERROR_LOG.open('a', encoding='utf-8') as ef:
                    ef.write(f"[{datetime.utcnow().isoformat()}] Exception fetching {url}: {e}\n")
                continue

            if not content:
                continue

            sources_used.append(url)
            for line in content.splitlines():
                cat, norm = normalize_and_classify_line(line)
                if not cat:
                    continue

                # secret detection
                found_secret = False
                for pat in SECRET_PATTERNS:
                    if pat.search(line):
                        found_secret = True
                        break
                if not found_secret and LONG_HEX.search(line):
                    found_secret = True

                if found_secret:
                    # write hashed redaction to suspected file (do not leak raw content)
                    with SUSPECTED_SECRETS.open('a', encoding='utf-8') as sf:
                        sf.write(hash_redact(line) + '\n')
                    suspected.append(line)
                    continue

                if cat == 'hosts':
                    hosts_set.add(norm)
                elif cat == 'adblock':
                    adblock_set.add(norm)
                elif cat == 'ip':
                    ips_set.add(norm)
                else:
                    other_set.add(norm)

    # Whitelist: minimal example — allowlist core services (prevent accidental blocking)
    WHITELIST = {'github.com', 'raw.githubusercontent.com', 'easylist.to', 'adguard.com'}
    hosts_set = {h for h in hosts_set if not any(w in h for w in WHITELIST)}

    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    # Header
    header_lines = [
        '! Title: Robust Block List Pro',
        '! Description: Combined block list from multiple sources (hosts/adblock/ips outputs)',
        f'! Total unique hosts: {len(hosts_set)}',
        f'! Total unique adblock rules: {len(adblock_set)}',
        f'! Total unique ips/cidrs: {len(ips_set)}',
        f'! Generated: {now}',
    ]
    header = '\n'.join(header_lines) + '\n\n'

    # Write outputs
    try:
        OUTPUT_HOSTS.write_text(header + '\n'.join(sorted(hosts_set)) + '\n', encoding='utf-8')
        OUTPUT_ADBLOCK.write_text(header + '\n'.join(sorted(adblock_set)) + '\n', encoding='utf-8')
        OUTPUT_IPS.write_text(header + '\n'.join(sorted(ips_set)) + '\n', encoding='utf-8')

        # merged: adblock (primary) then hosts as fallback (note: merged may be huge)
        merged_content = header + '\n'.join(sorted(adblock_set)) + '\n\n' + '\n'.join(sorted(hosts_set)) + '\n'
        OUTPUT_MERGED.write_text(merged_content, encoding='utf-8')

        # SOURCES.md
        src_header = '# SOURCES\n\nThis file lists the source URLs fetched when generating the block lists.\n\n'
        src_lines = [f'- {u}' for u in sorted(set(sources_used))]
        SOURCES_MD.write_text(src_header + '\n'.join(src_lines) + '\n', encoding='utf-8')

    except Exception as e:
        with ERROR_LOG.open('a', encoding='utf-8') as ef:
            ef.write(f"[{datetime.utcnow().isoformat()}] Error writing outputs: {e}\n")

    # Summary to stdout (no raw secrets)
    print(f"Generated outputs:\n - {OUTPUT_HOSTS}\n - {OUTPUT_ADBLOCK}\n - {OUTPUT_IPS}\n - {OUTPUT_MERGED}")
    print(f"Sources fetched: {len(sources_used)}")
    print(f"Suspected secrets found (redacted SHA256 written to {SUSPECTED_SECRETS}): {len(suspected)}")
    print(f"Errors logged to {ERROR_LOG}")


if __name__ == '__main__':
    main()
