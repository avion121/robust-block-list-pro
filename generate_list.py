#!/usr/bin/env python3
"""
generate_list.py

Generates a single merged "Ultimate Robust Blocklist Pro" list containing:
 - adblock/filter rules (||domain^, element-hiding rules if present)
 - hosts entries (0.0.0.0 domain)
 - plain domain lines
 - comment lines with helpful tool/service links

Outputs:
 - ultimate_goat_merged.txt   <- single merged file with everything (deduped)
 - README.md
 - fetch_errors.log
"""

from __future__ import annotations
import requests
import datetime
import re
import time
import sys
from typing import Tuple, List, Set, Dict

# Output names
MERGED_OUTPUT = "ultimate_goat_merged.txt"
README = "README.md"
FETCH_LOG = "fetch_errors.log"

# Network / retry settings
REQUEST_TIMEOUT = 30
RETRY_COUNT = 2
RETRY_BACKOFF = 2  # seconds

# ----------------------------
# Sources (expanded, curated)
# ----------------------------
SOURCES: List[str] = [
    # Core ad/tracking/privacy filters (adblock-style)
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt",
    "https://filters.adtidy.org/extension/chromium/filters/1.txt",
    "https://filters.adtidy.org/extension/chromium/filters/14.txt",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",

    # Fanboy / annoyance / cookie / notifications
    "https://easylist-downloads.adblockplus.org/fanboy-annoyance.txt",
    "https://easylist-downloads.adblockplus.org/fanboy-social.txt",
    "https://easylist-downloads.adblockplus.org/fanboy-notifications.txt",
    "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",

    # Hosts-style / DNS-level lists
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
    "http://winhelp2002.mvps.org/hosts.txt",
    "https://someonewhocares.org/hosts/hosts",

    # Firebog (Prigent curated hosts)
    "https://v.firebog.net/hosts/Prigent-Ads.txt",
    "https://v.firebog.net/hosts/Prigent-Malware.txt",
    "https://v.firebog.net/hosts/Prigent-Crypto.txt",
    "https://v.firebog.net/hosts/AdguardDNS.txt",
    "https://v.firebog.net/hosts/Easyprivacy.txt",
    "https://v.firebog.net/hosts/Admiral.txt",

    # Blocklists and aggregators
    "https://big.oisd.nl/",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",

    # Coin-miner lists
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",

    # URLhaus / malware / phishing / ransomware
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://threatfox.abuse.ch/downloads/hostfile/",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",

    # CNAME/cloaked trackers
    "https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains",

    # Perflyst Pi-hole curated
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SessionReplay.txt",

    # BlocklistProject / developerDan lists
    "https://blocklistproject.github.io/Lists/ads.txt",
    "https://blocklistproject.github.io/Lists/tracking.txt",
    "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    "https://www.github.developerdan.com/hosts/lists/tracking-aggressive-extended.txt",

    # WindowsSpyBlocker telemetry
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",

    # HageZi (DNS blocklists collection)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",

    # AdGuard English filter
    "https://filters.adtidy.org/extension/chromium/filters/2.txt",

    # Misc historical / helpful lists
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt",
]

# ----------------------------
# Helper utilities
# ----------------------------
DOMAIN_RE = re.compile(r"(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}", re.IGNORECASE)

def normalize_line(line: str) -> str:
    l = line.strip()
    if l and "//" in l and not l.lower().startswith(("http://", "https://")):
        l = l.split("//", 1)[0].rstrip()
    l = re.sub(r"\s+", " ", l)
    return l

def is_text_content(headers: dict) -> bool:
    ct = headers.get("Content-Type", "")
    return "text" in ct.lower() or "html" in ct.lower() or ct == ""

def fetch_url(url: str, timeout: int = REQUEST_TIMEOUT) -> Tuple[str, str | None]:
    headers = {"User-Agent": "ultimate-robust-blocklist-pro/1.0 (+https://github.com/)"}
    last_err = None
    for attempt in range(RETRY_COUNT + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            r.raise_for_status()
            if not is_text_content(r.headers):
                if r.text.strip():
                    return r.text, None
                return "", f"{url} returned non-text Content-Type: {r.headers.get('Content-Type','')}"
            return r.text, None
        except Exception as e:
            last_err = f"{url} failed attempt {attempt+1}: {e}"
            if attempt < RETRY_COUNT:
                time.sleep(RETRY_BACKOFF * (attempt + 1))
    return "", last_err

def extract_lines_from_text(text: str) -> List[str]:
    lines = []
    for raw in text.splitlines():
        l = raw.strip()
        if not l:
            continue
        if l.lower().startswith(("last-modified", "etag", "<!doctype", "<html")):
            continue
        lines.append(l)
    return lines

# ----------------------------
# Generation
# ----------------------------
def generate_merged(sources: List[str]) -> Tuple[Dict[str,int], int, List[str]]:
    raw_set: Set[str] = set()
    fetch_summary: Dict[str,int] = {}
    errors: List[str] = []

    for src in sources:
        txt, err = fetch_url(src)
        if err:
            errors.append(f"[{datetime.datetime.utcnow().isoformat()}] {err}")
            fetch_summary[src] = 0
            continue

        added_before = len(raw_set)
        lines = extract_lines_from_text(txt)

        if src.rstrip("/").endswith("filterlists.com") or src.endswith("/"):
            comment_line = f"# SOURCE-DIR: {src}"
            raw_set.add(comment_line)
            fetch_summary[src] = 1
            continue

        for l in lines:
            n = normalize_line(l)
            if n.startswith("<"):
                for href in re.findall(r'href=["\']([^"\']+)["\']', n):
                    raw_set.add(f"# LINK: {href}")
                continue
            if n.lower().startswith(("readme", "#", "license")) or n.startswith("Project") or n.startswith("Usage"):
                raw_set.add("# " + n)
                continue
            if len(n) > 0:
                raw_set.add(n)
        fetch_summary[src] = max(0, len(raw_set) - added_before)

    # Metadata header for Brave/uBO/AdGuard recognition
    metadata_items = [
        "! Title: Ultimate Robust Blocklist Pro",
        "! Description: A single merged list of domains, hosts, and adblock rules from 59 curated sources.",
        "! Homepage: https://github.com/<your-repo>",
        "! License: MIT",
    ]

    # Custom header notes
    header_items = [
        f"# Ultimate Robust Blocklist Pro - generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "# This single merged file contains domains, hosts entries, adblock/filter rules, and helpful tool links.",
        "# NOTE: This file intentionally mixes rules and domains."
    ]

    final_lines = sorted(raw_set)

    with open(MERGED_OUTPUT, "w", encoding="utf-8") as fh:
        for m in metadata_items:
            fh.write(m + "\n")
        fh.write("\n")
        for h in header_items:
            fh.write(h + "\n")
        fh.write("\n")
        for line in final_lines:
            fh.write(line + "\n")

    return fetch_summary, len(final_lines), errors

def generate_readme(sources: List[str], fetch_summary: Dict[str,int], total_count: int) -> None:
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(README, "w", encoding="utf-8") as f:
        f.write("# Ultimate Robust Blocklist Pro\n\n")
        f.write(f"**Generated:** {now}\n\n")
        f.write("This repository contains one single merged file `ultimate_goat_merged.txt` that includes domains, hosts-format entries, adblock/filter rules, and helpful tool links.\n\n")
        f.write(f"- **Total unique lines in merged file:** {total_count}\n\n")
        f.write("## Sources included\n")
        for s in sources:
            f.write(f"- {s}\n")
        f.write("\n## Per-source fetch summary (this run)\n")
        for s, c in fetch_summary.items():
            f.write(f"- {s} -> {c} lines added\n")
        f.write("\n## Notes\n")
        f.write("- This single file intentionally mixes adblock rules and domain/host entries.\n")
        f.write("- For DNS-level blockers, rules may not apply directly.\n")
        f.write("- fetch_errors.log contains any fetch failures.\n")

def main() -> int:
    print("Starting generation of Ultimate Robust Blocklist Pro ...")
    summary, total, errors = generate_merged(SOURCES)
    print(f"Fetched {len(SOURCES)} sources, built merged list with {total} unique lines.")

    if errors:
        with open(FETCH_LOG, "w", encoding="utf-8") as fl:
            for e in errors:
                fl.write(e + "\n")
        print(f"Fetch errors written to {FETCH_LOG} ({len(errors)} entries).")
    else:
        open(FETCH_LOG, "w", encoding="utf-8").close()
        print("No fetch errors.")

    generate_readme(SOURCES, summary, total)
    print("Wrote README.md and merged output:", MERGED_OUTPUT)
    return 0

if __name__ == "__main__":
    try:
        rc = main()
        sys.exit(rc)
    except Exception as exc:
        with open(FETCH_LOG, "a", encoding="utf-8") as fl:
            fl.write(f"[{datetime.datetime.utcnow().isoformat()}] Unhandled error: {exc}\n")
        print("Unhandled error during generation:", exc)
        raise
