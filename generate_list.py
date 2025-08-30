#!/usr/bin/env python3
"""
generate_list.py
Fetch many canonical blocklist sources (adblock filters, hosts files, domain lists),
extract domain names robustly, deduplicate, and write a single combined file.

Output files:
- ultimate_goat_blocklist.txt
- README.md
- fetch_errors.log
"""

import requests
import datetime
import os
import re
from urllib.parse import urlparse

# ===============================
# Output file
# ===============================
COMBINED_OUTPUT = "ultimate_goat_blocklist.txt"
README = "README.md"
FETCH_LOG = "fetch_errors.log"

# ===============================
# Canonical TRUE ULTIMATE GOAT LIST sources (from conversation)
# Only include canonical list URLs that provide list content.
# ===============================
SOURCES = [
    # Peter Lowe (hosts-style)
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext",

    # EasyList family (ad + privacy)
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",

    # Fanboy / Annoyances (element hiding / social / cookie)
    "https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_international.txt",

    # uBlock/uAssets filters (uBlock-optimized filters & badware)
    "https://raw.githubusercontent.com/ublockorigin/uassets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",

    # AdGuard base (extension filter) and AdGuard SDNS for DNS-level
    "https://filters.adtidy.org/extension/chromium/filters/1.txt",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",

    # StevenBlack unified hosts
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",

    # NoCoin (cryptominer blocking)
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",

    # URLhaus hostfile (malicious hosts)
    "https://urlhaus.abuse.ch/downloads/hostfile/",

    # Spam404 / Ultimate-Hosts-Blacklist
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",

    # DandelionSprout Anti-Malware (AdGuard Home variant)
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt",

    # Disconnect's simple lists (ads/tracking/malvertising)
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt"
]

# ===============================
# Helpers: domain extraction
# ===============================
DOMAIN_RE = re.compile(r"(?:[a-z0-9\-]{1,63}\.)+[a-z]{2,63}", re.IGNORECASE)

def extract_domains_from_line(line):
    """
    Given an arbitrary line from a hosts/filter/list file, return a set of candidate domains.
    Handles hosts entries (0.0.0.0 domain), adblock rules (||domain^), plain domains, URLs.
    """
    domains = set()
    line = line.strip()

    # Remove inline comments common in adblock lists
    if "//" in line:
        # keep single-line 'http' urls intact but strip trailing '//' comments common in some lists
        # only split when `//` is not part of a URL (i.e., when not preceded by http:)
        if not line.lower().startswith(("http://", "https://")):
            line = line.split("//", 1)[0].strip()

    # Hosts format: "0.0.0.0 example.com" or "127.0.0.1 example.com"
    if line.startswith(("0.0.0.0", "127.0.0.1")):
        parts = line.split()
        if len(parts) >= 2:
            candidate = parts[1].lstrip(".").lower()
            if candidate:
                domains.add(candidate)
        return domains

    # Adblock style: ||domain^ or ||domain^$third-party
    if line.startswith("||"):
        # strip leading || and trailing options like ^ and $...
        core = line[2:]
        core = core.split("^", 1)[0]
        core = core.split("/", 1)[0]
        core = core.lstrip(".").lower()
        if core:
            domains.add(core)
        return domains

    # Adblock domain-style or domain-only line (like ".example.com" or "example.com")
    # Also handle wildcard entries like "*.example.com" by removing wildcard and leading dots.
    cleaned = line.lstrip("*.").lstrip(".").lower()
    # If it's a simple word with spaces, skip (we'll try to find domain tokens)
    if " " not in cleaned and "/" not in cleaned and "@" not in cleaned and "(" not in cleaned:
        # keep only if contains a dot (simple domain)
        if "." in cleaned and len(cleaned) < 253:
            # trim any trailing punctuation
            candidate = cleaned.strip(" ,;\"'()[]{}<>")
            if DOMAIN_RE.search(candidate):
                domains.add(candidate)
            return domains

    # Fallback: find any domain-like tokens in the line
    for match in DOMAIN_RE.findall(line):
        d = match.lower().strip(".")
        if d:
            domains.add(d)

    return domains

# ===============================
# Fetch utility
# ===============================
def fetch_list(url, timeout=30):
    try:
        headers = {
            "User-Agent": "ultimate-goat-blocklist-generator/1.0 (+https://github.com/)"
        }
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        text = r.text
        domains = set()
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            # Skip obvious comments/metadata lines
            if line.startswith(("#", "!", "@@", "[", "Disclaimer", "Last-Modified", "ETag")):
                continue
            # Extract domains from line robustly
            for d in extract_domains_from_line(line):
                # normalize: remove leading www. and leading dots
                d = d.lstrip(".")
                if d.startswith("www."):
                    d = d[4:]
                # skip purely IP addresses and single-label tokens
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
                    continue
                if len(d) < 4 or d.count(".") < 1:
                    continue
                domains.add(d)
        return domains, None
    except Exception as e:
        return set(), f"{url} failed: {e}"

# ===============================
# Generation
# ===============================
def generate_combined(sources, output_file):
    all_domains = set()
    fetch_summary = {}
    errors = []

    for url in sources:
        dset, err = fetch_list(url)
        fetch_summary[url] = len(dset)
        if err:
            errors.append(f"[{datetime.datetime.utcnow().isoformat()}] {err}")
        all_domains.update(dset)

    # final cleanup: remove obvious aggregator domains that might be list hosts (optional)
    # (kept minimal: we do not remove anything automatically)

    # write combined file
    with open(output_file, "w", encoding="utf-8") as f:
        for dom in sorted(all_domains):
            f.write(dom + "\n")

    return fetch_summary, len(all_domains), errors

# ===============================
# README
# ===============================
def generate_readme(sources, fetch_summary, total_count):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(README, "w", encoding="utf-8") as f:
        f.write("# Ultimate GOAT Blocklist\n\n")
        f.write(f"**Last updated:** {now}\n\n")
        f.write(f"- **Combined domains:** {total_count}\n\n")
        f.write("This repository contains a single, canonical combined blocklist assembled from the community-maintained sources listed below. The generator extracts domains from hosts files, adblock-style lists, and plain domain lists, deduplicates them, and writes a sorted domain list `ultimate_goat_blocklist.txt`.\n\n")
        f.write("## Sources (canonical)\n")
        for s in sources:
            f.write(f"- {s}\n")
        f.write("\n## Notes\n")
        f.write("- This file is intended for DNS-level or hostfile-based blocking (Pi-hole, AdGuard Home, /etc/hosts conversions, etc.).\n")
        f.write("- If you plan to use this inside adblock extensions, prefer the original EasyList/EasyPrivacy/uBlock filters for best compatibility (those lists include element-hiding and special rules which are not preserved in this domain-only extraction).\n")
        f.write("- If a fetch fails you can inspect `fetch_errors.log` which is committed by the workflow.\n")

# ===============================
# Main
# ===============================
if __name__ == "__main__":
    print("Starting fetch of canonical GOAT sources...")
    summary, total, errors = generate_combined(SOURCES, COMBINED_OUTPUT)
    print(f"Fetched {len(SOURCES)} sources, extracted {total} unique domains.")

    # write fetch errors
    if errors:
        with open(FETCH_LOG, "w", encoding="utf-8") as fl:
            for e in errors:
                fl.write(e + "\n")
        print(f"Fetch errors written to {FETCH_LOG} ({len(errors)} errors).")
    else:
        # ensure empty log is present (so workflow can commit it)
        open(FETCH_LOG, "w", encoding="utf-8").close()
        print("No fetch errors.")

    # generate README
    generate_readme(SOURCES, summary, total)
    print("Wrote README.md and combined blocklist:", COMBINED_OUTPUT)
