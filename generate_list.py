#!/usr/bin/env python3
"""
generate_list.py — final exhaustive generator

Produces:
 - robust_block_list_pro_combined.txt  (hosts-format 0.0.0.0 <domain>)
 - fetch_meta.json
 - README.md
 - CHANGELOG.md
 - fetch_errors.log

This file includes every source mentioned across the conversation.
"""
import os
import re
import json
import requests
from datetime import datetime

# Outputs
COMBINED_FILE = "robust_block_list_pro_combined.txt"
META_FILE = "fetch_meta.json"
README_FILE = "README.md"
CHANGELOG_FILE = "CHANGELOG.md"
FETCH_ERRORS_LOG = "fetch_errors.log"

# --------------------
# Exhaustive SOURCES list (all lists mentioned in the conversation)
# Includes hosts-format files, ABP-style filter lists, curated registries & mirrors.
# --------------------
SOURCES = [
    # EasyList family (browser filters)
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://easylist.to/easylist/easylist_cookie/easylist_cookie_general_block.txt",

    # Fanboy annoyance variants
    "https://secure.fanboy.co.nz/fanboy-annoyance_ubo.txt",
    "https://easylist.to/easylist/fanboy-annoyance.txt",

    # Cookie / consent overlays
    "https://prebake.eu/",

    # Anti-cryptominer
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",

    # DandelionSprout (legitimate URL shortener, anti-malware)
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",

    # Community uBO filters / combined lists
    "https://raw.githubusercontent.com/LanikSJ/ubo-filters/master/filters/combined-filters.txt",
    "https://raw.githubusercontent.com/hl2guide/All-in-One-Customized-Adblock-List/master/adfilters_urls.txt",

    # Classic hosts & aggregators
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",  # Peter Lowe
    "http://someonewhocares.org/hosts/hosts",  # SomeoneWhoCares / Dan Pollock
    "https://winhelp2002.mvps.org/hosts.txt",  # MVPS hosts
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",  # AnudeepND
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",  # Frogeye first-party trackers

    # OISD (big/dbl/hosts)
    "https://big.oisd.nl/",
    "https://dbl.oisd.nl/",
    "https://hosts.oisd.nl/",

    # Firebog curated hosts (green/curated picks + EasyList-hosts mirror)
    "https://v.firebog.net/hosts/Prigent-Ads.txt",
    "https://v.firebog.net/hosts/Easyprivacy.txt",
    "https://v.firebog.net/hosts/AdguardDNS.txt",
    "https://v.firebog.net/hosts/RPiList-Malware.txt",
    "https://v.firebog.net/hosts/Easylist.txt",

    # Hagezi / HaGeZi aggregated tiers (pro / pro.plus / tif)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",

    # Security / phishing / malware feeds
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://www.spamhaus.org/drop/drop.txt",

    # AdGuard & related registries / SDNS
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/master/assets/filter_9.txt",

    # Catalogs / tools referenced (best-effort fetch may be HTML)
    "https://filterlists.com/",
    "https://justdomains.github.io/blocklists/",
    "https://v.firebog.net/",
]

# --------------------
# Whitelist sources (domains to exclude)
# These mirror what we discussed (uBlock unbreak, anudeep whitelist, Dandelion legitimate shorteners, ADTidy allowlist)
# --------------------
WHITELISTS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
    "https://filters.adtidy.org/extension/ublock/filters/17.txt",
]

# --------------------
# Parsing helpers
# --------------------
DOMAIN_RE = re.compile(r"(?:\|\|)?([a-z0-9\-._]{1,256}\.[a-z]{2,})(?=[\^/:,;\s]|$)", re.IGNORECASE)
GENERIC_DOMAIN_RE = re.compile(r"([a-z0-9\-._]{1,256}\.[a-z]{2,})", re.IGNORECASE)

def is_valid_domain(s: str) -> bool:
    if not s:
        return False
    s = s.strip().lower().strip(".")
    if " " in s or "/" in s or ":" in s:
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
        return False
    if s.count(".") < 1:
        return False
    if not re.match(r"^[a-z0-9\-.]+$", s):
        return False
    if len(s) < 4 or len(s) > 253:
        return False
    return True

def fetch_url_lines(url: str, errors: list) -> list:
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "robust-block-list-pro/1.0"})
        if r.status_code == 200 and r.text:
            return r.text.splitlines()
        errors.append(f"{url} => HTTP {r.status_code}")
    except Exception as e:
        errors.append(f"{url} => {repr(e)}")
    return []

def extract_domains_from_lines(lines: list) -> set:
    domains = set()
    for raw in lines:
        if not raw:
            continue
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue

        # hosts-format entries
        if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
            parts = line.split()
            if len(parts) >= 2:
                cand = parts[1].strip().lower().strip(".")
                if is_valid_domain(cand):
                    domains.add(cand)
                    continue

        # if the line *is* a plain domain
        if is_valid_domain(line):
            domains.add(line.lower())
            continue

        # ABP/Adblock syntax match (||example.com^)
        m = DOMAIN_RE.search(line)
        if m:
            cand = m.group(1).lower().strip().strip(".")
            if is_valid_domain(cand):
                domains.add(cand)
                continue

        # fallback: find any domain-like tokens
        for m2 in GENERIC_DOMAIN_RE.findall(line):
            cand = m2.lower().strip().strip(".")
            if is_valid_domain(cand):
                domains.add(cand)
    return domains

def fetch_and_extract(urls: list, errors: list) -> set:
    combined = set()
    for u in urls:
        lines = fetch_url_lines(u, errors)
        if not lines:
            continue
        doms = extract_domains_from_lines(lines)
        if doms:
            combined.update(doms)
    return combined

def write_errors(errors: list):
    if not errors:
        try:
            if os.path.exists(FETCH_ERRORS_LOG):
                os.remove(FETCH_ERRORS_LOG)
        except Exception:
            pass
        return
    with open(FETCH_ERRORS_LOG, "w", encoding="utf-8") as fh:
        for e in errors:
            fh.write(e + "\n")

# --------------------
# Main
# --------------------
def main():
    errors = []

    # fetch whitelist first
    whitelist = fetch_and_extract(WHITELISTS, errors)

    # fetch all sources
    all_domains = fetch_and_extract(SOURCES, errors)

    # remove whitelisted domains
    final = sorted(d for d in all_domains if d not in whitelist)

    # write combined hosts-format
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(COMBINED_FILE, "w", encoding="utf-8") as fh:
        fh.write(f"# Generated combined block list\n")
        fh.write(f"# Generated: {now}\n")
        fh.write(f"# Source count: {len(SOURCES)}\n\n")
        for dom in final:
            fh.write(f"0.0.0.0 {dom}\n")

    # metadata
    meta = {
        "combined_count": len(final),
        "source_count": len(SOURCES),
        "whitelist_count": len(whitelist),
        "last_updated": now
    }
    with open(META_FILE, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    # README
    readme = f"""# 🚀 Robust Block List Pro — Combined

Single combined hosts-format blocklist generated from the full set of sources
discussed in the repository's conversation.

- Combined file: {COMBINED_FILE}
- Entries: {meta['combined_count']:,}
- Last updated (UTC): {meta['last_updated']}

Sources included: EasyList, EasyPrivacy, EasyList Cookie, Fanboy (uBO & easylist),
Prebake, NoCoin, DandelionSprout (LegitURLShortener & Anti-Malware),
LanikSJ uBO filters, HL2Guide, StevenBlack, Peter Lowe (pgl.yoyo),
SomeoneWhoCares (Dan Pollock), MVPS hosts, AnudeepND, Frogeye firstparty trackers,
AdAway, OISD (big/dbl/hosts), Firebog curated hosts (Prigent-Ads, Easyprivacy,
AdguardDNS, RPiList-Malware, Easylist mirror), Hagezi aggregated tiers,
Phishing Army, Disconnect (tracking/ad), blocklistproject (malware/phishing),
Ultimate Hosts Blacklist, URLhaus, Spamhaus DROP, AdGuard SDNS & HostlistsRegistry,
plus catalog references (FilterLists, JustDomains, Firebog).

Usage: use the raw GitHub URL for Pi-hole / AdGuard Home / AdAway:
https://raw.githubusercontent.com/<USER>/<REPO>/main/{COMBINED_FILE}

Notes:
- This extracts domains from ABP-style filters and hosts files best-effort.
- If you encounter breakage, expand the WHITELISTS array or remove specific sources.
"""
    with open(README_FILE, "w", encoding="utf-8") as fh:
        fh.write(readme)

    # changelog
    entry = f"- {meta['last_updated']}: Combined entries = {meta['combined_count']:,}\n"
    if not os.path.exists(CHANGELOG_FILE):
        with open(CHANGELOG_FILE, "w", encoding="utf-8") as fh:
            fh.write("# 📜 Changelog\n\nDaily auto-generated update log.\n\n")
            fh.write(entry)
    else:
        with open(CHANGELOG_FILE, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        header = lines[:3] if len(lines) >= 3 else lines[:0]
        entries = (lines[3:] if len(lines) >= 3 else lines) + [entry]
        entries = entries[-30:]
        with open(CHANGELOG_FILE, "w", encoding="utf-8") as fh:
            fh.writelines(header + entries)

    # write errors if any
    write_errors(errors)

    print(f"Generated {COMBINED_FILE} with {meta['combined_count']} entries")
    if errors:
        print(f"Encountered {len(errors)} fetch errors; see {FETCH_ERRORS_LOG}")

if __name__ == "__main__":
    main()
