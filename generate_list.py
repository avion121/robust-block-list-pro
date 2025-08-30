#!/usr/bin/env python3
"""
generate_list.py

Generates a single merged "ULTIMATE GOAT" list containing:
 - adblock/filter rules (||domain^, element-hiding rules if present)
 - hosts entries (0.0.0.0 domain)
 - plain domain lines
 - comment lines with helpful tool/service links (SponsorBlock, FilterLists, Hagezi, FMHY, BlockTheSpot, Twitch solutions...)

Outputs:
 - ultimate_goat_merged.txt   <- single merged file with everything (deduped)
 - README.md
 - fetch_errors.log

Notes:
 - Deduplication is done on raw normalized lines (strip whitespace).
 - Script is conservative: retries transient errors; logs fetch errors.
 - The merged file mixes rules and domains as requested (single file).
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
# This list includes:
# - canonical ad/block filter sources (EasyList, uAssets, AdGuard, Fanboy, etc.)
# - hosts-style sources (StevenBlack, AdAway, MVPS, Firebog Prigent hosts)
# - threat-intel (URLhaus, RansomwareTracker, Phishing Army)
# - specialized lists & projects requested (Spotify/Twitch solutions, SponsorBlock, BilibiliSponsorBlock,
#   Legitimate URL Shortener / URL-cleaning lists, Hagezi, FilterLists directory, FMHY)
#
# Many are stable raw.githubusercontent.com, project pages, or canonical endpoints.
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
    "https://v.firebog.net/hosts/Prigent-Phishing.txt",
    "https://v.firebog.net/hosts/Prigent-Crypto.txt",
    "https://v.firebog.net/hosts/AdguardDNS.txt",
    "https://v.firebog.net/hosts/Easyprivacy.txt",
    "https://v.firebog.net/hosts/Admiral.txt",

    # Blocklists and aggregators
    "https://big.oisd.nl/",
    "https://small.oisd.nl/",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",

    # Coin-miner lists
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    "https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/list.txt",
    "https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/hosts",

    # URLhaus / malware / phishing / ransomware
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt",
    "https://ransomwaretracker.abuse.ch/downloads/CW_C2_DOMBL.txt",
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
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/master/hosts/hagezi-hosts.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/master/hosts/hagezi-pro.txt",

    # FMHY (unsafe sites filter)
    "https://raw.githubusercontent.com/fmhy/FMHYFilterlist/master/FMHy%20Filterlist%20Basic.txt",
    "https://raw.githubusercontent.com/fmhy/FMHYFilterlist/master/FMHy%20Filterlist%20Plus.txt",

    # Legitimate URL Shortener / ClearURLs-like & URL-tracker cleaning lists (Many repos)
    "https://raw.githubusercontent.com/yokoffing/filterlists/main/lists/Actually%20Legit%20URL%20Shortener.txt",
    "https://raw.githubusercontent.com/Universalizer/Universal-FilterLists/main/Actually%20Legitimate%20URL%20Shortener.txt",
    # Add additional URL-tracking removal lists (ClearURLs-like)
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/English/filter.txt",  # AdGuard filters include URL protections

    # SponsorBlock / SponsorBlockServer (note: extension DB & server - include comment link fetch)
    "https://raw.githubusercontent.com/ajayyy/SponsorBlockServer/master/README.md",
    "https://raw.githubusercontent.com/ajayyy/SponsorBlock/master/README.md",

    # BilibiliSponsorBlock
    "https://raw.githubusercontent.com/hanydd/BilibiliSponsorBlock/master/README.md",

    # Spotify/Twitch solutions (repositories; many are not pure blocklists but include rules/readmes)
    "https://raw.githubusercontent.com/mrpond/BlockTheSpot/master/README.md",
    "https://raw.githubusercontent.com/pixeltris/TwitchAdSolutions/master/README.md",
    "https://raw.githubusercontent.com/SpotX-Official/SpotX/master/README.md",

    # Twitch-specific filterlists (uBO/AdGuard collectors)
    "https://raw.githubusercontent.com/NotPaul/Twitch-Ad-Blocker/master/twitch-ad-blocker.txt",

    # Discord adblock / Disblock / community solutions (best-effort)
    "https://raw.githubusercontent.com/ZeroDot1/Discord-Block-List/master/README.md",  # community solutions
    "https://raw.githubusercontent.com/Perflyst/Perflyst-PiHole/master/Discord.txt",

    # Popup/overlay/redirect specialist lists and scripts (BehindTheOverlay, PopUpOFF)
    "https://raw.githubusercontent.com/iamadamdev/bypass-paywalls-chrome/master/README.md",  # paywall bypass project (info)
    "https://raw.githubusercontent.com/iamadamdev/bypass-paywalls-chrome/master/hostnames.txt",  # some hosts used by bypass lists
    "https://raw.githubusercontent.com/iamadamdev/bypass-paywalls-chrome/master/lists/filters.txt",

    # FilterLists / index (just a pointer to the directory so users can find more)
    "https://filterlists.com/",

    # Misc historical / helpful lists
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt",
]

# ----------------------------
# Helper utilities & regex
# ----------------------------
DOMAIN_RE = re.compile(r"(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}", re.IGNORECASE)

def normalize_line(line: str) -> str:
    # Remove BOM, trim whitespace, normalize spaces, remove trailing comments-only portions
    l = line.strip()
    # strip common inline comment markers after content when safe
    if l and "//" in l and not l.lower().startswith(("http://", "https://")):
        l = l.split("//", 1)[0].rstrip()
    # collapse multiple spaces
    l = re.sub(r"\s+", " ", l)
    return l

def is_text_content(headers: dict) -> bool:
    ct = headers.get("Content-Type", "")
    return "text" in ct.lower() or "html" in ct.lower() or ct == ""

def fetch_url(url: str, timeout: int = REQUEST_TIMEOUT) -> Tuple[str, str | None]:
    headers = {"User-Agent": "ultimate-goat-merged-generator/1.0 (+https://github.com/)"}
    last_err = None
    for attempt in range(RETRY_COUNT + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            r.raise_for_status()
            # Accept HTML/text responses; if binary or empty, return error
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
        # Keep comments lines starting with common comment chars (we'll normalize them)
        # But skip metadata headers like "Last-Modified:" or elaborate HTML titles
        if l.lower().startswith(("last-modified", "etag", "<!doctype", "<html")):
            continue
        lines.append(l)
    return lines

# Domain extraction — used to optionally validate domain-like lines if needed
def extract_domains_from_line(line: str) -> Set[str]:
    found = set()
    # hosts format "0.0.0.0 example.com"
    if line.startswith(("0.0.0.0", "127.0.0.1")):
        parts = line.split()
        if len(parts) >= 2:
            candidate = parts[1].lstrip(".")
            if DOMAIN_RE.search(candidate):
                found.add(candidate.lower())
        return found
    # adblock ||domain^
    if line.startswith("||"):
        core = line[2:].split("^",1)[0].split("/",1)[0].lstrip(".")
        if DOMAIN_RE.search(core):
            found.add(core.lower())
        return found
    # url-like
    for m in DOMAIN_RE.findall(line):
        found.add(m.lower())
    return found

# ----------------------------
# Generation
# ----------------------------
def generate_merged(sources: List[str]) -> Tuple[Dict[str,int], int, List[str]]:
    raw_set: Set[str] = set()  # store normalized lines for dedupe
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

        # If the source is a directory page (like filterlists.com), include a short comment line instead of raw content
        if src.rstrip("/").endswith("filterlists.com") or src.endswith("/"):
            comment_line = f"# SOURCE-DIR: {src}"
            raw_set.add(comment_line)
            fetch_summary[src] = 1
            continue

        for l in lines:
            n = normalize_line(l)
            # If the line is HTML (starts with <), ignore it except when it's README content where links may be present
            if n.startswith("<"):
                # attempt to extract links out of HTML
                for href in re.findall(r'href=["\']([^"\']+)["\']', n):
                    raw_set.add(f"# LINK: {href}")
                continue

            # Convert some README references into comment lines (helpful metadata)
            if n.lower().startswith(("readme", "#", "license")) or n.startswith("Project") or n.startswith("Usage"):
                # keep as comment
                raw_set.add("# " + n)
                continue

            # Keep valid host/adblock/domain entries and also keep other rules as-is (user requested single merged file)
            # Filter out obvious binary garbage
            if len(n) > 0:
                raw_set.add(n)
        fetch_summary[src] = max(0, len(raw_set) - added_before)

    # Add a curated header with tool links & notes (these are the exact tools you wanted included)
    header_items = [
        f"# ULTIMATE GOAT MERGED LIST - generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "# This single merged file contains domains, hosts entries, adblock/filter rules, and helpful tool links.",
        "# Tools & extensions references (not raw rules):",
        "# SponsorBlock (skip sponsored YouTube segments) -> https://github.com/ajayyy/SponsorBlock",
        "# SponsorBlock Server / DB -> https://github.com/ajayyy/SponsorBlockServer",
        "# BilibiliSponsorBlock -> https://github.com/hanydd/BilibiliSponsorBlock",
        "# BlockTheSpot / SpotX / Spotify solutions -> https://github.com/mrpond/BlockTheSpot  https://github.com/SpotX-Official/SpotX",
        "# Twitch ad solutions -> https://github.com/pixeltris/TwitchAdSolutions",
        "# Discord ad hiding / Disblock solutions -> community repos (see Perflyst / community)",
        "# Legitimate URL Shortener & URL tracking cleaning lists -> see yokoffing/filterlists & Universalizer lists",
        "# HageZi DNS Blocklists -> https://github.com/hagezi/dns-blocklists",
        "# FilterLists directory (index of filter/hosts lists) -> https://filterlists.com/",
        "# FMHY Filterlist (unsafe sites) -> https://github.com/fmhy/FMHYFilterlist",
        "# BehindTheOverlay / Popup removers & Paywall bypass (see bypass-paywalls-chrome repo for host rules)",
        "# NOTE: This file intentionally mixes rules and domains per user request.",
        "# If you need separate domain-only or rule-only outputs, create separate files from this merged dataset."
    ]
    # Add header lines into raw_set so they are included but keep them at top by inserting separately during write

    # Prepare sorted final list (deterministic)
    final_lines = sorted(raw_set)

    # write merged file with header first
    with open(MERGED_OUTPUT, "w", encoding="utf-8") as fh:
        for h in header_items:
            fh.write(h + "\n")
        fh.write("\n")
        for line in final_lines:
            fh.write(line + "\n")

    return fetch_summary, len(final_lines), errors

def generate_readme(sources: List[str], fetch_summary: Dict[str,int], total_count: int) -> None:
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(README, "w", encoding="utf-8") as f:
        f.write("# Ultimate GOAT Merged List\n\n")
        f.write(f"**Generated:** {now}\n\n")
        f.write("This repository contains one single merged file `ultimate_goat_merged.txt` that includes domains, hosts-format entries, adblock/filter rules, and comment lines with helpful tool links (SponsorBlock, BilibiliSponsorBlock, Spotify/Twitch tools, FilterLists, HageZi, FMHY, etc.).\n\n")
        f.write(f"- **Total unique lines in merged file:** {total_count}\n\n")
        f.write("## Sources included (curated)\n")
        for s in sources:
            f.write(f"- {s}\n")
        f.write("\n## Per-source fetch summary (this run)\n")
        for s, c in fetch_summary.items():
            f.write(f"- {s} -> {c} lines added\n")
        f.write("\n## Notes\n")
        f.write("- This single file intentionally mixes adblock rules and domain/host entries as you requested.\n")
        f.write("- If you use this file for DNS-level blockers (Pi-hole, AdGuard Home) be aware that adblock rules and element-hiding lines are not meaningful in DNS contexts — they will remain as comments/rules in this single file. For best compatibility, consider generating separate domain-only and rule-only exports in addition to this merged file.\n")
        f.write("- fetch_errors.log contains any fetch failures (404/timeout/non-text responses) for debugging.\n")

def main() -> int:
    print("Starting generation of ultimate_goat_merged.txt ...")
    summary, total, errors = generate_merged(SOURCES)
    print(f"Fetched {len(SOURCES)} sources, built merged list with {total} unique lines.")

    # write fetch errors if any
    if errors:
        with open(FETCH_LOG, "w", encoding="utf-8") as fl:
            for e in errors:
                fl.write(e + "\n")
        print(f"Fetch errors written to {FETCH_LOG} ({len(errors)} entries).")
    else:
        # ensure empty log exists for CI commit
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
