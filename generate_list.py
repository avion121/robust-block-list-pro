#!/usr/bin/env python3
# generate_list.py  (improved)
import os
import json
import time
import hashlib
import re
import requests
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path

# local imports
from sources import BLOCKLIST_SOURCES, WHITELIST_SOURCES

# Files / config
OUTPUT_ADBLOCK = "robust_block_list_pro.txt"
OUTPUT_HOSTS = "robust_hosts.txt"
OUTPUT_IPSET = "robust_ipset.txt"
LOG_FILE = "fetch_errors.log"
CACHE_META = ".fetch_cache.json"
CACHE_DIR = "cache"
STALE_THRESHOLD = 30 * 24 * 60 * 60  # 30 days

# Ensure cache dir
os.makedirs(CACHE_DIR, exist_ok=True)

# Helpers ---------------------------------------------------------------------

def _hash_url(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()

def load_cache_meta():
    if os.path.exists(CACHE_META):
        try:
            with open(CACHE_META, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache_meta(meta):
    with open(CACHE_META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

def log(msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")

def canonical_domain_from_url(u):
    try:
        p = urlparse(u)
        host = p.hostname or u
        if host and host.startswith("www."):
            host = host[4:]
        return host.lower()
    except Exception:
        return u.lower()

# Fetcher with ETag / If-Modified-Since and cached content -------------------

cache_meta = load_cache_meta()

def fetch_url_to_cache(url, timeout=25, retries=3, backoff=2):
    """Fetch a URL with ETag/If-Modified-Since support; cache content in cache/<hash>.txt"""
    meta = cache_meta.get(url, {})
    headers = {"Accept-Encoding": "identity", "User-Agent": "robust-blocklist-bot/1.0"}
    if meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        headers["If-Modified-Since"] = meta["last_modified"]

    cache_file = os.path.join(CACHE_DIR, f"{_hash_url(url)}.txt")
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            # 304 Not Modified -> reuse cache if available
            if r.status_code == 304:
                if os.path.exists(cache_file):
                    return open(cache_file, "r", encoding="utf-8", errors="replace").read(), meta.get("last_modified", "Unknown")
                else:
                    log(f"[304 but missing cache] {url}")
                    return "", "NotCached"
            if r.status_code == 200:
                content = r.text
                # write cache
                with open(cache_file, "w", encoding="utf-8") as f:
                    f.write(content)
                # update meta
                new_meta = {
                    "etag": r.headers.get("ETag"),
                    "last_modified": r.headers.get("Last-Modified"),
                    "fetched_at": int(time.time()),
                    "cache_file": cache_file
                }
                cache_meta[url] = new_meta
                save_cache_meta(cache_meta)
                # stale check
                lm = r.headers.get("Last-Modified")
                if lm:
                    try:
                        lm_ts = int(time.mktime(time.strptime(lm, "%a, %d %b %Y %H:%M:%S GMT")))
                        if time.time() - lm_ts > STALE_THRESHOLD:
                            log(f"[STALE] {url} (Last-Modified: {lm})")
                    except Exception:
                        pass
                return content, r.headers.get("Last-Modified", "Unknown")
            else:
                log(f"[HTTP {r.status_code}] {url} (Attempt {attempt})")
        except Exception as e:
            log(f"[ERROR] {url} → {e} (Attempt {attempt})")
        time.sleep(backoff ** (attempt - 1))
    return "", "Failed"

# Parsers --------------------------------------------------------------------

hosts_entry_re = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\-\._]+)')

def parse_hosts_lines(text):
    hosts = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or ln.startswith("!"):
            continue
        m = hosts_entry_re.match(ln)
        if m:
            hosts.add(m.group(1).lower())
    return hosts

def parse_domains_lines(text):
    domains = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or ln.startswith("!"):
            continue
        # remove URI scheme or path if accidentally included
        if ln.startswith("http://") or ln.startswith("https://"):
            try:
                ln = urlparse(ln).hostname or ln
            except Exception:
                pass
        # remove surrounding characters
        ln = ln.split()[0].strip().strip(".")
        if ln:
            domains.add(ln.lower())
    return domains

def parse_adblock_lines(text):
    rules = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("!") or ln.startswith("#"):
            continue
        # Keep cosmetic rules? optional — preserve them for now
        rules.add(ln)
    return rules

def parse_ip_lines(text):
    ipset = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or ln.startswith("!"):
            continue
        # basic IP/CIDR validation (very permissive)
        if re.match(r'^[0-9./:a-fA-F]+$', ln.split()[0]):
            ipset.add(ln.split()[0])
    return ipset

def parse_phishing_lines(text):
    # OpenPhish provides full URLs — we'll extract hostname
    domains = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        try:
            host = urlparse(ln).hostname or ln
            if host:
                domains.add(host.lower())
        except Exception:
            # fallback: try splitting
            host = ln.split("/")[0]
            if host:
                domains.add(host.lower())
    return domains

def parse_cname_json_or_domains(text):
    # AdGuard's repo is JSON; NextDNS provides a plain domains file.
    # Try JSON parse first, otherwise treat as plain domain-per-line.
    try:
        data = json.loads(text)
        domains = set()
        # AdGuard's JSON structure includes objects listing tracked domains or arrays; attempt best-effort extraction.
        if isinstance(data, dict):
            # extract all string values that look like domains
            def walk(obj):
                out = set()
                if isinstance(obj, dict):
                    for v in obj.values():
                        out |= walk(v)
                elif isinstance(obj, list):
                    for v in obj:
                        out |= walk(v)
                elif isinstance(obj, str):
                    if "." in obj and " " not in obj:
                        out.add(obj.lower())
                return out
            domains = walk(data)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str) and "." in item:
                    domains.add(item.lower())
        return domains
    except Exception:
        # treat as plain text of domains
        return parse_domains_lines(text)

# Validation helpers ---------------------------------------------------------

def is_valid_adblock_rule(line):
    # simple sanity: don't allow localhost or obvious garbage
    if not line or "localhost" in line.lower():
        return False
    # Accept broad variety: ||domain^, /regex/, @@exceptions, etc.
    return True

def normalize_hosts_entry(domain):
    return domain.strip().lower()

def to_adblock_from_domain(domain):
    # Domain -> adblock rule that blocks domain and subdomains
    # Examples: ||example.com^
    domain = domain.strip().lower()
    if not domain:
        return None
    # avoid adding raw IPs here
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return None
    return f"||{domain}^"

# Main generation ------------------------------------------------------------

def generate_combined_blocklist(write_hosts=True, write_ipset=True):
    adblock_rules = set()
    hosts_domains = set()
    domain_only = set()
    ipset = set()
    source_metadata = []
    now_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    version = datetime.utcnow().strftime("%Y%m%d%H%M")

    # helper to fetch+parse according to declared format
    def fetch_and_parse(source):
        url = source.get("url")
        fmt = source.get("format", "other")
        content, last_modified = fetch_url_to_cache(url)
        source_metadata.append(f"! - {url} (Fetched: {last_modified})")
        if not content:
            return
        if fmt == "hosts":
            hosts = parse_hosts_lines(content)
            for h in hosts:
                hosts_domains.add(normalize_hosts_entry(h))
        elif fmt == "adblock":
            rules = parse_adblock_lines(content)
            for r in rules:
                if is_valid_adblock_rule(r):
                    adblock_rules.add(r)
        elif fmt == "domains":
            domains = parse_domains_lines(content)
            for d in domains:
                domain_only.add(d)
        elif fmt == "cname":
            # JSON or plain list of domains
            domains = parse_cname_json_or_domains(content)
            for d in domains:
                domain_only.add(d)
        elif fmt == "phishing":
            # treat as URL list -> extract hosts (careful: broad)
            domains = parse_phishing_lines(content)
            for d in domains:
                domain_only.add(d)
        elif fmt == "ip":
            ips = parse_ip_lines(content)
            for ip in ips:
                ipset.add(ip)
        else:
            # try to autodetect: prefer hosts if '0.0.0.0' present
            if "0.0.0.0" in content or "127.0.0.1" in content:
                hosts = parse_hosts_lines(content)
                for h in hosts:
                    hosts_domains.add(normalize_hosts_entry(h))
            else:
                # fallback: try adblock first, then domains
                rules = parse_adblock_lines(content)
                if rules:
                    for r in rules:
                        adblock_rules.add(r)
                else:
                    domains = parse_domains_lines(content)
                    for d in domains:
                        domain_only.add(d)

    # Fetch blocklist sources
    for src in BLOCKLIST_SOURCES:
        try:
            fetch_and_parse(src)
        except Exception as e:
            log(f"[PARSE ERROR] {src.get('url')} → {e}")

    # Fetch whitelist sources and remove matches
    whitelisted_domains = set()
    whitelisted_rules = set()
    for src in WHITELIST_SOURCES:
        content, _ = fetch_url_to_cache(src.get("url"))
        if not content:
            continue
        fmt = src.get("format", "adblock")
        if fmt == "hosts" or fmt == "domains":
            whitelisted_domains |= parse_domains_lines(content)
        else:
            # treat as adblock -> parse lines and add to whitelist patterns
            whitelisted_rules |= parse_adblock_lines(content)

    # Apply whitelist: remove matching domains and convert domain whitelist to adblock/inverse removal
    # Remove any domain_only or hosts_domains present in whitelist
    domain_only = {d for d in domain_only if d not in whitelisted_domains}
    hosts_domains = {d for d in hosts_domains if d not in whitelisted_domains}
    # Remove adblock rules that exactly match a whitelist rule (simple approach)
    if whitelisted_rules:
        adblock_rules = {r for r in adblock_rules if r not in whitelisted_rules}

    # Convert domain-only lists into adblock rules for combined adblock file
    for d in domain_only:
        r = to_adblock_from_domain(d)
        if r:
            adblock_rules.add(r)

    # Convert hosts domains into both hosts file and adblock rules (optional)
    for h in hosts_domains:
        r = to_adblock_from_domain(h)
        if r:
            adblock_rules.add(r)

    # Final dedupe & sort
    final_adblock = sorted(adblock_rules)
    final_hosts = sorted(hosts_domains)
    final_ipset = sorted(ipset)

    # Write outputs
    header = [
        f"! Title: Robust Block List Pro",
        f"! Version: {version}",
        f"! Generated: {now_ts}",
        "! NOTE: This file was generated by generate_list.py",
        "! Sources:"
    ]
    header.extend(source_metadata)
    header_text = "\n".join(header) + "\n\n"

    # Write adblock combined
    with open(OUTPUT_ADBLOCK, "w", encoding="utf-8") as f:
        f.write(header_text)
        for r in final_adblock:
            f.write(r.rstrip() + "\n")

    # Write hosts file
    if write_hosts:
        with open(OUTPUT_HOSTS, "w", encoding="utf-8") as f:
            f.write(f"# Robust Hosts - Generated: {now_ts}\n")
            for h in final_hosts:
                f.write(f"0.0.0.0\t{h}\n")

    # Write ipset file
    if write_ipset and final_ipset:
        with open(OUTPUT_IPSET, "w", encoding="utf-8") as f:
            f.write(f"# Robust IP set - Generated: {now_ts}\n")
            for ip in final_ipset:
                f.write(ip + "\n")

    # return counts
    return {
        "adblock_count": len(final_adblock),
        "hosts_count": len(final_hosts),
        "ip_count": len(final_ipset)
    }

# CLI -----------------------------------------------------------------------

if __name__ == "__main__":
    # clear/create log
    open(LOG_FILE, "a", encoding="utf-8").close()
    print("Fetching sources (this may take a while for many sources)...")
    results = generate_combined_blocklist()
    print(f"✅ Wrote {OUTPUT_ADBLOCK} ({results['adblock_count']} adblock rules)")
    print(f"✅ Wrote {OUTPUT_HOSTS} ({results['hosts_count']} hosts entries)")
    if results["ip_count"] > 0:
        print(f"✅ Wrote {OUTPUT_IPSET} ({results['ip_count']} IP/CIDR entries)")
    else:
        print("ℹ️ No IP/CIDR entries collected (no ip feeds or empty).")
    print(f"ℹ️ Any fetch/parsing warnings logged to {LOG_FILE}")
