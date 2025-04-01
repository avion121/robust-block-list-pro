#!/usr/bin/env python3
import re
import requests
import uuid
from datetime import datetime

# List of source URLs for block lists
URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/privacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/quick-fixes.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/unbreak.txt",
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://ransomwaretracker.abuse.ch/blocklist/",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/alternates/fakenews-gambling/hosts",
    "https://big.oisd.nl",
    "https://o0.pages.dev/Lite/adblock.txt",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/refs/heads/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt"
]

# Base header for the robust block list
BASE_HEADER_LINES = [
    "! Title: Robust Block List Pro",
    "! Description: Combined block list from multiple sources"
]

def fetch_url(url):
    """Fetch content from URL; return text or empty string if error."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return ""

def extract_domain(line):
    """
    Extract a domain from an adblock rule.
    For example, converts:
      ||example.com^   to   example.com
    """
    match = re.match(r"^\|\|([^\^\/]+)\^", line)
    if match:
        return match.group(1)
    return None

def generate_mobileconfig(domains, output_filename):
    """
    Generate an iOS mobileconfig file using the full list of domains.
    """
    subset = sorted(domains)  # full list, no limit
    supplemental_domains = "\n            ".join([f"<string>{d}</string>" for d in subset])
    
    # Generate unique UUIDs for the profile payloads
    uuid1 = str(uuid.uuid4())
    uuid2 = str(uuid.uuid4())
    
    mobileconfig_template = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>PayloadContent</key>
    <array>
      <dict>
        <key>DNSSettings</key>
        <dict>
          <!-- Specify your preferred DNS servers -->
          <key>ServerAddresses</key>
          <array>
            <string>94.140.14.14</string>
            <string>94.140.15.15</string>
          </array>
          <!-- SupplementalMatchDomains from the blocklist -->
          <key>SupplementalMatchDomains</key>
          <array>
            {supplemental_domains}
          </array>
        </dict>
        <key>PayloadIdentifier</key>
        <string>com.yourcompany.dnsconfig</string>
        <key>PayloadType</key>
        <string>com.apple.dnsSettings.managed</string>
        <key>PayloadUUID</key>
        <string>{uuid1}</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
      </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Robust DNS Profile</string>
    <key>PayloadIdentifier</key>
    <string>com.yourcompany.robustdns</string>
    <key>PayloadUUID</key>
    <string>{uuid2}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadType</key>
    <string>Configuration</string>
  </dict>
</plist>
"""
    try:
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(mobileconfig_template)
        print(f"Mobileconfig generated successfully: {output_filename}")
    except IOError as e:
        print(f"Error writing to {output_filename}: {e}")

def main():
    robust_lines = []   # For the full robust block list (all lines)
    domain_set = set()  # For the DNS-compatible domain list
    
    for url in URLS:
        print(f"Fetching: {url}")
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line_clean = line.strip()
                # Save every non-empty line for the robust block list
                if line_clean:
                    robust_lines.append(line_clean)
                # For domain extraction, ignore comments and empty lines
                if line_clean.startswith("!") or not line_clean:
                    continue
                domain = extract_domain(line_clean)
                if domain:
                    domain_set.add(domain)
    
    # --- Part A: Write the full robust block list with header ---
    total_items = len(set(robust_lines))
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    header_lines = BASE_HEADER_LINES + [
        f"! Total Blocked Items: {total_items}",
        f"! Updated: {now}"
    ]
    robust_content = "\n".join(header_lines) + "\n\n" + "\n".join(sorted(set(robust_lines))) + "\n"
    robust_filename = "robust_block_list_pro.txt"
    try:
        with open(robust_filename, "w", encoding="utf-8") as f:
            f.write(robust_content)
        print(f"Robust block list generated: {robust_filename}")
    except IOError as e:
        print(f"Error writing to {robust_filename}: {e}")
    
    # --- Part B: Write the full DNS-compatible domain list ---
    dns_filename = "dns-blocklist.txt"
    try:
        with open(dns_filename, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(domain_set)) + "\n")
        print(f"DNS blocklist generated: {dns_filename}")
    except IOError as e:
        print(f"Error writing to {dns_filename}: {e}")
    
    # --- Part C: Generate the mobileconfig file using the full domain list ---
    mobileconfig_filename = "robust-dns-profile.mobileconfig"
    generate_mobileconfig(domain_set, mobileconfig_filename)

if __name__ == "__main__":
    main()
