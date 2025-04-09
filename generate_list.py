#!/usr/bin/env python3
import requests
from datetime import datetime
import re
import uuid
import plistlib
from xml.etree import ElementTree
from xml.dom import minidom

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
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
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
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/refs/heads/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/resource-abuse.txt",
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
    "https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt"
]

# Base header metadata for the block list
BASE_HEADER_LINES = [
    "! Title: Robust Block List Pro",
    "! Description: Combined block list from multiple sources"
]

# Regular expression patterns to match potential secrets
SECRET_PATTERNS = [
    re.compile(r'[a-zA-Z0-9]{40,60}'),  # Matches IBM SoftLayer API Key and IBM Cloud IAM Key
    re.compile(r'apikey', re.IGNORECASE),  # Matches the word 'apikey'
    re.compile(r'IBM', re.IGNORECASE),  # Matches the word 'IBM'
]

def fetch_url(url):
    """Fetch the content from a URL and return the text, or an empty string if failed."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return ""

def extract_domains(line):
    """Extract domain names from different filter formats"""
    domain = None

    # Check for common filter patterns
    if line.startswith('||'):
        # Matches ||domain.com^
        domain = re.match(r'^\|\|([\w.-]+)\^?', line)
        if domain:
            return domain.group(1)
    elif line.startswith('0.0.0.0 ') or line.startswith('127.0.0.1 '):
        # Matches 0.0.0.0 domain.com
        parts = line.split()
        if len(parts) >= 2:
            return parts[1]
    elif re.match(r'^[\w.-]+$', line):
        # Plain domain name
        return line
    elif '/' in line:
        # Skip URL paths
        return None

    return None

def generate_mobileconfig(domains, max_size=500000):
    """Generate iOS configuration profile with DNS settings"""
    # Generate unique identifiers
    payload_uuid = str(uuid.uuid4())
    profile_uuid = str(uuid.uuid4())

    # Create XML structure
    plist_dict = {
        'PayloadContent': [
            {
                'DNSSettings': {
                    'DNSProtocol': 'HTTPS',
                    'ServerAddresses': ['8.8.8.8'],  # Google DNS
                    'ServerURL': 'https://dns.google/dns-query'
                },
                'PayloadDescription': 'Configures device to use secure DNS',
                'PayloadDisplayName': 'Robust DNS Protection',
                'PayloadIdentifier': 'com.robustblocklistpro.dns',
                'PayloadType': 'com.apple.dnsSettings.managed',
                'PayloadUUID': payload_uuid,
                'PayloadVersion': 1
            }
        ],
        'PayloadDescription': 'Robust Block List Pro - DNS Protection',
        'PayloadDisplayName': 'Robust DNS Blocker',
        'PayloadIdentifier': 'com.robustblocklistpro',
        'PayloadRemovalDisallowed': False,
        'PayloadScope': 'System',
        'PayloadType': 'Configuration',
        'PayloadUUID': profile_uuid,
        'PayloadVersion': 1
    }

    # Add OnDemandRules if we have domains
    if domains:
        plist_dict['PayloadContent'][0]['OnDemandRules'] = [{
            'Action': 'Disconnect',
            'DNSDomainMatch': domains,
            'DNSDomainMatchType': 'MatchesAny',
            'InterfaceTypeMatch': 'Any'
        }]

    # Generate plist XML
    plist_xml = plistlib.dumps(plist_dict)

    # Wrap in configuration profile header
    xml_header = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    )

    # Pretty-print the XML
    parsed = minidom.parseString(plist_xml)
    pretty_plist = parsed.toprettyxml(indent='  ', encoding='UTF-8').decode()

    # Combine header and pretty-printed plist
    mobileconfig_content = xml_header + pretty_plist

    # Check the size of the mobileconfig content
    if len(mobileconfig_content) > max_size:
        print(f"Warning: Mobileconfig size ({len(mobileconfig_content)} bytes) exceeds the maximum allowed size ({max_size} bytes).")
        # Reduce the number of domains to fit within the size limit
        while len(mobileconfig_content) > max_size and domains:
            domains.pop()
            plist_dict['PayloadContent'][0]['OnDemandRules'][0]['DNSDomainMatch'] = domains
            plist_xml = plistlib.dumps(plist_dict)
            parsed = minidom.parseString(plist_xml)
            pretty_plist = parsed.toprettyxml(indent='  ', encoding='UTF-8').decode()
            mobileconfig_content = xml_header + pretty_plist

    return mobileconfig_content

def main():
    combined_lines = set()
    filtered_lines = []

    for url in URLS:
        print(f"Fetching: {url}")
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line_clean = line.strip()
                # Skip empty lines and lines already included in the header
                if line_clean and line_clean not in BASE_HEADER_LINES:
                    # Filter out lines containing potential secrets
                    if not any(pattern.search(line_clean) for pattern in SECRET_PATTERNS):
                        combined_lines.add(line_clean)
                    else:
                        filtered_lines.append(line_clean)

    total_count = len(combined_lines)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Construct header with metadata
    header_lines = BASE_HEADER_LINES + [
        f"! Total Blocked Items: {total_count}",
        f"! Updated: {now}"
    ]
    header = "\n".join(header_lines)

    # Prepare final sorted list content
    sorted_lines = sorted(combined_lines)
    final_content = header + "\n\n" + "\n".join(sorted_lines) + "\n"

    # Write the formatted list to file
    output_filename = "robust_block_list_pro.txt"
    try:
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(final_content)
        print(f"List generated successfully: {output_filename}")
    except IOError as e:
        print(f"Error writing to {output_filename}: {e}")

    # Generate iOS configuration profile
    print("\nGenerating iOS configuration profile...")

    # Extract domains from combined lines
    domains = set()
    for line in sorted_lines:
        if line.startswith('!'):  # Skip comments
            continue
        domain = extract_domains(line)
        if domain:
            domains.add(domain)

    # Generate mobileconfig content
    domain_list = list(domains)[:50000]  # Initial limit of 50,000 domains
    mobileconfig_content = generate_mobileconfig(domain_list)

    # Write mobileconfig file
    config_filename = "dns_blocker.mobileconfig"
    try:
        with open(config_filename, "w", encoding="utf-8") as f:
            f.write(mobileconfig_content)
        print(f"iOS configuration profile generated: {config_filename}")
        print(f"Domains included: {len(domain_list)}")
    except IOError as e:
        print(f"Error writing {config_filename}: {e}")

    # Log filtered lines
    if filtered_lines:
        print("\nFiltered lines (potential secrets):")
        for line in filtered_lines:
            print(line)

if __name__ == "__main__":
    main()
