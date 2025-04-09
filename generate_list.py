#!/usr/bin/env python3
import requests
from datetime import datetime
import re
import uuid
import plistlib
from xml.dom import minidom

URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://big.oisd.nl",
]

BASE_HEADER = [
    "! Title: Robust Block List Pro",
    "! Description: Comprehensive blocking list with iOS support"
]

SECRET_PATTERNS = [
    re.compile(r'[a-zA-Z0-9]{32,}'),
    re.compile(r'api[_-]?key', re.I),
    re.compile(r'secret', re.I)
]

def fetch(url):
    try:
        return requests.get(url, timeout=15).text
    except Exception as e:
        print(f"Failed {url}: {str(e)}")
        return ""

def extract(line):
    line = line.strip()
    if not line or line.startswith('!'): return None
    
    patterns = [
        (r'^\|\|([\w.-]+)\^', 1),
        (r'^0\.0\.0\.0 ([\w.-]+)', 1),
        (r'^127\.0\.0\.1 ([\w.-]+)', 1),
        (r'^([\w.-]+)$', 0)
    ]
    
    for pattern, group in patterns:
        match = re.match(pattern, line)
        if match: return match.group(group)
    return None

def create_ios_config(domains, max_size=524288):
    config_uuid = str(uuid.uuid4())
    payload_uuid = str(uuid.uuid4())
    
    plist = {
        'PayloadContent': [{
            'DNSSettings': {
                'DNSProtocol': 'HTTPS',
                'ServerAddresses': ['8.8.8.8'],
                'ServerURL': 'https://dns.google/dns-query'
            },
            'OnDemandRules': [{
                'Action': 'Disconnect',
                'DNSDomainMatch': domains,
                'DNSDomainMatchType': 'MatchesAny',
                'InterfaceTypeMatch': 'Any'
            }],
            'PayloadIdentifier': 'com.robustblock.pro',
            'PayloadType': 'com.apple.dnsSettings.managed',
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1
        }],
        'PayloadIdentifier': 'com.robustblock.main',
        'PayloadType': 'Configuration',
        'PayloadUUID': config_uuid,
        'PayloadVersion': 1
    }
    
    xml = plistlib.dumps(plist, fmt=plistlib.FMT_XML)
    xml = minidom.parseString(xml).toprettyxml(indent='', newl='')
    xml = '<?xml version="1.0" encoding="UTF-8"?>' + xml
    
    while len(xml.encode('utf-8')) > max_size and domains:
        domains = domains[:-500]
        plist['PayloadContent'][0]['OnDemandRules'][0]['DNSDomainMatch'] = domains
        xml = plistlib.dumps(plist, fmt=plistlib.FMT_XML)
        xml = minidom.parseString(xml).toprettyxml(indent='', newl='')
        xml = '<?xml version="1.0" encoding="UTF-8"?>' + xml
    
    return xml, domains

def main():
    entries = set()
    filtered = []
    
    # Process block lists
    for url in URLS:
        print(f"Fetching {url}")
        content = fetch(url)
        for line in content.splitlines():
            line = line.strip()
            if line and line not in BASE_HEADER:
                if any(p.search(line) for p in SECRET_PATTERNS):
                    filtered.append(line)
                else:
                    entries.add(line)
    
    # Generate block list
    header = '\n'.join(BASE_HEADER + [
        f"! Entries: {len(entries)}",
        f"! Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    ])
    
    with open("robust_block_list_pro.txt", "w") as f:
        f.write(f"{header}\n\n" + '\n'.join(sorted(entries)))
    
    # Generate iOS config
    domains = {extract(line) for line in entries if extract(line)}
    domains = [d for d in domains if d]
    
    print(f"\nFound {len(domains)} domains for iOS")
    config, final_domains = create_ios_config(domains)
    
    with open("dns_blocker.mobileconfig", "w") as f:
        f.write(config)
    
    print(f"iOS config: {len(final_domains)} domains")
    print(f"Config size: {len(config.encode('utf-8'))} bytes")

if __name__ == "__main__":
    main()
