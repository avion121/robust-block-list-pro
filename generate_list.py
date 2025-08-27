#!/usr/bin/env python3
import os
import re
import json
import time
import requests

# --------------------
# Configuration
# --------------------

LOG_FILE = "fetch_errors.log"
META_FILE = "fetch_meta.json"

SOURCE_URLS = [
    # Ads & Tracking
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",  # AnudeepND Adservers (hosts)
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",  # Frogeye First-Party Trackers (hosts)
    "https://o0.pages.dev/Lite/hosts",  # 1Hosts (Lite) (hosts)

    # Security-focused
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",  # Phishing Army
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",  # Blocklist Project Malware
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",  # Blocklist Project Phishing
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",  # Dandelion Sprout Anti-Malware
    "https://urlhaus.abuse.ch/downloads/hostfile/",  # URLHaus (hosts)
    "https://v.firebog.net/hosts/AdguardDNS.txt",  # Firebog AdguardDNS (hosts)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",  # Hagezi Threat Intelligence Feeds
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",  # Hagezi Pro++
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/anti.piracy.txt",  # Hagezi Anti-Piracy

    # Regional EasyList
    "https://easylist-downloads.adblockplus.org/easylistgermany.txt",  # EasyList Germany
    "https://easylist-downloads.adblockplus.org/indianlist%2Beasylist.txt",  # EasyList India
    "https://easylist-downloads.adblockplus.org/liste_fr.txt",  # EasyList France
    "https://easylist-downloads.adblockplus.org/easylistitaly.txt",  # EasyList Italy
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",  # EasyList China
    "https://easylist-downloads.adblockplus.org/easylist_russia.txt",  # EasyList Russia
    "https://easylist-downloads.adblockplus.org/easylistspanish.txt",  # EasyList Spain
    "https://easylist-downloads.adblockplus.org/easylistdutch.txt",  # EasyList Dutch
    "https://easylist-downloads.adblockplus.org/easylistportuguese.txt",  # EasyList Portuguese
    "https://easylist-downloads.adblockplus.org/abp-filters-anti-cv.txt",  # EasyList Arabic (Anti-CV)
    "https://easylist-downloads.adblockplus.org/israellist.txt",  # EasyList Hebrew
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianList.txt",  # Dandelion Sprout Nordic

    # AdGuard extras
    "https://filters.adtidy.org/extension/ublock/filters/3.txt",  # AdGuard Tracking Protection
    "https://filters.adtidy.org/extension/ublock/filters/4.txt",  # AdGuard Social Media
    "https://filters.adtidy.org/extension/ublock/filters/10.txt",  # AdGuard Spyware
    "https://filters.adtidy.org/extension/ublock/filters/11.txt",  # AdGuard Mobile Ads
    "https://filters.adtidy.org/extension/ublock/filters/14.txt",  # AdGuard Annoyances

    # Gaming
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt",  # Dandelion Sprout Game Console

    # High-value additions
    "https://www.spamhaus.org/drop/drop.txt",  # Spamhaus DROP (IP/netblock)
    "https://big.oisd.nl/",  # OISD big (domains)
    "https://dbl.oisd.nl/",  # OISD dbl mirror
    "https://hosts.oisd.nl/",  # OISD hosts mirror
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",  # Disconnect tracking
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",  # Disconnect ads
]
