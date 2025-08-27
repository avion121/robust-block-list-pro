# sources.py
# Canonical blocklist/whitelist sources with explicit formats.
# Formats:
#  - "adblock" : Adblock/AdGuard/uBO style filter lists (keep lines as-is)
#  - "hosts"   : hosts-format (0.0.0.0 or 127.0.0.1 entries)
#  - "domains" : plain domain-per-line lists (one domain per line)
#  - "cname"   : CNAME-cloaked tracker domain lists (domains, convert to adblock rules)
#  - "phishing": URL feeds (OpenPhish / PhishTank) - parsed into domains
#  - "ip"      : IP/CIDR lists (for ipset/firewall use)
#  - "other"   : unknown or mixed - generator will try to autodetect
#
# NOTE: I preserved your original sources and added the suggested ones.
# If you want some feeds excluded at runtime (e.g., ip lists) toggle them in generate_list.py.

BLOCKLIST_SOURCES = [
    # Core ad & privacy (adblock / filters)
    {"url": "https://easylist.to/easylist/easylist.txt", "format": "adblock"},
    {"url": "https://easylist.to/easylist/easyprivacy.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/anti-adblock.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/lantern.txt", "format": "adblock"},

    # Fanboy extras
    {"url": "https://secure.fanboy.co.nz/fanboy-annoyance.txt", "format": "adblock"},
    {"url": "https://secure.fanboy.co.nz/fanboy-social.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt", "format": "adblock"},
    {"url": "https://www.fanboy.co.nz/enhancedstats.txt", "format": "adblock"},

    # Crypto miners
    {"url": "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt", "format": "adblock"},
    {"url": "https://zerodot1.gitlab.io/CoinBlockerLists/list_browser.txt", "format": "adblock"},

    # Hosts-format sources
    {"url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "format": "hosts"},
    {"url": "https://adaway.org/hosts.txt", "format": "hosts"},
    {"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "format": "hosts"},
    {"url": "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt", "format": "hosts"},
    {"url": "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt", "format": "hosts"},
    {"url": "https://o0.pages.dev/Lite/hosts", "format": "hosts"},

    # Security-focused
    {"url": "https://phishing.army/download/phishing_army_blocklist_extended.txt", "format": "domains"},
    {"url": "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt", "format": "domains"},
    {"url": "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt", "format": "domains"},
    {"url": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt", "format": "adblock"},
    {"url": "https://urlhaus.abuse.ch/downloads/hostfile/", "format": "hosts"},
    {"url": "https://v.firebog.net/hosts/AdguardDNS.txt", "format": "hosts"},
    {"url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/anti.piracy.txt", "format": "adblock"},

    # Regional EasyList (adblock)
    {"url": "https://easylist-downloads.adblockplus.org/easylistgermany.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/indianlist%2Beasylist.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/liste_fr.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/easylistitaly.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/easylistchina.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/easylist_russia.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/easylistspanish.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/easylistdutch.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/easylistportuguese.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/abp-filters-anti-cv.txt", "format": "adblock"},
    {"url": "https://easylist-downloads.adblockplus.org/israellist.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianList.txt", "format": "adblock"},

    # AdGuard extras (adblock)
    {"url": "https://filters.adtidy.org/extension/ublock/filters/3.txt", "format": "adblock"},
    {"url": "https://filters.adtidy.org/extension/ublock/filters/4.txt", "format": "adblock"},
    {"url": "https://filters.adtidy.org/extension/ublock/filters/10.txt", "format": "adblock"},
    {"url": "https://filters.adtidy.org/extension/ublock/filters/11.txt", "format": "adblock"},
    {"url": "https://filters.adtidy.org/extension/ublock/filters/14.txt", "format": "adblock"},

    # Gaming
    {"url": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt", "format": "adblock"},

    # ---------- ADDED HIGH-IMPACT SOURCES (your request) ----------
    # OISD domain blocklist (domain-level; 'big' is a comprehensive superset)
    {"url": "https://big.oisd.nl/", "format": "domains"},
    {"url": "https://nsfw.oisd.nl/", "format": "domains"},

    # AdGuard CNAME/cloaked trackers (JSON raw)
    {"url": "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/script/src/cloaked-trackers.json", "format": "cname"},

    # NextDNS CNAME-cloaking blocklist (domains)
    {"url": "https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains", "format": "cname"},

    # OpenPhish (community feed of phishing URLs)
    {"url": "https://openphish.com/feed.txt", "format": "phishing"},

    # PhishTank (online-valid CSV; may need API key for heavy usage)
    {"url": "http://data.phishtank.com/data/online-valid.csv", "format": "phishing"},

    # Classic hosts aggregators (hosts-format)
    {"url": "https://winhelp2002.mvps.org/hosts.zip", "format": "hosts"},
    {"url": "https://someonewhocares.org/hosts/zero/0.0.0.0", "format": "hosts"},  # 0.0.0.0 variant
    {"url": "https://someonewhocares.org/hosts/hosts", "format": "hosts"},

    # hpHosts (historical; site has been unstable or deprecated sometimes)
    {"url": "http://hosts-file.net/ad_servers.txt", "format": "hosts", "note": "deprecated/monitor"},

    # IP/ASN threat feeds (optional; output written to ipset file)
    {"url": "https://www.spamhaus.org/drop/drop.txt", "format": "ip"},
    {"url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "format": "ip"},

    # (Keep this list easily extendable...)
]

WHITELIST_SOURCES = [
    {"url": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt", "format": "adblock"},
    {"url": "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt", "format": "domains"},
    {"url": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt", "format": "domains"},
    {"url": "https://filters.adtidy.org/extension/ublock/filters/17.txt", "format": "adblock"},
]
