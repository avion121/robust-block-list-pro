import requests

# ✅ Curated, stable blocklist sources (Aug 24, 2025)
BLOCKLIST_URLS = [
    # Core ad & privacy
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",

    # Fanboy extras
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://easylist-downloads.adblockplus.org/fanboy-social.txt",
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",

    # Crypto miners
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",

    # Hosts-format sources
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",

    # Security-focused (domains/ABP)
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",

    # Hagezi
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",

    # Regional EasyList
    "https://easylist-downloads.adblockplus.org/easylistgermany.txt",
    "https://easylist-downloads.adblockplus.org/indianlist%2Beasylist.txt",
]

WHITELIST_URLS = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
]

OUTPUT_FILE = "robust_block_list_pro.txt"
LOG_FILE = "fetch_errors.log"


def fetch_list(url):
    """Fetch a list safely, skipping broken URLs and logging failures."""
    try:
        response = requests.get(url, headers={"Accept-Encoding": "identity"}, timeout=25)
        if response.status_code == 200:
            return response.text.splitlines()
        else:
            with open(LOG_FILE, "a", encoding="utf-8") as log:
                log.write(f"[HTTP {response.status_code}] {url}\n")
            return []
    except Exception as e:
        with open(LOG_FILE, "a", encoding="utf-8") as log:
            log.write(f"[ERROR] {url} → {e}\n")
        return []


def generate_combined_blocklist():
    block_entries = set()
    whitelist_entries = set()

    # Fetch all blocklist entries
    for url in BLOCKLIST_URLS:
        lines = fetch_list(url)
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "localhost" in line:
                continue
            block_entries.add(line.lower())

    # Fetch all whitelist entries
    for url in WHITELIST_URLS:
        lines = fetch_list(url)
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            whitelist_entries.add(line.lower())

    # Apply whitelist
    final_entries = block_entries - whitelist_entries
    return sorted(final_entries)


if __name__ == "__main__":
    # Clear log file at start
    open(LOG_FILE, "w").close()

    combined = generate_combined_blocklist()
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(combined))

    print(f"✅ Final blocklist: {len(combined)} entries → {OUTPUT_FILE}")
    print(f"ℹ️ Errors (if any) logged in {LOG_FILE}")
