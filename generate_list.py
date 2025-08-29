#!/usr/bin/env python3
import requests, datetime, os

# ===============================
# File Paths
# ===============================
COMBINED_OUTPUT = "robust_block_list_pro_combined.txt"
IOS_LITE_OUTPUT = "robust_block_list_ios_lite.txt"
README = "README.md"
FETCH_LOG = "fetch_errors.log"

# ===============================
# Sources
# ===============================
SOURCES_MONSTER = [
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_1_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Spyware/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Social/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Annoyances/filter.txt",
    "https://curben.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
    "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
    "https://someonewhocares.org/hosts/hosts",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/extra.txt",
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"
]

SOURCES_IOS_LITE = [
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_1_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Spyware/filter.txt",
    "https://curben.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
    "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"
]

# ===============================
# Fetch Utility
# ===============================
def fetch_list(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        lines = r.text.splitlines()
        domains = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith(("#", "!", "//")):
                continue
            if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
                parts = line.split()
                if len(parts) > 1:
                    domains.add(parts[1].lower())
            elif line.startswith(("||", ".")):
                domains.add(line.lstrip("|.").split("^")[0].lower())
            elif " " not in line and "." in line:
                domains.add(line.lower())
        return domains, None
    except Exception as e:
        return set(), f"{url} failed: {e}"

# ===============================
# Generate
# ===============================
def generate_blocklist(sources, output_file):
    all_domains = set()
    results = {}
    errors = []
    for url in sources:
        domains, err = fetch_list(url)
        if err:
            errors.append(f"[{datetime.datetime.utcnow()}] {err}\n")
        results[url] = len(domains)
        all_domains.update(domains)
    with open(output_file, "w") as f:
        for d in sorted(all_domains):
            f.write(d + "\n")
    return results, len(all_domains), errors

# ===============================
# README Generator
# ===============================
def generate_readme(results_monster, results_ios, monster_count, ios_count):
    last_updated = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # prepare changelog entry
    changelog_entry = f"- **{last_updated}** → Monster: `{monster_count}` domains, iOS Lite: `{ios_count}` domains\n"

    # read old changelog
    old_changelog = []
    if os.path.exists(README):
        with open(README, "r") as old:
            lines = old.readlines()
            if "## 📜 Changelog" in "".join(lines):
                idx = lines.index("## 📜 Changelog\n")
                old_changelog = lines[idx+1:]

    combined_changelog = [changelog_entry] + old_changelog
    combined_changelog = combined_changelog[:4]  # keep 4 entries max

    with open(README, "w") as f:
        f.write("# 🛡️ Robust Block List Pro\n\n")
        f.write(f"![Last Updated](https://img.shields.io/badge/Last%20Updated-{last_updated.replace(' ', '%20')}-blue)\n")
        f.write(f"![Monster Domains](https://img.shields.io/badge/Monster%20Domains-{monster_count}-brightgreen)\n")
        f.write(f"![iOS Lite Domains](https://img.shields.io/badge/iOS%20Lite%20Domains-{ios_count}-yellow)\n\n")
        f.write("Automatically updated ultimate blocklists for ads, trackers, malware, and telemetry.\n\n")

        # 📥 downloads
        f.write("## 📥 Direct Downloads\n")
        f.write(f"[![Download Monster](https://img.shields.io/badge/Download-Monster-blue)](https://raw.githubusercontent.com/avion121/robust-block-list-pro/main/{COMBINED_OUTPUT})\n")
        f.write(f"[![Download iOS Lite](https://img.shields.io/badge/Download-iOS%20Lite-orange)](https://raw.githubusercontent.com/avion121/robust-block-list-pro/main/{IOS_LITE_OUTPUT})\n\n")

        # 📦 variants
        f.write("## 📦 Blocklist Variants\n")
        f.write("- **Monster (Full)** → `robust_block_list_pro_combined.txt`\n")
        f.write("- **iOS Lite (Safe Subset)** → `robust_block_list_ios_lite.txt`\n\n")

        # ✅ usage
        f.write("## ✅ Recommended Usage\n")
        f.write("- **Monster (Full)** → Best for desktops, routers, and power users.\n")
        f.write("- **iOS Lite (Safe Subset)** → Optimized for iOS/Android apps.\n\n")
        f.write("_Tip: If you experience app/site breakage on mobile, switch to iOS Lite._\n\n")

        # 🔗 sources
        f.write("## 🔗 Sources\n")
        f.write("### Monster (22 lists)\n")
        for url in SOURCES_MONSTER:
            f.write(f"- {url}\n")
        f.write("\n### iOS Lite (7 lists)\n")
        for url in SOURCES_IOS_LITE:
            f.write(f"- {url}\n")

        # 📜 changelog
        f.write("\n## 📜 Changelog\n")
        for entry in combined_changelog:
            f.write(entry)

# ===============================
# Main
# ===============================
if __name__ == "__main__":
    res_monster, monster_count, err_monster = generate_blocklist(SOURCES_MONSTER, COMBINED_OUTPUT)
    res_ios, ios_count, err_ios = generate_blocklist(SOURCES_IOS_LITE, IOS_LITE_OUTPUT)

    # log fetch errors separately
    with open(FETCH_LOG, "w") as log:
        for e in err_monster + err_ios:
            log.write(e)

    # update readme
    generate_readme(res_monster, res_ios, monster_count, ios_count)