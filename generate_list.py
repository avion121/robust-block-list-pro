#!/usr/bin/env python3
"""
generate_list.py

Generates a single, unified, and optimized blocklist for Brave Browser (Desktop & Mobile).
This script fetches rules from high-quality, curated sources, removes duplicates,
and formats the output into a standard Adblock Plus compatible list.
"""
import requests
import datetime
import re
import sys
import time

# --- Configuration ---

# The single, unified output file for both Desktop and Mobile.
OUTPUT_FILENAME = "ultimate_brave_blocklist.txt"
README_FILENAME = "README.md"
LOG_FILENAME = "fetch_errors.log"

# !! IMPORTANT !!
# !! This has been updated with your repository information.
GITHUB_REPO_PATH = "avion121/robust-block-list-pro" # <-- FIX 1: Updated the variable with your repository path.

# Network settings for fetching source files.
REQUEST_TIMEOUT = 30  # seconds
RETRY_COUNT = 2
RETRY_BACKOFF = 5  # seconds

# The curated, high-quality sources for the ULTIMATE TRUE GOAT BLOCK LIST.
# These are selected for effectiveness, low false-positives, and active maintenance.
SOURCES = {
    "General Ad & Tracker Blocking": [
        "https://abp.oisd.nl/",  # OISD Blocklist Full
    ],
    "Enhanced Privacy & Anti-Tracking": [
        # <-- FIX 2: Updated HaGeZi URLs to their new location.
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",  # HaGeZi's Multi PRO
        "https://filters.adtidy.org/windows/filters/3.txt",  # AdGuard Tracking Protection
    ],
    "Security (Malware, Phishing & Scams)": [
        "https://urlhaus.abuse.ch/downloads/hostfile/",  # URLHaus Malicious URLs
        # <-- FIX 2: Updated HaGeZi URLs to their new location.
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt", # HaGeZi's Threat Intelligence Feeds
    ],
    "Annoyance Removal": [
        "https://easylist.to/easylist/fanboy-annoyance.txt",  # Fanboy's Annoyances
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt",  # uBlock Annoyances
    ]
}

# --- Core Logic ---

def fetch_url(url: str) -> tuple[str | None, str | None]:
    """Fetches a URL with retries, a custom user-agent, and returns its text content."""
    headers = {
        f"User-Agent": "ULTIMATE-GOAT-BLOCKLIST-Generator/1.0 (+https://github.com/{GITHUB_REPO_PATH})",
        "Accept-Encoding": "gzip, deflate"
    }
    for attempt in range(RETRY_COUNT + 1):
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            response.raise_for_status()
            return response.text, None
        except requests.exceptions.RequestException as e:
            error_message = f"Failed to fetch {url} on attempt {attempt + 1}: {e}"
            if attempt < RETRY_COUNT:
                time.sleep(RETRY_BACKOFF)
            else:
                return None, error_message
    return None, error_message # Should not be reached, but for safety

def process_line(line: str) -> str | None:
    """Cleans, normalizes, and converts a single line to the correct Adblock format."""
    line = line.strip()

    # Skip empty lines, full comments, and list headers
    if not line or line.startswith(('!', '#', '[Adblock Plus')):
        return None

    # Remove inline comments, but be careful not to damage cosmetic filter rules
    if '##' not in line and '#@#' not in line:
        line = line.split('#', 1)[0].strip()
        if not line:
            return None

    # Convert hosts file format (e.g., "0.0.0.0 example.com") to Adblock format
    match = re.match(r"^(0\.0\.0\.0|127\.0\.0\.1|::)\s+([\w\.-]+)", line)
    if match:
        domain = match.group(2)
        if domain != "localhost":
            return f"||{domain}^"
        return None

    # Return the line if it's already a valid rule
    return line

def generate_blocklist() -> tuple[set[str], list[str]]:
    """Fetches all sources and generates the final, deduplicated blocklist."""
    unique_rules = set()
    errors = []

    print("Fetching rules from sources...")
    for category, urls in SOURCES.items():
        print(f"\n--- Processing Category: {category} ---")
        for url in urls:
            print(f"Fetching: {url}")
            content, error = fetch_url(url)
            if error:
                print(f"  ERROR: {error}")
                errors.append(f"[{datetime.datetime.utcnow().isoformat()}] {error}")
                continue

            count = 0
            for line in content.splitlines():
                processed_rule = process_line(line)
                if processed_rule and processed_rule not in unique_rules:
                    unique_rules.add(processed_rule)
                    count += 1
            print(f"  -> Added {count} new unique rules.")

    return unique_rules, errors

def write_output_files(rules: set[str], errors: list[str]):
    """Writes the final blocklist, README, and error log to disk."""
    if GITHUB_REPO_PATH == "_YOUR_REPO_HERE_/_YOUR_REPO_HERE_":
        print("\n\nCRITICAL ERROR: You must update the 'GITHUB_REPO_PATH' variable in the script.\n\n")
        sys.exit(1)

    sorted_rules = sorted(list(rules))
    now = datetime.datetime.utcnow()
    now_str_header = now.strftime('%a, %d %b %Y %H:%M:%S UTC')
    now_str_readme = now.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # 1. Write the blocklist file
    print(f"\nWriting {len(rules)} rules to {OUTPUT_FILENAME}...")
    with open(OUTPUT_FILENAME, "w", encoding="utf-8") as f:
        f.write("! Title: ULTIMATE TRUE GOAT BLOCK LIST\n")
        f.write("! Description: A unified and optimized blocklist for Brave Browser (Desktop & Mobile). Combines the best lists for ads, tracking, malware, and annoyances.\n")
        f.write(f"! Last Updated: {now_str_header}\n")
        f.write("! Expires: 6 hours (updates automatically)\n")
        f.write(f"! Homepage: https://github.com/{GITHUB_REPO_PATH}\n")
        f.write("! Version: 1.0\n")
        f.write("\n")
        for rule in sorted_rules:
            f.write(rule + "\n")
    print("Blocklist generation complete.")

    # 2. Write the error log
    if errors:
        print(f"Writing {len(errors)} errors to {LOG_FILENAME}...")
        with open(LOG_FILENAME, "w", encoding="utf-8") as f:
            for error in errors:
                f.write(error + "\n")
    else:
        open(LOG_FILENAME, "w").close()
        print("No fetch errors occurred.")

    # 3. Write the README file
    print(f"Generating {README_FILENAME}...")
    with open(README_FILENAME, "w", encoding="utf-8") as f:
        f.write("# ULTIMATE TRUE GOAT BLOCK LIST for Brave Browser\n\n")
        f.write(f"**Last Updated:** `{now_str_readme}`  \n")
        f.write(f"**Total Rules:** `{len(rules)}`\n\n")
        f.write("A single, powerful, and optimized blocklist designed to work perfectly with Brave Browser on both **Desktop and Mobile**. It provides comprehensive, all-around protection against ads, trackers, malware, and annoyances without breaking websites.\n\n")
        f.write("## 🚀 How to Use\n\n")
        f.write("Simply add the following URL to your Brave browser's custom filter lists.\n\n")
        f.write("**Blocklist URL:**\n")
        f.write(f"```\nhttps://raw.githubusercontent.com/{GITHUB_REPO_PATH}/main/ultimate_brave_blocklist.txt\n```\n")
        f.write("\n**Instructions:**\n")
        f.write("1. In Brave, go to `Settings` -> `Shields` -> `Content filtering`.\n")
        f.write("2. On Desktop, you can also navigate directly to `brave://settings/shields/filters`.\n")
        f.write("3. Scroll down to **\"Add custom filter lists\"**.\n")
        f.write("4. Paste the blocklist URL above and click `Add`.\n\n")
        f.write("That's it! The list will update automatically.\n\n")
        f.write("## ✨ Features\n\n")
        f.write("- **Unified & Optimized**: One list for both Desktop and Mobile. No need for separate versions.\n")
        f.write("- **Highly Compatible**: Does not break websites, thanks to carefully selected sources.\n")
        f.write("- **Comprehensive**: Blocks ads, trackers, malware, phishing, and annoyances.\n")
        f.write("- **No Duplicates**: Automatically cleaned and deduplicated for efficiency.\n")
        f.write("- **Always Fresh**: Automatically updates every 6 hours to catch the latest threats.\n\n")
        f.write("## 📚 Sources Included\n\n")
        f.write("This list is built from the following best-in-class sources:\n\n")
        for category, urls in SOURCES.items():
            f.write(f"### {category}\n")
            for url in urls:
                f.write(f"- `{url}`\n")
            f.write("\n")
        f.write("---\n*This project is automated via GitHub Actions. Any fetch errors are logged in `fetch_errors.log`.*")

def main():
    """Main function to run the script."""
    final_rules, fetch_errors = generate_blocklist()
    if not final_rules:
        print("CRITICAL: No rules were generated. Aborting file write to prevent creating an empty list.")
        with open(LOG_FILENAME, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.utcnow().isoformat()}] CRITICAL: No rules were generated. Check all sources.\n")
        return 1
    
    write_output_files(final_rules, fetch_errors)
    return 0

if __name__ == "__main__":
    sys.exit(main())
