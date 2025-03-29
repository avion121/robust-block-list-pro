import requests

# List of URLs to fetch content from
urls = [
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/quick-fixes.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "https://blocklistproject.github.io/Lists/tracking.txt",
    "https://easylist.to/easylistgermany/easylistgermany.txt",
    "https://easylist-downloads.adblockplus.org/advblock.txt",
    "https://raw.githubusercontent.com/craiu/mobiletrackers/master/list.txt",
    "https://ssl.bblck.me/blacklists/audio-video.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout%27s%20Anti-Malware%20List.txt"
]

def fetch_content(url):
    """Fetch content from the given URL and return text."""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Error fetching {url}: Status code {response.status_code}")
            return ""
    except Exception as e:
        print(f"Exception fetching {url}: {e}")
        return ""

def main():
    combined_content = ""
    for url in urls:
        content = fetch_content(url)
        # Add a header for clarity (optional)
        combined_content += f"# Content from {url}\n" + content + "\n\n"
    
    # Optional: Remove duplicate lines if needed
    # lines = combined_content.splitlines()
    # unique_lines = list(dict.fromkeys(lines))
    # combined_content = "\n".join(unique_lines)
    
    with open("robust_block_list_pro.txt", "w", encoding="utf-8") as file:
        file.write(combined_content)
    
    print("robust_block_list_pro.txt updated successfully.")

if __name__ == "__main__":
    main()
