
#!/usr/bin/env python3
import requests
from generate_list import BLOCKLIST_URLS, WHITELIST_URLS

def validate_urls(urls):
    invalid_urls = []
    for url in urls:
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code != 200:
                invalid_urls.append(f"{url} (Status: {response.status_code})")
        except requests.RequestException as e:
            invalid_urls.append(f"{url} (Error: {e})")
    return invalid_urls

def main():
    print("Validating blocklist URLs...")
    invalid_blocklists = validate_urls(BLOCKLIST_URLS)
    print("Validating whitelist URLs...")
    invalid_whitelists = validate_urls(WHITELIST_URLS)
    
    if invalid_blocklists or invalid_whitelists:
        print("Invalid URLs found:")
        for url in invalid_blocklists:
            print(f"Blocklist: {url}")
        for url in invalid_whitelists:
            print(f"Whitelist: {url}")
    else:
        print("All URLs are valid.")

if __name__ == "__main__":
    main()

