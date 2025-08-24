#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor
from generate_list import BLOCKLIST_URLS, WHITELIST_URLS, HEADERS

def check(url: str) -> str | None:
    try:
        # some endpoints don't like HEAD; stream GET is cheap and reliable
        r = requests.get(url, headers=HEADERS, timeout=20, allow_redirects=True, stream=True)
        return None if r.ok else f"{url} (Status: {r.status_code})"
    except requests.RequestException as e:
        return f"{url} (Error: {e})"

def validate_urls(urls):
    bad = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(check, urls):
            if res:
                bad.append(res)
    return bad

def main():
    print("Validating blocklist URLs...")
    bad_block = validate_urls(BLOCKLIST_URLS)
    print("Validating whitelist URLs...")
    bad_white = validate_urls(WHITELIST_URLS)
    if bad_block or bad_white:
        print("Invalid URLs found:")
        for s in bad_block:
            print(f"Blocklist: {s}")
        for s in bad_white:
            print(f"Whitelist: {s}")
    else:
        print("All URLs are valid.")

if __name__ == "__main__":
    main()
