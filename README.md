Robust Block List Pro

The Ultimate, Most Powerful Ad, Tracker, Malware, and Scam Blocking List

Robust Block List Pro is a dynamically generated, comprehensive block list designed to deliver unmatched protection against ads, trackers, malware, phishing, cryptojacking, scams, pop-ups, and other online threats. Aggregating over 70 high-quality sources, including uBlock Origin, EasyList, AdGuard, hagezi, blocklistproject, and advanced threat intelligence feeds, this list is crafted to be the ULTIMATE TRUE GOAT (Greatest of All Time) for privacy and security enthusiasts. Updated daily via GitHub Actions, it ensures fresh, effective blocking for tools like uBlock Origin, Pi-hole, AdGuard Home, and more.

Features





Massive Coverage: Combines core, regional, and specialized block lists for ads, trackers, malware, phishing, scams, cryptojacking, pop-ups, and native OS telemetry.



Daily Updates: Automated via GitHub Actions at 5:00 AM UTC to block the latest threats.



Deduplication & Safety: Removes duplicates and filters potential secrets (e.g., API keys) for a clean, efficient list.



Broad Compatibility: Works with browser extensions (uBlock Origin, AdBlock Plus), DNS blockers (Pi-hole, AdGuard Home), and hosts-based filtering.



Open Source: Freely available, with contributions welcome to enhance its power.

Block List Sources

Robust Block List Pro aggregates from the following trusted sources, organized by category:

Core Filters





uBlock Origin: Core filters, badware, privacy, quick fixes, unbreak



EasyList & EasyPrivacy: Global ad and tracking lists



AdGuard: Mobile, anti-annoyance, spyware filters



Fanboy: Annoyance and anti-adblock filters

Malware & Phishing





abuse.ch: Feodo Tracker IP blocklist, URLhaus hostfile



phishing.army: Standard and extended phishing blocklists



blocklistproject: Malware, phishing, scam, crypto, tracking lists



Malware Filter: Dedicated phishing and malware domains

Ads & Tracking





StevenBlack Hosts: Fakenews and gambling variants



hagezi: Pro, Ultimate, Pop-up Ads, Native Trackers, Threat Intelligence Feeds (TIF)



Disconnect: Simple tracking and ad lists



Privacy Badger: EFF's tracker list



pgl.yoyo.org: Ad server hosts

Anti-Adblock & Cryptojacking





Anti-Adblock Killer: Reek's anti-adblock filters



CoinBlocker & NoCoin: Cryptojacking protection



bogachenko: Anti-adblock countermeasures

Regional & Specialized





EasyList Regional: Japan, Germany, France, Spain, Russia, China, Italy, Dutch, Indonesia, Arabic



AdGuard Chinese: China-specific ad servers



SmartTV & IoT: Perflyst's SmartTV blocklist, durable napkin scam hosts



FireHOL: Levels 1-3 IP blocklists



Family-Safe: someonewhocares.org hosts

GOAT Enhancements





Threat Intelligence: hagezi TIF (malware, C2, phishing)



Scams & Crypto: blocklistproject scam and crypto lists



Pop-ups: hagezi pop-up ads



Native Trackers: hagezi multi-platform telemetry (Apple, Google, Microsoft)



Extended Ads/Tracking: AdGuard DNS, Disconnect Simple Ads, developerdan



Risky Content: FadeMind's add.Risk hosts

For the complete list of sources, see generate_list.py.

Installation





Clone or Download the Repository:

git clone https://github.com/<your-username>/<your-repo>.git



Install Python 3: Ensure Python 3.x is installed on your system.



Install Dependencies:

pip install requests



Run the Script:

python generate_list.py

This generates robust_block_list_pro.txt in the repository root.

Usage

uBlock Origin / AdBlock Plus





Open your ad blocker's settings.



Add the list URL:

https://raw.githubusercontent.com/<your-username>/<your-repo>/main/robust_block_list_pro.txt



Update filters to apply.

Pi-hole / AdGuard Home





Add the list URL to your blocklist sources in the admin interface.



Update gravity or refresh to apply.



Note: Convert hosts-format entries (e.g., 127.0.0.1 domain) to domains if needed for DNS-based blockers.

Hosts File

Append the contents of robust_block_list_pro.txt to your system's hosts file:





Linux: /etc/hosts



Windows: C:\Windows\System32\drivers\etc\hostsEnsure proper formatting for hosts-based blocking.

Automation

The block list is updated daily at 5:00 AM UTC via the GitHub Actions workflow defined in update-robust-block-list-pro.yml. To enable automation in your repository:





Create a Personal Access Token (PAT) with repo scope.



Store it in your repository's secrets as PAT_TOKEN.



The workflow will:





Check out the repository.



Run generate_list.py.



Commit and push updates to robust_block_list_pro.txt if changes are detected.

Contributing

We welcome contributions to make Robust Block List Pro the ULTIMATE GOAT block list! To contribute:





Add New Sources:





Suggest high-quality, low-false-positive block lists via issues or pull requests.



Include the URL, category, and rationale for inclusion.



Improve the Script:





Enhance generate_list.py (e.g., add hosts-to-ABP conversion, logging, or retry logic).



Report Issues:





Open an issue for false positives, broken sources, or script errors.



Fork the repository, make changes, and submit a pull request with a clear description.

Notes





Performance: With over 70 sources, the list is extensive. Test for false positives (e.g., legitimate sites breaking) and optimize for your tool's limits (e.g., Pi-hole's gravity size).



Format Compatibility: The script combines ABP-style (||domain^) and hosts-style (127.0.0.1 domain) entries. For DNS blockers, you may need to parse hosts entries into domain lists.



Testing: Test updates in a controlled environment before deploying to production systems.



License: This project is licensed under the MIT License.

Acknowledgments

Special thanks to the maintainers of uBlock Origin, EasyList, AdGuard, hagezi, blocklistproject, and all source lists for their invaluable contributions to a safer internet.

For questions or support, open an issue or contact the maintainer at [your-email@example.com].



Generated and maintained by Robust Block List Pro - The Ultimate GOAT Block List
