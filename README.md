🚫 Robust Block List Pro
Robust Block List Pro is the ultimate, enterprise-grade blocklist aggregator designed to deliver a faster, safer, and more private browsing experience. Every day at 05:00 UTC, our GitHub Actions workflow aggregates 65+ best-in-class feeds covering ads, trackers, malware, phishing, cryptojacking, annoyances, and more. It deduplicates entries, filters potential secrets, and generates a lean, battle-tested robust_block_list_pro.txt compatible with uBlock Origin, AdGuard, Pi-hole, and other DNS-level blockers.

📦 Features

Daily Auto-Update: Cron-driven GitHub Actions at 05:00 UTC, with manual dispatch option.
Comprehensive Multi-Source Aggregation: 65+ curated upstream lists, including:
Ads & Trackers: uBlock Origin, EasyList, StevenBlack, HaGeZi Pro/Ultimate, OISD Full, AdAway, DeveloperDan, AnudeepND
Malware & Phishing: Abuse.ch, Phishing Army (Extended), Malware-Filter, NoTrack, Mandiant APT1, Talos Intelligence, Blocklist Project
Coin-Miners & Cryptojacking: CoinBlocker, NoCoin, Anti-Adblock Killer
Anti-Adblock & Annoyances: Fanboy Annoyance, I Don't Care About Cookies, AdGuard AntiAnnoyances, Cookiemonster
IoT / SmartTV / Pi-Hole: Perflyst SmartTV, durablenapkin scamblocklist
Telemetry & Privacy: Disconnect.me, Privacy Badger, WindowsSpyBlocker, Frogeye First-Party Trackers
Regional & Language-Specific: EasyList (Japan, Germany, France, Spain, Russia, China, Italy), KADhosts (Poland), HostsVN (Vietnam), ArabList, AdGuard Chinese
Threat Intelligence: FireHOL (Levels 1–3), MVPS Hosts, SomeoneWhoCares (family-safe)


Smart Filtering: Removes duplicates and patterns matching API keys or sensitive data (e.g., 40–60 char tokens, "apikey", "IBM").
Clean, Sorted Output: Human-readable header with metadata (total items, update timestamp) and sorted rules.
Zero-Touch Deployment: Commits only on changes, using a Personal Access Token (PAT) for secure pushes.
Ultimate Power: Combines OISD Full and HaGeZi Ultimate for millions of blocked domains, tackling 2025 threats like AI-generated phishing and telemetry.


🛠️ Quick Start
Prerequisites

GitHub repository with write access
A Personal Access Token (PAT_TOKEN) scoped to push commits
(Optional) Local Python 3.x for testing

Installation

Clone or fork this repo:git clone https://github.com/<your-username>/robust-block-list-pro.git


Add your token in GitHub:
Go to Settings → Secrets and variables → Actions → Secrets
Click New repository secret
Name it PAT_TOKEN, paste your token, and save


Review the workflow at .github/workflows/update-blocklist.yml

Running Locally
cd robust-block-list-pro
python3 generate_list.py
# Outputs robust_block_list_pro.txt


📝 Output Preview
! Title: Robust Block List Pro
! Description: Combined block list from multiple sources
! Total Blocked Items: ~5000000
! Updated: 2025-08-24 05:00:00 UTC

0.0.0.0 example-malicious-domain.com
||tracking.adnetwork.com^
||clickbait.example.net^
...

Note: Total items vary (estimated 5–10M unique entries after deduplication) based on upstream updates.

⚙️ Workflow Details

Schedule: 0 5 * * * (05:00 UTC daily)
Trigger: Manual via Actions → Run workflow
Steps:
Checkout code (no persistent credentials)
Set up Python 3.x
Install requests library
Run generate_list.py
Commit and push changes only if the blocklist updates




🔮 Roadmap & To-Do

 Add domain exclusion (whitelist exceptions)
 Support multi-format exports (AdGuard, hosts, DNSMasq)
 Create a minimal "lite" profile for low-power devices
 Build GitHub Pages dashboard with stats, charts, and downloads
 Implement automated tests for URL liveness and content sanity
 Add logging for filtered lines and error handling


🤝 Contributing

Fork the repo
Create a feature branch (git checkout -b feature/name)
Commit your changes (git commit -m "feat: description")
Push to branch (git push origin feature/name)
Open a Pull Request and describe your additions

Please adhere to the Contributor Covenant Code of Conduct.

📄 License
This project is released under the MIT License.

Created with ❤️ to make your browsing faster, safer, and more private. The ultimate TRUE GOAT blocklist for 2025 and beyond.
