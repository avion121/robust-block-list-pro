# 🚫 Robust Block List Pro

**Robust Block List Pro** is a high-performance, daily-updated blocklist that combines entries from the most reliable ad, tracker, malware, phishing, and annoyance filter sources. It is designed to work seamlessly with adblockers like **uBlock Origin**, **AdGuard**, and **Pi-hole**, to enhance security, privacy, and browsing performance across all platforms.

---

## 📋 What It Does

- ✅ Aggregates entries from **38+ highly curated filter lists**
- 🔁 **Auto-updates daily at 5:00 AM UTC** via GitHub Actions
- 🧹 Automatically removes duplicates and potential API keys or secrets
- 🧪 Filters out malformed or suspicious entries
- 🧾 Outputs a clean and sorted `robust_block_list_pro.txt` file

---

## 🛠️ How It Works

1. The Python script [`generate_list.py`](./generate_list.py):
   - Fetches all configured blocklists
   - Merges and deduplicates rules
   - Filters lines resembling secrets (API keys, tokens, etc.)
   - Generates a sorted, unified list with metadata

2. GitHub Actions:
   - Runs daily (`cron: 0 5 * * *`)
   - Commits only if content has changed
   - Uses a Personal Access Token (`PAT_TOKEN`) for pushing changes

---

## 📂 Output Preview


! Title: Robust Block List Pro
! Description: Combined block list from multiple sources
! Total Blocked Items: 153762
! Updated: 2025-04-13 05:00:00 UTC

0.0.0.0 example-malicious-domain.com
||tracking.adnetwork.com^
||clickbait.example.net^
⚙️ Tech Stack
Python 3.x

GitHub Actions

requests Python package

🔐 GitHub Actions Secrets
Secret Name	Description
PAT_TOKEN	GitHub Personal Access Token with repo scope for pushing commits

Add this in your repository:
Settings > Secrets and Variables > Actions > New repository secret

📅 Automation Schedule
⏱ Runs automatically every day at 5:00 AM UTC

▶️ Can also be manually triggered via GitHub Actions → Run workflow

🚀 To Do / Future Features
 Add domain exclusion support (block exceptions)

 Output support for multiple formats (e.g., AdGuard, hosts, raw DNS)

 Optional minimal version (for performance)

 GitHub Pages dashboard (visual UI, stats, download buttons)

📄 License
This project is open-source under the MIT License.

Created with ❤️ to make the web safer, faster, and more private.











