# 🚫 Robust Block List Pro

**Robust Block List Pro** is a daily auto-updated, consolidated block list that aggregates entries from the most trusted adblock, malware, privacy, and phishing filter sources. This list is intended to enhance online security, block malicious domains, and improve privacy across browsers and devices.

---

## 📋 What It Does

- ✅ Aggregates entries from 20+ curated block list sources
- 🔄 Automatically updates every day at **5:00 AM UTC** using GitHub Actions
- 🧹 Filters out any lines that may accidentally contain secrets (e.g., API keys)
- 📄 Outputs a clean `robust_block_list_pro.txt` file in the root of the repository

---

## 🛠️ How It Works

1. Python script `generate_list.py` fetches and merges entries from all sources.
2. Removes duplicates and filters lines with patterns that resemble sensitive data.
3. Generates a final sorted list with a detailed header.
4. Commits the updated file to the repository automatically via GitHub Actions.

---

## 🧪 Tech Stack

- **Python 3.x**
- **GitHub Actions** for automation
- **Requests** library for HTTP requests

---

## 🔐 Secrets Used in GitHub Actions

| Name       | Description                         |
|------------|-------------------------------------|
| `PAT_TOKEN`| Personal Access Token with `repo` scope to push changes |

Add this secret via:
Settings > Secrets and Variables > Actions > New repository secret

yaml
Copy
Edit

---

## 📂 Output Example


! Title: Robust Block List Pro
! Description: Combined block list from multiple sources
! Total Blocked Items: 153762
! Updated: 2025-04-13 05:00:00 UTC

0.0.0.0 example-malicious-domain.com
||tracking.adnetwork.com^
||clickbait.example.net^
...
📅 Automation Schedule
Runs every day at 5:00 AM UTC

Can also be manually triggered via GitHub Actions > Run workflow

📌 To Do (Future Ideas)
 Add option to exclude specific domains

 Output in multiple formats (Adblock Plus, uBlock Origin, Hosts)

 Add user dashboard or GitHub Pages UI

📄 License
This project is open-source under the MIT License.

Created with ❤️ to promote a safer, faster, and more private internet experience.

yaml
Copy
Edit

---

Let me know if you'd like help creating a `LICENSE` file or setting up GitHub Pages to show a visual summary of the block list!
