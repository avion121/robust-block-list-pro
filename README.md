# 🚫 Robust Block List Pro

**Robust Block List Pro** is your go-to, enterprise‑grade blocklist aggregator. Every day at 05:00 UTC, our GitHub Actions workflow pulls from 40+ best‑in‑class ad, tracker, malware, phishing, and annoyance feeds—deduplicates entries, strips out any potential secrets, and publishes a lean, battle‑tested `robust_block_list_pro.txt` for seamless use with uBlock Origin, AdGuard, Pi‑hole, and other DNS‑level blockers.

---

## 📦 Features

* **Daily Auto‑Update**: Cron‑driven GitHub Actions at 05:00 UTC, plus manual dispatch.
* **Multi‑Source Aggregation**: 40+ curated upstream lists covering:

  * Ads & Trackers
  * Malware & Phishing
  * Coin‑Miners & Cryptojacking
  * Anti‑Adblock & Cookie Pop‑ups
  * IoT / SmartTV / Pi‑Hole extensions
  * Regional & Language‑Specific Variants
  * FireHOL IP Blocklists (Level 1–3)
  * Family‑Safe Hosts (SomeoneWhoCares)
* **Smart Filtering**: Removes duplicates and patterns matching API keys or other secrets.
* **Clean, Sorted Output**: Human‑readable header with metadata, then sorted rules.
* **Zero‑Touch Deployment**: Only commits when there’s a change; leverages a PAT for secure pushes.

---

## 🛠️ Quick Start

### Prerequisites

* GitHub repository with write access
* A Personal Access Token (`PAT_TOKEN`) scoped to push commits
* (Optional) Local Python 3.x for testing.

### Installation

1. **Clone** or **fork** this repo.
2. **Add** your token in GitHub:

   1. Go to **Settings → Secrets → Actions**
   2. Click **New repository secret**
   3. Name it `PAT_TOKEN`, paste your token, save.
3. **Review** the workflow at `.github/workflows/update-blocklist.yml`.

### Running Locally

```bash
git clone https://github.com/<you>/robust-block-list-pro.git
cd robust-block-list-pro
python3 generate_list.py
# results in robust_block_list_pro.txt
```

---

## 📝 Output Preview

```text
! Title: Robust Block List Pro
! Description: Combined block list from multiple sources
! Total Blocked Items: 153762
! Updated: 2025-04-13 05:00:00 UTC

0.0.0.0 example-malicious-domain.com
||tracking.adnetwork.com^
||clickbait.example.net^
...
```

---

## ⚙️ Workflow Details

* **Schedule**: `0 5 * * *` (05:00 UTC daily)
* **Trigger**: Manual via **Actions → Run workflow**
* **Steps**:

  1. Checkout code (no persistent credentials)
  2. Setup Python 3.x
  3. Install `requests`
  4. Run `generate_list.py`
  5. Commit & push only on changes

---

## 🔮 Roadmap & To‑Do

* [ ] Domain exclusion (whitelist exceptions)
* [ ] Multi‑format exports (AdGuard, hosts, DNSMasq)
* [ ] Minimal “lite” profile for low‑power devices
* [ ] GitHub Pages dashboard: stats, charts, downloads
* [ ] Automated tests for URL liveness and content sanity

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/name`)
3. Commit your changes (`git commit -m "feat: description"`)
4. Push to branch (`git push origin feature/name`)
5. Open a Pull Request and describe your additions

Please follow the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md).

---

## 📄 License

This project is released under the [MIT License](./LICENSE).

---

*created with ❤️ to make your browsing faster, safer, and more private.*
