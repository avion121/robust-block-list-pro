# Robust Block List Pro

Robust Block List Pro consolidates multiple block lists into a single, comprehensive, and frequently updated list. This project automatically aggregates and formats block list data from various trusted sources.

## Features

- **Automated Updates:**  
  The list is updated daily at 5 AM UTC via GitHub Actions. Manual updates can also be triggered through the GitHub Actions tab.

- **Data Aggregation:**  
  The project fetches data from multiple sources, including uBlock Origin filters, EasyList, malware trackers, host‑based lists, resource‑abuse filters, and anti‑adblock bypass lists.

- **Deduplication & Sorting:**  
  It removes duplicate entries and sorts the consolidated list for clarity.

- **Metadata Header:**  
  The generated list includes a header displaying:
  - The title and description.
  - The total number of unique blocked items.
  - The last updated timestamp in UTC.

## Repository Structure

- **.github/workflows/update_robust_block_list_pro.yml:**  
  Contains the GitHub Actions workflow configuration that:
  - Checks out the repository.
  - Sets up a Python environment.
  - Installs dependencies.
  - Runs the Python script.
  - Commits and pushes any changes to `robust_block_list_pro.txt`.

- **generate_list.py:**  
  The Python script responsible for:
  - Fetching and processing block list data from the specified URLs.
  - Including resource‑abuse, Anti‑Adblock Warning Removal List, and Anti‑Adblock Killer (AakList).
  - Omitting deprecated sources (e.g., mirror1.malwaredomains.com).
  - Generating `robust_block_list_pro.txt` with a formatted header and sorted list.

- **robust_block_list_pro.txt:**  
  The output file containing the consolidated and updated block list.

## Setup and Usage

### Clone the Repository

```bash
git clone https://github.com/your-username/robust-block-list-pro.git
cd robust-block-list-pro
```

### GitHub Actions

No additional configuration is required. The workflow uses the default `GITHUB_TOKEN` provided by GitHub Actions and a `PAT_TOKEN` secret for pushing changes.

### Customize Sources

To add or remove block list sources, simply edit the `URLS` list in `generate_list.py`. The current configuration includes:

- Core uBlock filters (ads, privacy, badware, quick‑fixes, unbreak)
- EasyList & EasyPrivacy
- Malware and phishing trackers (Abuse.ch, RansomwareTracker, URLhaus)
- Host‑based lists (StevenBlack, Spam404, OISD, etc.)
- Resource‑Abuse filters to block hidden crypto‑miners and fingerprinting
- Anti‑Adblock Warning Removal List
- Anti‑Adblock Killer (AakList)

### Manual Update

You can trigger a manual update via the GitHub Actions tab in your repository.

## Requirements

- Python 3.x
- [requests](https://pypi.org/project/requests/)

The necessary Python libraries are installed automatically by the GitHub Actions workflow.

## Acknowledgements

This project is made possible thanks to the work of the following communities and projects:

- uBlock Origin
- EasyList & EasyPrivacy
- Feodo Tracker & Ransomware Tracker
- URLhaus
- pgl.yoyo.org (Peter Lowe’s hosts)
- Hagezi DNS Blocklists
- StevenBlack Hosts
- OISD & o0 Pages Dev
- Spam404 Lists
- Malware Filter
- Adguard Team
- Phishing Army
- Fanboy Annoyance
- DandelionSprout Anti‑Malware List
- **Anti‑Adblock Warning Removal List**
- **Anti‑Adblock Killer (AakList)**
- **uBlock filters – Resource Abuse**

## Contributing

Contributions, issues, and feature requests are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.

---

With these updates, your README now reflects the added resource‑abuse and anti‑adblock sources, the removal of deprecated feeds, and the correct workflow filename and usage instructions. Enjoy!

