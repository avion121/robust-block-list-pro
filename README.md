# Robust Block List Pro

Robust Block List Pro consolidates multiple block lists into a single, comprehensive, and frequently updated list. This project automatically aggregates and formats block list data from various trusted sources.

## Features

- **Automated Updates:**  
  The list is updated daily at 5 AM UTC via GitHub Actions. Manual updates can also be triggered through the GitHub Actions tab.

- **Data Aggregation:**  
  The project fetches data from multiple sources, including uBlock Origin filters, EasyList, malware trackers, and more.

- **Deduplication & Sorting:**  
  It removes duplicate entries and sorts the consolidated list for clarity.

- **Metadata Header:**  
  The generated list includes a header displaying:
  - The title and description.
  - The total number of unique blocked items.
  - The last updated timestamp in UTC.

## Repository Structure

- **.github/workflows/update_list.yml:**  
  Contains the GitHub Actions workflow configuration that:
  - Checks out the repository.
  - Sets up a Python environment.
  - Installs dependencies.
  - Runs the Python script.
  - Commits and pushes any changes to `robust_block_list_pro.txt`.

- **generate_list.py:**  
  The Python script responsible for:
  - Fetching and processing block list data from specified URLs.
  - Generating `robust_block_list_pro.txt` with a formatted header and sorted list.

- **robust_block_list_pro.txt:**  
  The output file containing the consolidated and updated block list.

## Setup and Usage

### Clone the Repository

```bash
git clone https://github.com/your-username/robust-block-list-pro.git
cd robust-block-list-pro
GitHub Actions
No additional configuration is required. The workflow uses the default GITHUB_TOKEN provided by GitHub Actions.

Customize Sources
To add or remove block list sources, simply edit the URLS list in generate_list.py.

Manual Update
You can trigger a manual update via the GitHub Actions tab in your repository.

Requirements
Python 3.x

Requests Library:
The necessary Python libraries are installed automatically by the GitHub Actions workflow.

Acknowledgements
This project is made possible thanks to the work of the following communities and projects:

uBlock Origin

EasyList

EasyPrivacy

Feodo Tracker

Ransomware Tracker

URLhaus

pgl.yoyo.org

Hagezi DNS Blocklists

StevenBlack Hosts

OISD

o0 Pages Dev

Spam404 Lists

Malware Filter

Adguard Team

Phishing Army

Fanboy Annoyance

DandelionSprout Anti-Malware List

Contributing
Contributions, issues, and feature requests are welcome! Please open an issue or submit a pull request.

License
This project is licensed under the MIT License.



---

With these files in place, your project will automatically update a well-formatted, comprehensive block list daily. The Python script now includes improved error handling and formatting, the workflow is correctly set up, and the README provides a clear overview and instructions. Enjoy!
