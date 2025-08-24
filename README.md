Robust Block List Pro
Overview
Robust Block List Pro is a comprehensive, automated block list that aggregates and curates entries from multiple trusted sources to block ads, trackers, malware, and other unwanted content. This project uses a GitHub Actions workflow to fetch, process, and combine block lists daily, producing a single, unified block list (robust_block_list_pro.txt) for use in ad blockers, DNS filters, or other content filtering tools.
Features

Daily Updates: Automatically updates every day at 5:00 AM UTC using GitHub Actions.
Curated Sources: Combines high-quality block lists from sources like uBlock Origin, EasyList, AdGuard, and more.
Deduplication: Removes duplicate entries to ensure a clean and efficient list.
Whitelist Support: Excludes whitelisted domains to prevent false positives.
Secret Filtering: Filters out potential API keys or sensitive tokens for safety.
Single Output: Generates one unified block list (robust_block_list_pro.txt) for easy integration.

Usage

Download the Block List: Get the latest robust_block_list_pro.txt from the Releases or directly from the repository.
Integrate with Tools: Import the list into your preferred ad blocker (e.g., uBlock Origin, AdGuard) or DNS filter (e.g., Pi-hole).
Stay Updated: The list is updated daily, so configure your tool to check for updates regularly.

Setup for Development
To run or modify the block list generation locally:

Clone the Repository:git clone https://github.com/<your-repo>.git
cd robust-block-list-pro


Install Dependencies:Ensure you have Python 3.11 installed, then run:pip install requests tenacity


Run the Script:Execute the generation script:python generate_list.py

This will fetch the block lists, process them, and generate robust_block_list_pro.txt.

GitHub Actions Workflow
The project uses a GitHub Actions workflow (robust_block_list_pro.yml) to:

Run daily at 5:00 AM UTC.
Fetch and process block lists using generate_list.py.
Commit and push the updated robust_block_list_pro.txt to the repository.

To customize the workflow:

Update the PAT_TOKEN secret in your GitHub repository settings for authenticated pushes.
Modify BLOCKLIST_URLS in generate_list.py to add or remove sources.

Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a new branch (git checkout -b feature/your-feature).
Make your changes (e.g., add new block list sources, improve filtering logic).
Test locally using python generate_list.py.
Push your changes and create a pull request.

Please ensure new block list sources are reliable and do not introduce duplicates or invalid entries.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Contact
For issues or suggestions, open an issue on the GitHub repository or contact the maintainer at your-email@example.com.
