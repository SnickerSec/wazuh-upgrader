# Wazuh Component Upgrade Script

This Python script is designed to facilitate the upgrade of individual Wazuh components (Indexer, Manager, or Dashboard) on an Ubuntu system. It automates the process of fetching upgrade instructions, stopping relevant services, installing updates, and configuring components.

## Script Functionality

*   **Fetches Upgrade Data:** Extracts necessary URLs from the official Wazuh upgrade guide.
*   **Executes System Commands:** Runs shell commands with logging and error handling.
*   **Installs Packages:** Handles package installations using `apt-get`.
*   **Retrieves Wazuh Indexer Address:** Determines the Wazuh Indexer address (assuming localhost for simplicity).
*   **Sets Up Wazuh Repository:** Configures the system to access the Wazuh package repository.
*   **Stops Indexer Services:** Handles Wazuh Indexer service manipulation for updates.
*   **Stops Filebeat and Wazuh Dashboard:** Manages the stopping of Filebeat and Wazuh Dashboard.
*   **Upgrades Components:** Provides functions to upgrade individual Wazuh components:
    *   **Indexer:** Upgrades the Wazuh Indexer component.
    *   **Manager:** Upgrades the Wazuh Manager component, including Filebeat configurations.
    *   **Dashboard:** Upgrades the Wazuh Dashboard component.
*   **Main Function:** Parses command-line arguments and orchestrates the upgrade process.

## Dependencies

*   `argparse`
*   `os`
*   `requests`
*   `lxml`
*   `delegator`
*   `logging`
*   `socket`

## Environment Variables

*   `WAZUH_USERNAME`
*   `WAZUH_PASSWORD`

## Usage

1.  **Set Environment Variables:** Configure `WAZUH_USERNAME` and `WAZUH_PASSWORD` with your Wazuh credentials.
2.  **Run the Script:** Execute the script from the command line, specifying the component to upgrade:

    ```bash
    python wazuh_upgrade.py <component>
    ```

    Replace `<component>` with one of the following:

    *   `indexer`
    *   `manager`
    *   `dashboard`

## Example

```bash
python wazuh_upgrade.py manager
```

## Important Considerations

*   **Wazuh Indexer Address:** The script assumes the Wazuh Indexer is listening on localhost. Adjust the `get_wazuh_indexer_address` function if your configuration is different.
*   **Error Handling:** The script includes error handling and logging to assist in troubleshooting any issues during the upgrade process.
*   **Backup:** It's strongly recommended to create a backup of your Wazuh configuration and data before performing any upgrades.

## Remember

This script provides a basic framework for automating Wazuh component upgrades. You may need to customize it further to fit your specific environment and requirements. Please refer to the official Wazuh documentation for detailed upgrade instructions and best practices.

## Disclaimer

Use this script at your own risk. The author and contributors are not responsible for any data loss, system instability, or other issues that may arise from using this script.
