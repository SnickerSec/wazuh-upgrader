# Wazuh Upgrade Automation Script

This script automates the upgrade of various Wazuh components, including the Wazuh Indexer, Manager, and Dashboard. It handles the setup of necessary repositories, stops services during upgrades, installs updates, and restarts services as needed.

## Prerequisites

### Dependencies

- The script requires the following Python libraries:
  - `requests`
  - `lxml`
  - `dotenv`
  
You can install these dependencies using:

```bash
pip install -r requirements.txt
```

### System Requirements

- The script should be run on a system with `apt` as the package manager (e.g., Debian or Ubuntu).
- Ensure `gnupg` and `apt-transport-https` are installed for repository management.
  
### Environment Variables

The script requires Wazuh credentials to manage Wazuh Indexer configurations. Create a `.env` file in the root directory and include the following variables:

```plaintext
WAZUH_USERNAME=<your_wazuh_username>
WAZUH_PASSWORD=<your_wazuh_password>
```

## Usage

### Running the Script

To run the script, execute:

```bash
python upgrade_wazuh.py
```

This will:

1. Set up the Wazuh repository.
2. Identify running Wazuh components.
3. Upgrade each component in sequence.

### Command-Line Arguments

The script currently does not require additional arguments. However, components are automatically detected and upgraded if they are running.

## Features

- **Automatic Dependency Installation**: Checks for and installs missing packages (like `gnupg` and `apt-transport-https`).
- **Automatic Service Detection**: Identifies active Wazuh components and only upgrades those that are running.
- **Service Stop/Restart**: Safely stops services before upgrades and restarts them after completion.
- **Retry Mechanism**: Commands are retried up to 3 times in case of transient failures.

## Functions

- `fetch_upgrade_data(url)`: Fetches URLs for alerts templates and Wazuh module for Filebeat from the Wazuh upgrade guide.
- `run_command(command, ignore_errors=False, retries=3)`: Runs shell commands with optional retry capability.
- `setup_wazuh_repository()`: Sets up the Wazuh repository and updates the package list.
- `upgrade_indexer()`: Upgrades the Wazuh Indexer component.
- `upgrade_manager(alerts_template, wazuh_module_filebeat)`: Upgrades the Wazuh Manager, including downloading and setting up the Filebeat configuration.
- `upgrade_dashboard()`: Upgrades the Wazuh Dashboard.

## Error Handling

The script logs errors and retries certain operations to improve robustness. If a component fails to upgrade, a detailed error message is logged, and the script continues upgrading other components.

## Logging

The script logs all operations to the console. Logs include information about:

- The status of each command.
- Any errors encountered.
- Wazuh components that are running and being upgraded.

## Troubleshooting

- **"WAZUH_USERNAME and WAZUH_PASSWORD environment variables must be set"**: Ensure the `.env` file is present in the script directory with valid credentials.
- **Command Failure**: If a command fails after the maximum number of retries, check system permissions and network configurations, especially if upgrading Wazuh components requires network access.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Author

This script was developed by Chuck.
