# Wazuh Component Updater

This script automates the process of upgrading Wazuh components (Indexer, Manager, and Dashboard) on a system. It intelligently identifies which components are currently running and performs the necessary upgrades accordingly.

## Features

* **Automatic Upgrades:**  Upgrades all running Wazuh components without manual intervention.
* **Intelligent Detection:**  Identifies the running components using `systemctl`.
* **Wazuh Repository Setup:** Automatically sets up the Wazuh repository for package installation.
* **Filebeat Configuration:**  Handles Filebeat configuration when upgrading the Wazuh Manager.
* **Error Handling:**  Includes basic error handling and logging for troubleshooting.

## Prerequisites

* **Python 3:** Make sure you have Python 3 installed on your system.
* **Required Libraries:** Install the necessary Python libraries using:

   ```bash
   pip install requests lxml delegator
   ```

* **Wazuh Credentials:** Set the following environment variables:
  * `WAZUH_USERNAME`: Your Wazuh username.
  * `WAZUH_PASSWORD`: Your Wazuh password.
* **Root Privileges:** The script needs to be run with root privileges (e.g., using `sudo`).

## Usage

1. **Clone the repository:**

   ```bash
   git clone <repository_url>
   ```

2. **Navigate to the script directory:**

   ```bash
   cd <repository_directory>
   ```

3. **Run the script:**

   ```bash
   sudo python wazuh_upgrade.py 
   ```

## Important Notes

* **Backup:** It's strongly recommended to back up your Wazuh configuration and data before running this script.
* **Dependencies:** Be aware of potential dependencies between Wazuh components. The script currently upgrades all running components, but you might need to adjust the order of upgrades in some cases.
* **Testing:** Thoroughly test this script in a non-production environment before using it in production.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

```

**Remember to replace the following placeholders:**

* `<repository_url>`: The actual URL of your GitHub repository.
* `<repository_directory>`: The name of the directory where you cloned the repository.
* `wazuh_upgrade.py`: The actual name of your Python script file.

You can further customize this README to include additional information about your script, such as:

* More detailed instructions on how to set up the Wazuh environment.
* Troubleshooting tips.
* Contact information or links to support resources.

Please let me know if you have any other questions.
