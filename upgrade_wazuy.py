import os
import requests
from lxml import html
import logging
import socket
import subprocess
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Constants
WAZUH_UPGRADE_URL = "https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html"
SYSTEMCTL_DAEMON_RELOAD = "systemctl daemon-reload"
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")


def run_command(command, ignore_errors=False, retries=3):
    """
    Executes a system command and logs the output. Retries in case of failure.

    Args:
        command (str): Command to execute.
        ignore_errors (bool): Whether to ignore errors and continue execution.
        retries (int): Number of retries in case of failure.

    Returns:
        subprocess.CompletedProcess: Command result object.
    """
    logging.info(f"Executing command: {command}")
    attempt = 0
    while attempt < retries:
        try:
            result = subprocess.run(
                command, shell=True, check=True, text=True, capture_output=True
            )
            logging.info(f"Command output: {result.stdout}")
            return result
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed with error: {e.stderr}")
            attempt += 1
            if attempt >= retries and not ignore_errors:
                raise RuntimeError(
                    f"Command failed after {retries} attempts: {e.stderr}"
                )
            elif ignore_errors:
                break


def fetch_upgrade_data(url):
    """
    Fetches the alerts template and Wazuh module for Filebeat URLs from the given Wazuh upgrade guide URL.

    Args:
        url (str): URL of the Wazuh upgrade guide.

    Returns:
        tuple: alerts_template URL and wazuh_module_filebeat URL.
    """
    logging.info(f"Fetching data from {url}")
    try:
        page = requests.get(url)
        page.raise_for_status()
        tree = html.fromstring(page.content)
        alerts_template = tree.xpath(
            '//*[@id="configuring-filebeat"]/ol/li[2]/div/div/pre/text()[4]'
        )[0].strip()
        wazuh_module_filebeat = tree.xpath(
            '//*[@id="configuring-filebeat"]/ol/li[1]/div/div/pre/text()[3]'
        )[0].strip()
        return alerts_template, wazuh_module_filebeat
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching the page content: {e}")
        raise
    except IndexError as e:
        logging.error(f"Error parsing the page content: {e}")
        raise


def install_package(package_name):
    """
    Installs a package using apt-get.

    Args:
        package_name (str): The name of the package to install.
    """
    logging.info(f"Installing package: {package_name}")
    run_command(f"apt-get install -y {package_name}")


def get_wazuh_indexer_address():
    """
    Retrieves the Wazuh Indexer listening address from the system.

    Returns:
        str: Wazuh Indexer listening address.
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return f"https://{local_ip}:9200"
    except socket.error as e:
        logging.error(f"Error retrieving Wazuh Indexer address: {e}")
        raise


def setup_wazuh_repository():
    """
    Sets up the Wazuh repository by installing required packages, importing the GPG key, and adding the repository.
    """
    logging.info("Setting up Wazuh repository")
    install_package("gnupg")
    install_package("apt-transport-https")
    run_command(
        "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg"
    )
    run_command(
        "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee -a /etc/apt/sources.list.d/wazuh.list"
    )
    run_command("apt-get update")


def stop_indexer_services(wazuh_indexer_address):
    """
    Stops Wazuh Indexer services, installs updates, and restarts the services.

    Args:
        wazuh_indexer_address (str): Address of the Wazuh Indexer.
    """
    try:
        run_command(
            f"curl -X DELETE '{wazuh_indexer_address}/_index_template/ss4o_*_template' -u {WAZUH_USERNAME}:{WAZUH_PASSWORD} -k"
        )
        run_command(
            f"curl -X PUT '{wazuh_indexer_address}/_cluster/settings' -u {WAZUH_USERNAME}:{WAZUH_PASSWORD} -k -H 'Content-Type: application/json' -d'{{\"persistent\": {{\"cluster.routing.allocation.enable\": \"primaries\"}}}}'"
        )
        run_command(
            f"curl -X POST '{wazuh_indexer_address}/_flush/synced' -u {WAZUH_USERNAME}:{WAZUH_PASSWORD} -k"
        )
        logging.info("Stopping Wazuh Indexer service")
        run_command("systemctl stop wazuh-indexer")
        logging.info("Installing Wazuh Indexer update")
        install_package("wazuh-indexer")
        logging.info("Restarting Wazuh Indexer service")
        run_command(SYSTEMCTL_DAEMON_RELOAD)
        run_command("systemctl enable wazuh-indexer")
        run_command("systemctl start wazuh-indexer")
        run_command(
            f"curl -X PUT '{wazuh_indexer_address}/_cluster/settings' -u {WAZUH_USERNAME}:{WAZUH_PASSWORD} -k -H 'Content-Type: application/json' -d'{{\"persistent\": {{\"cluster.routing.allocation.enable\": \"all\"}}}}'"
        )
    except RuntimeError as e:
        logging.error(f"Failed to stop indexer services: {e}")
        raise


def stop_filebeat():
    """
    Stops Filebeat and Wazuh Dashboard services.
    """
    logging.info("Stopping Filebeat and Wazuh Dashboard services")
    run_command("systemctl stop filebeat", ignore_errors=True)
    run_command("systemctl stop wazuh-dashboard", ignore_errors=True)


def upgrade_indexer():
    """
    Upgrades the Wazuh Indexer component.
    """
    stop_filebeat()
    wazuh_indexer_address = get_wazuh_indexer_address()
    stop_indexer_services(wazuh_indexer_address)


def upgrade_manager(alerts_template, wazuh_module_filebeat):
    """
    Upgrades the Wazuh Manager component.

    Args:
        alerts_template (str): URL of the alerts template.
        wazuh_module_filebeat (str): URL of the Wazuh module for Filebeat.
    """
    stop_filebeat()
    logging.info("Updating Wazuh Manager")
    install_package("wazuh-manager")
    logging.info("Downloading Wazuh module for Filebeat")
    run_command(
        f"curl -s {wazuh_module_filebeat} | sudo tar -xvz -C /usr/share/filebeat/module"
    )
    logging.info("Downloading alerts template")
    run_command(f"curl -so /etc/filebeat/wazuh-template.json {alerts_template}")
    run_command("chmod go+r /etc/filebeat/wazuh-template.json")
    logging.info("Restarting Filebeat service")
    run_command(SYSTEMCTL_DAEMON_RELOAD)
    run_command("systemctl enable filebeat")
    run_command("systemctl start filebeat")
    logging.info("Upgrading Wazuh template and pipelines for Filebeat")
    run_command("filebeat setup --pipelines")
    run_command("filebeat setup --index-management -E output.logstash.enabled=false")


def upgrade_dashboard():
    """
    Upgrades the Wazuh Dashboard component.
    """
    stop_filebeat()
    logging.info("Installing Wazuh Dashboard update")
    install_package("wazuh-dashboard")
    logging.info("Restarting Wazuh Dashboard service")
    run_command(SYSTEMCTL_DAEMON_RELOAD)
    run_command("systemctl enable wazuh-dashboard")
    run_command("systemctl start wazuh-dashboard")


def get_running_components():
    """
    Identifies which Wazuh components are currently running on the system.

    Returns:
        list: List of running Wazuh components (e.g., ["indexer", "manager", "dashboard"]).
    """
    components = ["indexer", "manager", "dashboard"]
    running_components = []

    for component in components:
        result = run_command(
            f"systemctl is-active wazuh-{component}", ignore_errors=True
        )
        if result.returncode == 0:
            running_components.append(component)

    return running_components


def main():
    """
    Main function to handle command-line arguments and perform the upgrade process.
    """
    # Check if the Wazuh credentials are set
    if not WAZUH_USERNAME or not WAZUH_PASSWORD:
        logging.error(
            "WAZUH_USERNAME and WAZUH_PASSWORD environment variables must be set."
        )
        exit(1)

    alerts_template, wazuh_module_filebeat = fetch_upgrade_data(WAZUH_UPGRADE_URL)

    function_map = {
        "indexer": upgrade_indexer,
        "dashboard": upgrade_dashboard,
        "manager": lambda: upgrade_manager(alerts_template, wazuh_module_filebeat),
    }

    try:
        setup_wazuh_repository()

        # Identify running components and trigger updates
        running_components = get_running_components()
        logging.info(f"Running Wazuh components: {running_components}")

        for component in running_components:
            logging.info(f"Upgrading {component} component...")
            function_map[component]()

    except Exception as e:
        logging.error(f"An error occurred during the upgrade process: {e}")


if __name__ == "__main__":
    main()
