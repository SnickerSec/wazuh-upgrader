import os
import requests
from lxml import html
import logging
import socket
import subprocess
import time
from typing import List, Optional
from dataclasses import dataclass
from functools import wraps
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Constants
WAZUH_UPGRADE_URL = "https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html"
SYSTEMCTL_DAEMON_RELOAD = "systemctl daemon-reload"
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")
BACKUP_DIR = Path("/var/backup/wazuh")
CONFIG_PATHS = {
    "indexer": "/etc/wazuh-indexer",
    "manager": "/etc/wazuh-manager",
    "dashboard": "/etc/wazuh-dashboard",
}


def sanitize_command(command: Optional[str]) -> str:
    """
    Redacts sensitive information (e.g., passwords) from a command string.

    Args:
        command (str): The command string to sanitize.

    Returns:
        str: The sanitized command string with sensitive information redacted.
    """
    if command is None:
        return ""
    sanitized = command
    # List of sensitive values to redact from logs
    secrets = []
    if WAZUH_PASSWORD:
        secrets.append(WAZUH_PASSWORD)
    # Add other secrets here if needed in future
    for secret in secrets:
        if secret:
            sanitized = sanitized.replace(secret, "[REDACTED]")
    return sanitized


# Custom exceptions and data classes
class WazuhUpgradeError(Exception):
    pass


class ConfigurationError(WazuhUpgradeError):
    pass


class UpgradeFailedError(WazuhUpgradeError):
    pass


@dataclass
class ComponentState:
    version: str
    config_files: List[str]
    status: str
    backup_path: Optional[str] = None


# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def retry_with_backoff(retries=3, backoff_in_seconds=1):
    """Retry decorator with exponential backoff"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for i in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if i == retries - 1:
                        raise
                    wait_time = backoff_in_seconds * 2**i
                    logging.warning(
                        f"Attempt {i+1} failed: {str(e)}. Retrying in {wait_time}s..."
                    )
                    time.sleep(wait_time)
            return None

        return wrapper

    return decorator


def validate_environment() -> None:
    """Validate environment and dependencies"""
    required_commands = ["curl", "apt-get", "systemctl", "tar"]
    for cmd in required_commands:
        if not subprocess.run(["which", cmd], capture_output=True).returncode == 0:
            raise ConfigurationError(f"Required command '{cmd}' not found")

    if not all([WAZUH_USERNAME, WAZUH_PASSWORD]):
        raise ConfigurationError("Missing required environment variables")


def backup_component(component: str) -> str:
    """Create backup of component with state information"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / component / timestamp
    backup_path.mkdir(parents=True, exist_ok=True)

    # Backup configuration
    config_path = Path(CONFIG_PATHS[component])
    if config_path.exists():
        run_command(f"cp -r {config_path}/* {backup_path}/")

    # Save component state
    state = ComponentState(
        version=get_current_version(component),
        config_files=[str(p) for p in config_path.rglob("*") if p.is_file()],
        status=get_component_status(component),
        backup_path=str(backup_path),
    )

    with open(backup_path / "state.json", "w") as f:
        json.dump(state.__dict__, f)

    return str(backup_path)


def restore_component(component: str, backup_path: str) -> None:
    """Restore component from backup"""
    backup_path = Path(backup_path)
    if not backup_path.exists():
        raise WazuhUpgradeError(f"Backup path {backup_path} not found")

    with open(backup_path / "state.json") as f:
        state = ComponentState(**json.load(f))

    # Stop component
    run_command(f"systemctl stop wazuh-{component}", ignore_errors=True)

    # Restore configuration
    config_path = Path(CONFIG_PATHS[component])
    run_command(f"rm -rf {config_path}/*")
    run_command(f"cp -r {backup_path}/* {config_path}/")

    # Reinstall previous version if available
    if state.version != "unknown":
        run_command(f"apt-get install -y wazuh-{component}={state.version}")

    # Restart component
    run_command(f"systemctl restart wazuh-{component}")


@retry_with_backoff(retries=3)
def get_component_status(component: str) -> str:
    """Get detailed component status"""
    try:
        result = run_command(f"systemctl status wazuh-{component}", ignore_errors=True)
        return "active" if result and result.returncode == 0 else "inactive"
    except Exception:
        return "unknown"


def check_component_health(component: str) -> bool:
    """Check if a component is healthy after upgrade"""
    status = get_component_status(component)
    return status == "active"


def get_current_version(component: str) -> str:
    """Get current version of a Wazuh component"""
    try:
        result = run_command(
            f"apt-cache policy wazuh-{component} | grep Installed", ignore_errors=True
        )
        if result and result.returncode == 0:
            version = result.stdout.split()[1]
            return version if version != "(none)" else "unknown"
        return "unknown"
    except Exception:
        return "unknown"


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
    # Log the command in a sanitized form only
    sanitized_command = sanitize_command(command)
    # If we still detect a password in the original command, avoid logging details
    if WAZUH_PASSWORD and isinstance(command, str) and WAZUH_PASSWORD in command:
        logging.info("Executing sensitive command: [command details redacted]")
    else:
        logging.info(f"Executing command: {sanitized_command}")

    attempt = 0
    while attempt < retries:
        try:
            result = subprocess.run(
                command, shell=True, check=True, text=True, capture_output=True
            )
            # Sanitize stdout before logging in case it contains sensitive data
            sanitized_stdout = sanitize_command(result.stdout)
            logging.info(f"Command output: {sanitized_stdout}")
            return result
        except subprocess.CalledProcessError as e:
            # Sanitize stderr before logging in case it contains sensitive data
            sanitized_stderr = sanitize_command(e.stderr)
            logging.error(f"Command failed with error: {sanitized_stderr}")
            attempt += 1
            if attempt >= retries and not ignore_errors:
                raise RuntimeError(
                    f"Command failed after {retries} attempts: {sanitized_stderr}"
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


def upgrade_component_safe(component: str, *args) -> None:
    """Safely upgrade a component with rollback capability"""
    backup_path = backup_component(component)
    try:
        if component == "indexer":
            upgrade_indexer()
        elif component == "manager":
            upgrade_manager(*args)
        elif component == "dashboard":
            upgrade_dashboard()

        # Verify upgrade success
        if not check_component_health(component):
            raise UpgradeFailedError(f"{component} health check failed")

    except Exception as e:
        logging.error(f"Upgrade failed for {component}: {str(e)}")
        logging.info(f"Rolling back {component}...")
        restore_component(component, backup_path)
        raise


def main():
    """
    Enhanced main function with proper validation and error handling
    """
    try:
        validate_environment()

        alerts_template, wazuh_module_filebeat = fetch_upgrade_data(WAZUH_UPGRADE_URL)
        setup_wazuh_repository()

        # Enforce upgrade order
        components = ["indexer", "manager", "dashboard"]
        running_components = get_running_components()

        for component in components:
            if component in running_components:
                logging.info(f"Upgrading {component}...")
                upgrade_component_safe(
                    component,
                    alerts_template if component == "manager" else None,
                    wazuh_module_filebeat if component == "manager" else None,
                )

    except WazuhUpgradeError as e:
        logging.error(f"Upgrade failed: {str(e)}")
        exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        exit(1)
    else:
        logging.info("Upgrade completed successfully")


if __name__ == "__main__":
    main()
