# Wazuh Upgrade Automation Script

This script automates the upgrade of various Wazuh components (Indexer, Manager, and Dashboard) with enhanced safety features including backup/restore capabilities and health checks.

## Prerequisites

### Dependencies

```bash
pip install -r requirements.txt
```

Required Python packages:

- requests
- lxml
- python-dotenv
- typing-extensions

### System Requirements

- Debian/Ubuntu-based system with `apt` package manager
- Root/sudo access
- Required system tools:
  - curl
  - apt-get
  - systemctl
  - tar

### Environment Configuration

Create a `.env` file with:

```plaintext
WAZUH_USERNAME=<your_wazuh_username>
WAZUH_PASSWORD=<your_wazuh_password>
```

## Features

### Core Features

- Automatic component detection and ordered upgrades
- Backup and restore capabilities
- Health checks pre/post upgrade
- Automatic rollback on failure
- Exponential backoff retry mechanism
- Comprehensive logging

### Safety Mechanisms

- Component state tracking
- Configuration backups
- Version tracking
- Automatic rollback on failure
- Health verification after upgrades

## Usage

Basic execution:

```bash
sudo python upgrade_wazuh.py
```

The script will:

1. Validate environment and dependencies
2. Create backups of existing configurations
3. Perform upgrades in the correct order (Indexer → Manager → Dashboard)
4. Verify health after each upgrade
5. Automatically rollback if issues are detected

## Backup and Restore

Backups are stored in `/var/backup/wazuh/<component>/<timestamp>/` and include:

- Configuration files
- Component state information
- Version information

Automatic rollback occurs if:

- Component health check fails
- Upgrade process encounters errors
- Service fails to start

## Troubleshooting

### Common Issues

1. Missing Dependencies

```bash
sudo apt-get update
sudo apt-get install curl gnupg apt-transport-https
```

2. Permission Issues

```bash
sudo chmod -R 755 /var/backup/wazuh
```

3. Health Check Failures

- Check component logs: `/var/log/wazuh-*`
- Verify service status: `systemctl status wazuh-*`

## Error Handling

The script includes:

- Exponential backoff retry mechanism
- Detailed error logging
- Automatic rollback capabilities
- Health verification

## Logging

Logs include:

- Command execution details
- Backup operations
- Health check results
- Error messages with stack traces
- Rollback operations

## Advanced Usage

### Manual Rollback

Backups can be found in `/var/backup/wazuh/` organized by component and timestamp.

### Checking Component Status

```bash
python upgrade_wazuh.py --status
```

## Contributing

Please submit issues and pull requests on GitHub.

## License

MIT License

## Author

Created by Chuck
