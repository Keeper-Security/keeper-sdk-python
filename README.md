[![PyPI](https://img.shields.io/pypi/v/keepersdk)](https://pypi.org/project/keepersdk/)
[![License](https://img.shields.io/pypi/l/keepersdk)](https://github.com/Keeper-Security/keeper-sdk-python/blob/master/LICENSE)
![Python](https://img.shields.io/pypi/pyversions/keepersdk)
![License](https://img.shields.io/pypi/status/keepersdk)

# Keeper SDK for Python

## Overview

The Keeper SDK for Python provides developers with a comprehensive toolkit for integrating Keeper Security's password management and secrets management capabilities into Python applications. This repository contains two primary packages:

- **Keeper SDK (`keepersdk`)**: A Python library for programmatic access to Keeper Vault, enabling developers to build custom integrations, automate password management workflows, and manage enterprise console operations.
- **Keeper CLI (`keepercli`)**: A modern command-line interface for interacting with Keeper Vault and Enterprise Console, offering efficient commands for vault management, enterprise administration, and automation tasks.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Keeper SDK](#keeper-sdk)
  - [SDK Installation](#sdk-installation)
  - [SDK Environment Setup](#sdk-environment-setup)
  - [SDK Configuration](#sdk-configuration)
  - [SDK Usage Example](#sdk-usage-example)
- [Keeper CLI](#keeper-cli)
  - [CLI Installation](#cli-installation)
  - [CLI Environment Setup](#cli-environment-setup)
  - [CLI Usage](#cli-usage)
- [Development Setup](#development-setup)
- [Contributing](#contributing)
- [License](#license)

---

## Prerequisites

Before installing the Keeper SDK or CLI, ensure your system meets the following requirements:

- **Python Version**: Python 3.10 or higher
- **Operating System**: Windows, macOS, or Linux
- **Package Manager**: pip (Python package installer)
- **Virtual Environment** (recommended): `venv` or `virtualenv`

To verify your Python version:
```bash
python3 --version
```

---

## Keeper SDK

### About Keeper SDK

The Keeper SDK is a Python library that provides programmatic access to Keeper Security's platform. It enables developers to:

- Authenticate users and manage sessions
- Access and manipulate vault records (passwords, files, custom fields)
- Manage folders and shared folders
- Administer enterprise console operations (users, teams, roles, nodes)
- Integrate Keeper's zero-knowledge security architecture into applications
- Automate password rotation and secrets management workflows

### SDK Installation

#### From PyPI (Recommended)

Install the latest stable release from the Python Package Index:

```bash
pip install keepersdk
```

#### From Source

To install from source for development or testing purposes:

```bash
# Clone the repository
git clone https://github.com/Keeper-Security/keeper-sdk-python
cd keeper-sdk-python/keepersdk-package

# Install dependencies
pip install -r requirements.txt

# Install the SDK
pip install .
```

### SDK Environment Setup

For optimal development practices, it's recommended to use a virtual environment:

**Step 1: Create a Virtual Environment**

```bash
# On macOS/Linux
python3 -m venv venv

# On Windows
python -m venv venv
```

**Step 2: Activate the Virtual Environment**

```bash
# On macOS/Linux
source venv/bin/activate

# On Windows
venv\Scripts\activate
```

**Step 3: Install Keeper SDK dependencies**

```bash
pip install -r requirements.txt
pip install setuptools
```

**Step 4: Install keepersdk into the venv**
```bash
python setup.py install
```

Your environment is now ready for SDK development.

### SDK Configuration

The Keeper SDK uses a configuration storage system to manage authentication settings and endpoints. You can use:

- **JsonConfigurationStorage**: Stores configuration in JSON format (default)
- **InMemoryConfigurationStorage**: Temporary in-memory storage for testing
- **Custom implementations**: Implement your own configuration storage

No additional configuration files are required for basic usage. Authentication settings are managed programmatically through the SDK.

### SDK Usage Example

Below is a complete example demonstrating authentication, vault synchronization, and record retrieval:

```python
import sqlite3
import getpass

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record

# Initialize configuration and authentication context
config = configuration.JsonConfigurationStorage()
server = 'keepersecurity.com' # can be set to keepersecurity.com, keepersecurity.com.au, keepersecurity.jp, keepersecurity.eu, keepersecurity.ca, govcloud.keepersecurity.us
keeper_endpoint = endpoint.KeeperEndpoint(config, keeper_server=server)
login_auth_context = login_auth.LoginAuth(keeper_endpoint)

# Authenticate user
login_auth_context.login('username@company.com')

# Complete password verification
# Note: In case 2fa and device approval flows fail, we can use verify password
# login_auth_context.login_step.verify_password('your_secure_password')

while not login_auth_context.login_step.is_final():
    if isinstance(login_auth_context.login_step, login_auth.LoginStepDeviceApproval):
        login_auth_context.login_step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
    elif isinstance(login_auth_context.login_step, login_auth.LoginStepPassword):
        password = getpass.getpass('Enter password: ')
        login_auth_context.login_step.verify_password(password)
    elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
        channel = login_auth_context.login_step.get_channels()[0]
        code = getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
        login_auth_context.login_step.send_code(channel.channel_uid, code)
    else:
        raise NotImplementedError()

# Check if login was successful
if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
    # Obtain authenticated session
    keeper_auth = login_auth_context.login_step.take_keeper_auth()
    
    # Set up vault storage (using SQLite in-memory database)
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth.auth_context.username, 'utf-8')
    )
    
    # Initialize vault and synchronize with Keeper servers
    vault = vault_online.VaultOnline(keeper_auth, vault_storage)
    vault.sync_down()
    
    # Access and display vault records
    print("Vault Records:")
    print("-" * 50)
    for record in vault.vault_data.records():
        print(f'Title: {record.title}')
        
        # Handle legacy (v2) records
        if record.version == 2:
            legacy_record = vault.vault_data.load_record(record.record_uid)
            if isinstance(legacy_record, vault_record.PasswordRecord):
                print(f'Username: {legacy_record.login}')
                print(f'URL: {legacy_record.link}')
        
        # Handle modern (v3+) records
        elif record.version >= 3:
            print(f'Record Type: {record.record_type}')
        
        print("-" * 50)
    vault.close()
    keeper_auth.close()
```

**Important Security Notes:**
- Never hardcode credentials in production code
- Always implement proper two-factor authentication
- Use device approval flows for enhanced security
- Consider using environment variables or secure vaults for credential management

---

## Keeper CLI

### About Keeper CLI

Keeper CLI is a powerful command-line interface that provides direct access to Keeper Vault and Enterprise Console features. It enables users to:

- Manage vault records, folders, and attachments from the terminal
- Perform enterprise administration tasks (user management, team operations, role assignments)
- Execute batch operations and automation scripts
- Generate audit reports and monitor security events
- Configure Secrets Manager applications
- Import and export vault data

Keeper CLI is ideal for system administrators, DevOps engineers, and power users who prefer terminal-based workflows.

### CLI Installation

#### From Source

```bash
# Clone the repository
git clone https://github.com/Keeper-Security/keeper-sdk-python
cd keeper-sdk-python/keepercli-package

# Install dependencies
pip install -r requirements.txt
python setup.py install
```

### CLI Environment Setup

**Complete Setup from Source:**

**Step 1: Create and Activate Virtual Environment**

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

**Step 2: Install Keeper SDK (Required Dependency)**

```bash
cd keepersdk-package
pip install -r requirements.txt
pip install setuptools
python setup.py install
```

**Step 3: Install Keeper CLI**

```bash
cd ../keepercli-package
pip install -r requirements.txt
```

### CLI Usage

Once installed, launch Keeper CLI:

```bash
# Run Keeper CLI
python -m keepercli
```

**Common CLI Commands:**

```bash
# Login to your Keeper account
Not Logged In> login

# List all vault records
My Vault> list

# Search for a specific record
My Vault> search <query>

# Display record details
My Vault> get <record_uid>

# Add a new record
My Vault> add-record

# Sync vault with server
My Vault> sync-down

# Enterprise user management
My Vault> enterprise-user list
My Vault> enterprise-user add
My Vault> enterprise-user edit

# Team management
My Vault> enterprise-team list
My Vault> enterprise-team add

# Generate audit report
My Vault> audit-report

# Exit CLI
My Vault> quit
```

**Interactive Mode:**

Keeper CLI provides an interactive shell with command history, tab completion, and contextual help:

```bash
My Vault> help              # Display all available commands
My Vault> help <command>    # Get help for a specific command
My Vault> my-command --help # Display command-specific options
```

---

## Contributing

We welcome contributions from the community! Please feel free to submit pull requests, report issues, or suggest enhancements through our [GitHub repository](https://github.com/Keeper-Security/keeper-sdk-python).

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Support

For support, documentation, and additional resources:

- **Documentation**: [Keeper Security Developer Portal](https://docs.keeper.io/)
- **Support**: [Keeper Security Support](https://www.keepersecurity.com/support.html)
- **Community**: [Keeper Security GitHub](https://github.com/Keeper-Security)