[![PyPI](https://img.shields.io/pypi/v/keepersdk)](https://pypi.org/project/keepersdk/)
[![License](https://img.shields.io/pypi/l/keepersdk)](https://github.com/Keeper-Security/keeper-sdk-python/blob/master/LICENSE)
![Python](https://img.shields.io/pypi/pyversions/keepersdk)
![License](https://img.shields.io/pypi/status/keepersdk)

# Keeper SDK for Python

## Overview

The Keeper SDK for Python provides developers with a comprehensive toolkit for integrating Keeper Security's password management and secrets management capabilities into Python applications. This repository contains two primary packages:

- **Keeper SDK (`keepersdk`)**: A Python library for programmatic access to Keeper Vault, enabling developers to build custom integrations, automate password management workflows, and manage enterprise console operations.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Keeper SDK](#keeper-sdk)
  - [SDK Installation](#sdk-installation)
  - [SDK Environment Setup](#sdk-environment-setup)
  - [SDK Configuration](#sdk-configuration)
  - [SDK Usage Example](#sdk-usage-example)
- [Contributing](#contributing)
- [License](#license)

---

## Prerequisites

Before installing the Keeper SDK, ensure your system meets the following requirements:

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

# Install the SDK
pip install -e .
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
pip install -e keepersdk-package
```

**Step 4: Install keepersdk into the venv**
```bash
pip install -e keepercli-package
```

Your environment is now ready for SDK development.

### SDK Configuration

The Keeper SDK uses a configuration storage system to manage authentication settings and endpoints. You can use:

- **JsonConfigurationStorage**: Stores configuration in JSON format (default)
- **InMemoryConfigurationStorage**: Temporary in-memory storage for testing
- **Custom implementations**: Implement your own configuration storage

#### **Requirement for client**

If you are accessing keepersdk from a new device, you need to ensure that there is a config.json file present from which the sdk reads credentials. This ensures that the client doesn't contain any hardcoded credentials. Create the .json file in .keeper folder of current user, you might need to create a .keeper folder.

Alternatively you can run the sample login script to give username and password during execution as an alternate to keeping it stored. This will turn on persistent login and would not require re-login for the timeout duration.

A sample showing the structure of the config.json needed is shown below:

```
{
  "users": [
    {
      "user": "username@yourcompany.com",
      "password":"yourpassword",
      "server": "keepersecurity.com",
      "last_device": {
        "device_token": ""
      }
    }
  ],
  "servers": [
    {
      "server": "keepersecurity.com",
      "server_key_id": 10
    }
  ],
  "devices": [
    {
      "device_token": "",
      "private_key": "",
      "server_info": [
        {
          "server": "keepersecurity.com",
          "clone_code": ""
        }
      ]
    }
  ],
  "last_login": "username@yourcompany.com",
  "last_server": "keepersecurity.com"
}
```
### SDK Persistent Login Flow
The persistent login flow allows you to authenticate once and remain logged in for a specified timeout period without requiring session refresh. This is particularly useful for automated scripts and long-running applications.

**Key Features:**
- **One-time setup**: Configure persistent login on a new device with a single execution
- **Automatic session management**: No need to re-authenticate during the timeout period
- **Configurable timeout**: Default is 30 days, but can be customized
- **Device registration**: Registers the device's data key for secure authentication

**When to Use:**
- Automated scripts and background services
- Long-running applications that need continuous access
- Development and testing environments
- Applications where user interaction is not always possible

**Important Notes:**
- Persistent login must be enabled on first-time device setup
- The device data key registration is a one-time operation per device
- Enterprise policies may restrict persistent login usage
- Always follow your organization's security policies when using persistent login

**Example: Setting Up Persistent Login**

This example demonstrates how to enable persistent login on a new device. Run this script once to configure persistent login for subsequent sessions:

```python
import logging
import getpass

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.constants import KEEPER_PUBLIC_HOSTS

# Initialize configuration and authentication context
config = configuration.JsonConfigurationStorage()
if not config.get().last_server:
    print("Available server options:")
    for region, host in KEEPER_PUBLIC_HOSTS.items():
        print(f"  {region}: {host}")
    server = input('Enter server (default: keepersecurity.com): ').strip() or 'keepersecurity.com'

    config.get().last_server = server
else:
    server = config.get().last_server
keeper_endpoint = endpoint.KeeperEndpoint(config, server)
login_auth_context = login_auth.LoginAuth(keeper_endpoint)

# Authenticate user
username = None
if config.get().last_login:
    username = config.get().last_login
if not username:
    username = input('Enter username: ')
login_auth_context.resume_session = True
login_auth_context.login(username)

while not login_auth_context.login_step.is_final():
    if isinstance(login_auth_context.login_step, login_auth.LoginStepDeviceApproval):
        login_auth_context.login_step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
        print("Device approval request sent. Login to existing vault/console or ask admin to approve this device and then press return/enter to resume")
        input()
    elif isinstance(login_auth_context.login_step, login_auth.LoginStepPassword):
        password = getpass.getpass('Enter password: ')
        login_auth_context.login_step.verify_password(password)
    elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
        channel = login_auth_context.login_step.get_channels()[0]
        code = getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
        login_auth_context.login_step.send_code(channel.channel_uid, code)
    else:
        raise NotImplementedError(f"Unsupported login step type: {type(login_auth_context.login_step).__name__}")

# Check if login was successful
if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
    # Obtain authenticated session
    keeper_auth_context = login_auth_context.login_step.take_keeper_auth()

    # Enable persistent login and register data key for device for the first time
    keeper_auth.set_user_setting(keeper_auth_context, 'persistent_login', '1')
    keeper_auth.register_data_key_for_device(keeper_auth_context)
    mins_per_day = 60*24
    timeout_in_minutes = mins_per_day*30 # 30 days
    keeper_auth.set_user_setting(keeper_auth_context, 'logout_timer', str(timeout_in_minutes))
    
    print("Persistent login turned on successfully and device registered")

    keeper_auth_context.close()
```

### SDK Usage Example

Below is a complete example demonstrating authentication, vault synchronization, and record retrieval:

```python
import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record

# Initialize configuration and authentication context
config = configuration.JsonConfigurationStorage()
if not config.get().last_server:
    print("Available server options:")
    for region, host in KEEPER_PUBLIC_HOSTS.items():
        print(f"  {region}: {host}")
    server = input('Enter server (default: keepersecurity.com): ').strip() or 'keepersecurity.com'

    config.get().last_server = server
else:
    server = config.get().last_server
keeper_endpoint = endpoint.KeeperEndpoint(config, server)
login_auth_context = login_auth.LoginAuth(keeper_endpoint)

# Authenticate user
username = None
if config.get().last_login:
    username = config.get().last_login
if not username:
    username = input('Enter username: ')
login_auth_context.resume_session = True
login_auth_context.login(username)

logged_in_with_persistent = True
while not login_auth_context.login_step.is_final():
    if isinstance(login_auth_context.login_step, login_auth.LoginStepDeviceApproval):
        login_auth_context.login_step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
        print("Device approval request sent. Login to existing vault/console or ask admin to approve this device and then press return/enter to resume")
        input()
    elif isinstance(login_auth_context.login_step, login_auth.LoginStepPassword):
        password = getpass.getpass('Enter password: ')
        login_auth_context.login_step.verify_password(password)
    elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
        channel = login_auth_context.login_step.get_channels()[0]
        code = getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
        login_auth_context.login_step.send_code(channel.channel_uid, code)
    else:
        raise NotImplementedError(f"Unsupported login step type: {type(login_auth_context.login_step).__name__}")
    logged_in_with_persistent = False

if logged_in_with_persistent:
    print("Succesfully logged in with persistent login")

# Check if login was successful
if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
    # Obtain authenticated session
    keeper_auth_context = login_auth_context.login_step.take_keeper_auth()
    
    # Set up vault storage (using SQLite in-memory database)
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    
    # Initialize vault and synchronize with Keeper servers
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
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
    keeper_auth_context.close()
```

**Important Security Notes:**
- Never hardcode credentials in production code
- Always implement proper two-factor authentication
- Use device approval flows for enhanced security
- Consider using environment variables or secure vaults for credential management

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