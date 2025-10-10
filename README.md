[![PyPI](https://img.shields.io/pypi/v/keepersdk)](https://pypi.org/project/keepersdk/)
[![License](https://img.shields.io/pypi/l/keepersdk)](https://github.com/Keeper-Security/keeper-sdk-python/blob/master/LICENSE)
![Python](https://img.shields.io/pypi/pyversions/keepersdk)
![License](https://img.shields.io/pypi/status/keepersdk)
# Keeper-Security/keeper-sdk-python
### Keeper SDK for Python

### Installation
```bash
pip install keepersdk
```

### Clone source code 
```bash
$ git clone https://github.com/Keeper-Security/keeper-sdk-python
```

### Steps to setup environment for using python keepersdk
```
Requirement - python 3.10 or higher
1. Open a terminal/zsh/powershell
2. Create a virtual environment (venv) using "python3 -m venv venv" (Optionally python or py depending on python setup)
3. Activate the venv using "source venv/bin/activate" for MacOS/Linux or "venv\Scripts\Activate' for Windows
4. Move to keepersdk-package using "cd keepersdk-package"
5. Run "pip install -r requirements.txt" for installing dependencies
6. Run "pip install setuptools" tp install setuptools which will be used to create keepersdk package
7. Run "python setup.py install" to install keepersdk from the keepersdk-package as a lib
8. Create a client file for the keepersdk to use it  complete the login flow and access Keeper Vault and Console elements. An example is added below.
```


### Steps to setup enviroment for using python keepercli-package
```
Continuing from step 7 of previous section to setup keepersdk-package
8. Move to keepercli-package using "cd ../keepercli-package" or "cd ..\keepercli-package"
9. Run "pip install -r requirements.txt" for installing dependencies
10. Run "python setup.py install" to install keepercli from the keepercli-package as a lib
11. Run command "python -m keepercli" to run the keepercli which is the new version of Commander CLI with more efficient commands
```

### Example

```python
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record

config = configuration.JsonConfigurationStorage()
keeper_endpoint = endpoint.KeeperEndpoint(config)
login_auth_context = login_auth.LoginAuth(keeper_endpoint)
login_auth_context.login('username@company.com')
# bypassing device approval and 2fa step, not recommended
login_auth_context.login_step.verify_password('yourpassword')

if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
    keeper_auth = login_auth_context.login_step.take_keeper_auth()
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(lambda: conn, vault_owner=bytes(keeper_auth.auth_context.username, 'utf-8'))
    vault = vault_online.VaultOnline(keeper_auth, vault_storage)
    vault.sync_down()

    # List records
    for record in vault.vault_data.records():
        print(f'Title: {record.title}')
        if record.version == 2:
            legacy_record = vault.vault_data.load_record(record.record_uid)
            if isinstance(legacy_record, vault_record.PasswordRecord):
                print(f'Username: {legacy_record.login}')
```