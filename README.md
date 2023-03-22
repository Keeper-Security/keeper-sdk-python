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

### Example

```python
import os
from login import auth, configuration, endpoint
from vault import sqlite_storage, vault_online, vault_record

config_filename = os.path.join(os.path.dirname(__file__), 'config.json')
config = configuration.JsonConfigurationStorage(file_name=config_filename)
keeper_endpoint = endpoint.KeeperEndpoint(config)
login_auth = auth.LoginAuth(keeper_endpoint)
login_auth.login('username@company.com')

while not login_auth.login_step.is_final():
    if isinstance(login_auth.login_step, auth.LoginStepPassword):
        password = input('Enter password: ')
        login_auth.login_step.verify_password(password)
    if isinstance(login_auth.login_step, auth.LoginStepTwoFactor):
        channel = login_auth.login_step.get_channels()[0]
        code = input(f'Enter 2FA code for {channel.channel_name}: ')
        login_auth.login_step.send_code(channel.channel_uid, code)
    else:
        raise NotImplementedError()

if isinstance(login_auth.login_step, auth.LoginStepConnected):
    keeper_auth = login_auth.login_step.keeper_auth()
    vault_storage = sqlite_storage.SqliteVaultStorage(file_name=':memory:',
                                                      vault_owner=keeper_auth.auth_context.username)
    vault = vault_online.VaultOnline(keeper_auth, vault_storage)
    vault.sync_down()

    # List records
    for record in vault.records():
        print(f'Title: {record.title}')
        if record.version == 2:
            legacy_record = vault.load_record(record.record_uid)
            if isinstance(legacy_record, vault_record.PasswordRecord):
                print(f'Username: {legacy_record.login}')
```