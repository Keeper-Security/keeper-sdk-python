# Keeper SDK for Python

###Installation
```bash
pip install keepersdk
```

###Clone source code 
```bash
$ git clone https://github.com/Keeper-Security/keeper-sdk-python
```

###Example
```python
from keepersdk import Auth, Vault, AuthUI

class BasicAuthUI(AuthUI):
    def get_twofactor_code(self, provider):
        return input('Enter 2FA code: ')

username = "<username>"
password = "<password>"
auth = Auth(auth_ui=BasicAuthUI())
auth.login(username, password)

vault = Vault(auth)
# List records
for record in vault.get_all_records():
    print(record.title) 
```