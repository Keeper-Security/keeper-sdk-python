import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record
from keepersdk.constants import KEEPER_PUBLIC_HOSTS

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