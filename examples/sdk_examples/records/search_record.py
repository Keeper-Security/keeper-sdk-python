import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online
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
    print("Successfully logged in with persistent login")

if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
    keeper_auth_context = login_auth_context.login_step.take_keeper_auth()
    
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()

    print("Searching for records...")
    print("-" * 50)
    
    search_pattern = input('Enter search pattern (e.g., "example", "login", or record UID): ') or "example"
    
    record_type = None
    record_version = None
    
    print(f'\nSearching for records matching: "{search_pattern}"')
    if record_type:
        print(f'Record type filter: {record_type}')
    if record_version:
        print(f'Record version filter: {record_version}')
    print("-" * 50)
    
    try:
        matching_records = list(vault.vault_data.find_records(
            criteria=search_pattern,
            record_type=record_type,
            record_version=record_version
        ))
        
        if matching_records:
            print(f'\nFound {len(matching_records)} matching record(s):')
            print("-" * 50)
            
            for record_info in matching_records:
                print(f'Title: {record_info.title}')
                print(f'Record UID: {record_info.record_uid}')
                print(f'Record Type: {record_info.record_type}')
                print(f'Record Version: {record_info.version}')
                print("-" * 50)
        else:
            print(f'\nNo records found matching: "{search_pattern}"')
            print('\nTip: Try searching for a different term or check available records using list_records.py')
    
    except Exception as e:
        print(f'Error searching for records: {str(e)}')
    
    vault.close()
    keeper_auth_context.close()
