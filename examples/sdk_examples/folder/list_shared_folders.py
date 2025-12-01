import getpass
import logging
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint

logging.getLogger('asyncio').setLevel(logging.CRITICAL)
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
    
    search_pattern = input('Enter search pattern (or press Enter for all shared folders): ').strip()
    
    if search_pattern:
        shared_folders = list(vault.vault_data.find_shared_folders(search_pattern))
    else:
        shared_folders = list(vault.vault_data.shared_folders())
    
    if shared_folders:
        print("\nShared Folders")
        print("=" * 120)
        print(f"{'Folder Name':<40} {'Shared Folder UID':<40} {'Records':<15} {'Users':<15}")
        print("-" * 120)
        
        for sf_info in shared_folders:
            shared_folder = vault.vault_data.load_shared_folder(sf_info.shared_folder_uid)
            
            folder_name = sf_info.name or '(Unnamed)'
            folder_uid = sf_info.shared_folder_uid
            
            record_count = 0
            user_count = 0
            
            if shared_folder:
                record_count = len(shared_folder.record_permissions)
                user_count = len(shared_folder.user_permissions)
            
            print(f"{folder_name[:39]:<40} {folder_uid[:39]:<40} {record_count:<15} {user_count:<15}")
        
        print("-" * 120)
        print(f"Total shared folders: {len(shared_folders)}")
    else:
        if search_pattern:
            print(f"No shared folders found matching: '{search_pattern}'")
        else:
            print("No shared folders found in vault")
    
    vault.close()
    keeper_auth_context.close()

