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
    
    search_pattern = input('Enter search pattern (or press Enter for all folders): ').strip()
    
    all_folders = list(vault.vault_data.folders())
    
    folders_to_display = []
    if search_pattern:
        for folder in all_folders:
            if search_pattern.lower() in folder.name.lower() or search_pattern == folder.folder_uid:
                folders_to_display.append(folder)
    else:
        folders_to_display = all_folders
    
    if folders_to_display:
        print("\nFolders in vault")
        print("=" * 120)
        print(f"{'Folder Name':<40} {'Type':<25} {'Folder UID':<40} {'Records':<15}")
        print("-" * 120)
        
        for folder in folders_to_display:
            folder_name = folder.name or '(Unnamed)'
            folder_type = folder.folder_type
            folder_uid = folder.folder_uid
            record_count = len(folder.records)
            
            print(f"{folder_name[:39]:<40} {folder_type:<25} {folder_uid[:39]:<40} {record_count:<15}")
        
        print("-" * 120)
        print(f"Total folders: {len(folders_to_display)}")
    else:
        if search_pattern:
            print(f"No folders found matching: '{search_pattern}'")
        else:
            print("No folders found in vault")
    
    vault.close()
    keeper_auth_context.close()

