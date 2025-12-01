import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, record_management
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
    
    folder_search = input('Enter folder name or UID to move: ').strip()
    
    if not folder_search:
        print("Folder identifier cannot be empty")
    else:
        folder_found = None
        
        for folder in vault.vault_data.folders():
            if folder.name.lower() == folder_search.lower() or folder.folder_uid == folder_search:
                folder_found = folder
                break
        
        if not folder_found:
            print(f"Folder '{folder_search}' not found")
        else:
            print(f"\nFolder to move:")
            print(f"Name: {folder_found.name}")
            print(f"Type: {folder_found.folder_type}")
            print(f"UID: {folder_found.folder_uid}")
            
            destination_search = input('\nEnter destination folder UID (or leave empty for root): ').strip()
            
            destination_folder = None
            if destination_search:
                destination_folder = vault.vault_data.get_folder(destination_search)
                if not destination_folder:
                    print(f"Destination folder '{destination_search}' not found")
                else:
                    print(f"Destination: {destination_folder.name}")
            else:
                destination_folder = vault.vault_data.root_folder
                print("Destination: Root folder")
            
            if destination_folder:
                confirm = input('\nProceed with move? (yes/no): ').strip().lower()
                
                if confirm == 'yes':
                    try:
                        def on_warning(message: str) -> None:
                            print(f"Warning: {message}")
                        
                        record_management.move_vault_objects(
                            vault,
                            [folder_found.folder_uid],
                            dst_folder_uid=destination_folder.folder_uid if destination_folder.folder_uid else '',
                            on_warning=on_warning
                        )
                        
                        print(f"\nFolder moved successfully!")
                        
                        vault.sync_down()
                        
                    except Exception as e:
                        print(f"Error moving folder: {e}")
                else:
                    print("Move cancelled")
    
    vault.close()
    keeper_auth_context.close()

