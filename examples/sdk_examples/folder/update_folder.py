import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, folder_management
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
    
    folder_search = input('Enter folder name or UID to update: ').strip()
    
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
            print(f"\nCurrent folder name: {folder_found.name}")
            print(f"Folder type: {folder_found.folder_type}")
            print(f"Folder UID: {folder_found.folder_uid}")
            
            new_name = input('\nEnter new folder name: ').strip()
            
            if not new_name:
                print("New folder name cannot be empty")
            else:
                try:
                    folder_management.update_folder(
                        vault,
                        folder_found.folder_uid,
                        folder_name=new_name
                    )
                    
                    print(f"\nFolder updated successfully!")
                    print(f"Old name: {folder_found.name}")
                    print(f"New name: {new_name}")
                    
                    vault.sync_down()
                    
                except Exception as e:
                    print(f"Error updating folder: {e}")
    
    vault.close()
    keeper_auth_context.close()

