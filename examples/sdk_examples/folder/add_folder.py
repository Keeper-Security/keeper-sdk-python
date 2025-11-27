import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, folder_management

config = configuration.JsonConfigurationStorage()
keeper_endpoint = endpoint.KeeperEndpoint(config)
login_auth_context = login_auth.LoginAuth(keeper_endpoint)

username = None
if config.get().users() and config.get().users()[0]:
    username = config.get().users()[0].username
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
        raise NotImplementedError()
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
    
    folder_name = input('Enter name for new folder: ').strip()
    
    if not folder_name:
        print("Folder name cannot be empty")
    else:
        is_shared = input('Create as shared folder? (y/n): ').strip().lower() == 'y'
        
        parent_uid = None
        if not is_shared:
            use_parent = input('Add to a parent folder? (y/n): ').strip().lower() == 'y'
            if use_parent:
                parent_uid = input('Enter parent folder UID: ').strip()
                if parent_uid:
                    parent_folder = vault.vault_data.get_folder(parent_uid)
                    if not parent_folder:
                        print(f"Parent folder '{parent_uid}' not found")
                        parent_uid = None
        
        try:
            if is_shared:
                folder_uid = folder_management.add_folder(
                    vault, 
                    folder_name, 
                    is_shared_folder=True,
                    manage_records=True,
                    manage_users=False,
                    can_share=True,
                    can_edit=True
                )
                print(f"\nShared folder created successfully!")
            else:
                folder_uid = folder_management.add_folder(
                    vault, 
                    folder_name,
                    is_shared_folder=False,
                    parent_uid=parent_uid
                )
                print(f"\nFolder created successfully!")
            
            print(f"Folder UID: {folder_uid}")
            print(f"Folder Name: {folder_name}")
            
            vault.sync_down()
            
        except Exception as e:
            print(f"Error creating folder: {e}")
    
    vault.close()
    keeper_auth_context.close()

