import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.vault import sqlite_storage, vault_online, record_management
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


def login():
    """
    Handle the login process including server selection, authentication,
    and multi-factor authentication steps.
    
    Returns:
        keeper_auth_context: The authenticated Keeper context, or None if login fails.
    """
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
        return login_auth_context.login_step.take_keeper_auth()
    
    return None


def delete_folder(keeper_auth_context: keeper_auth.KeeperAuth):
    """
    Delete a folder from the vault.
    
    Args:
        keeper_auth_context: The authenticated Keeper context.
    """
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    
    folder_search = input('Enter folder name or UID to delete: ').strip()
    
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
            print(f"\nFolder to delete:")
            print(f"Name: {folder_found.name}")
            print(f"Type: {folder_found.folder_type}")
            print(f"UID: {folder_found.folder_uid}")
            print(f"Records: {len(folder_found.records)}")
            print(f"Subfolders: {len(folder_found.subfolders)}")
            
            confirm = input('\nAre you sure you want to delete this folder? (yes/no): ').strip().lower()
            
            if confirm == 'yes':
                try:
                    def confirm_deletion(message: str) -> bool:
                        print(f"\n{message}")
                        answer = input("\nContinue with deletion? (yes/no): ").strip().lower()
                        return answer == 'yes'
                    
                    record_management.delete_vault_objects(
                        vault,
                        [folder_found.folder_uid],
                        confirm=confirm_deletion
                    )
                    
                    print(f"\nFolder deleted successfully!")
                    
                    vault.sync_down()
                    
                except Exception as e:
                    print(f"Error deleting folder: {e}")
            else:
                print("Deletion cancelled")
    
    vault.close()
    keeper_auth_context.close()


def main():
    """
    Main entry point for the delete folder script.
    Performs login and deletes a folder.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        delete_folder(keeper_auth_context)
    else:
        print("Login failed. Unable to delete folder.")


if __name__ == "__main__":
    main()
