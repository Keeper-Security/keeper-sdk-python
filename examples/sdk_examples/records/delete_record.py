import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_types, record_management
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


def delete_record(keeper_auth_context):
    """
    Delete a record from the vault.
    
    Args:
        keeper_auth_context: The authenticated Keeper context.
    """
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()

    print("Deleting record from vault...")
    print("-" * 50)
    
    search_title = "Example Record"
    
    record_to_delete = None
    for record_info in vault.vault_data.records():
        if record_info.title.lower() == search_title.lower():
            record_to_delete = record_info
            break
    
    if record_to_delete:
        print(f'Found record to delete: {record_to_delete.title}')
        print(f'Record UID: {record_to_delete.record_uid}')
        
        response = input(f'Are you sure you want to delete "{record_to_delete.title}"? (yes/no): ')
        
        if response.lower() in ['yes', 'y']:
            try:
                record_path = vault_types.RecordPath(record_uid=record_to_delete.record_uid, folder_uid='')
                
                def confirm_deletion(summary: str) -> bool:
                    print("\nDeletion Summary:")
                    print(summary)
                    return True
                
                record_management.delete_vault_objects(vault, [record_path], confirm=confirm_deletion)
                
                print("-" * 50)
                print(f'Successfully deleted record: {record_to_delete.title}')
                print("-" * 50)
                
                vault.sync_down()
                
                deleted_record = vault.vault_data.get_record(record_to_delete.record_uid)
                if not deleted_record:
                    print('Verified: Record was deleted from vault')
                
            except Exception as e:
                print(f'Error deleting record: {str(e)}')
        else:
            print('Deletion cancelled')
    else:
        print(f'No record found with title: "{search_title}"')
        print('Available records:')
        for i, record_info in enumerate(vault.vault_data.records(), 1):
            if i > 10:
                print(f'... and more')
                break
            print(f'  - {record_info.title} ({record_info.record_uid})')
    
    vault.close()
    keeper_auth_context.close()


def main():
    """
    Main entry point for the delete record script.
    Performs login and deletes a record.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        delete_record(keeper_auth_context)
    else:
        print("Login failed. Unable to delete record.")


if __name__ == "__main__":
    main()
