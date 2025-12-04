import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record, record_management
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


def update_record(keeper_auth_context):
    """
    Update a record in the vault.
    
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

    print("Updating record in vault...")
    print("-" * 50)
    
    record_to_update = None
    for record_info in vault.vault_data.records():
        record_to_update = record_info
        break
    
    if record_to_update:
        record = vault.vault_data.load_record(record_to_update.record_uid)
        
        print(f'Updating record: {record_to_update.title}')
        print(f'Record UID: {record_to_update.record_uid}')
        print(f'Record Version: {record_to_update.version}')
        
        if isinstance(record, vault_record.PasswordRecord):
            print('Original values:')
            print(f'  Title: {record.title}')
            print(f'  Username: {record.login}')
            print(f'  URL: {record.link}')
            print(f'  Notes: {record.notes[:50] if record.notes else ""}...')
            
            record.title = f'{record.title} (Updated)'
            record.login = f'updated_{record.login}' if record.login else 'updated@example.com'
            record.password = 'UpdatedPassword123!'
            record.link = 'https://updated-example.com'
            record.notes = f'{record.notes}\n\nUpdated on: SDK Example'
            
            print('\nNew values:')
            print(f'  Title: {record.title}')
            print(f'  Username: {record.login}')
            print(f'  URL: {record.link}')
            
        elif isinstance(record, vault_record.TypedRecord):
            print('Original values:')
            print(f'  Title: {record.title}')
            print(f'  Record Type: {record.record_type}')
            
            record.title = f'{record.title} (Updated)'
            record.notes = f'{record.notes}\n\nUpdated on: SDK Example' if record.notes else 'Updated on: SDK Example'
            
            print('\nNew values:')
            print(f'  Title: {record.title}')
        
        try:
            record_management.update_record(vault, record)
            print("\n" + "-" * 50)
            print('Successfully updated record!')
            print("-" * 50)
            
            vault.sync_down()
            
            updated_record_info = vault.vault_data.get_record(record_to_update.record_uid)
            if updated_record_info:
                print(f'Verified: Record "{updated_record_info.title}" was updated')
            
        except Exception as e:
            print(f'Error updating record: {str(e)}')
    else:
        print('No records found in vault to update')
    
    vault.close()
    keeper_auth_context.close()


def main():
    """
    Main entry point for the update record script.
    Performs login and updates a record.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        update_record(keeper_auth_context)
    else:
        print("Login failed. Unable to update record.")


if __name__ == "__main__":
    main()
