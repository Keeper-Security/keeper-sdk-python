import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
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


def add_record(keeper_auth_context: keeper_auth.KeeperAuth):
    """
    Add a new record to the vault.
    
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

    print("Adding new record to vault...")
    print("-" * 50)
    
    new_record = vault_record.PasswordRecord()
    new_record.title = "Example Record"
    new_record.login = "user@example.com"
    new_record.password = "SecurePassword123!"
    new_record.link = "https://example.com"
    new_record.notes = "This is an example record created using the Keeper SDK"
    
    folder_uid = None
    
    try:
        record_uid = record_management.add_record_to_folder(vault, new_record, folder_uid)
        print(f'Successfully added record!')
        print(f'Record UID: {record_uid}')
        print(f'Title: {new_record.title}')
        print(f'Username: {new_record.login}')
        print(f'URL: {new_record.link}')
        print(f'Notes: {new_record.notes}')
        print("-" * 50)
        
        vault.sync_down()
        
        added_record = vault.vault_data.get_record(record_uid)
        if added_record:
            print(f'Verified: Record "{added_record.title}" exists in vault')
        
    except Exception as e:
        print(f'Error adding record: {str(e)}')
    
    vault.close()
    keeper_auth_context.close()


def main():
    """
    Main entry point for the add record script.
    Performs login and adds a new record.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        add_record(keeper_auth_context)
    else:
        print("Login failed. Unable to add record.")


if __name__ == "__main__":
    main()
