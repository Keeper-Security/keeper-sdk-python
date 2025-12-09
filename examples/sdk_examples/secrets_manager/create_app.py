import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.vault import sqlite_storage, vault_online, ksm_management
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


def login():
    """Handle server selection, username input, and authentication steps."""
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


def create_secrets_manager_application(keeper_auth_context: keeper_auth.KeeperAuth):
    """Create a new Secrets Manager application."""
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    
    try:
        app_name = input('Enter name for new Secrets Manager application: ').strip()
        
        if not app_name:
            print("Application name cannot be empty")
        else:
            force_add = input('Allow duplicate names? (y/n): ').strip().lower() == 'y'
            
            print(f"\nCreating Secrets Manager application: {app_name}")
            
            app_uid = ksm_management.create_secrets_manager_app(vault, app_name, force_add=force_add)
            
            print(f"\n✓ Secrets Manager application created successfully!")
            print(f"Application Name: {app_name}")
            print(f"Application UID: {app_uid}")
            print("\nNext steps:")
            print("  1. Share records or folders with this application")
            print("  2. Generate client devices for access")
            print("  3. Use the application in your integrations")
            
            vault.sync_down()
        
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error creating application: {e}")
    
    vault.close()
    keeper_auth_context.close()


def main():
    """Main function to orchestrate login and Secrets Manager application creation."""
    keeper_auth_context = login()
    if keeper_auth_context:
        create_secrets_manager_application(keeper_auth_context)


if __name__ == '__main__':
    main()
