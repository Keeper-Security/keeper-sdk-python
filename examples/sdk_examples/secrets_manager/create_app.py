import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, ksm_management

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

