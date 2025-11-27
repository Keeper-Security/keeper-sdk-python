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
        app_search = input('Enter application name or UID: ').strip()
        
        if not app_search:
            print("Application identifier cannot be empty")
        else:
            app = ksm_management.get_secrets_manager_app(vault, app_search)
            
            print(f"\nSecrets Manager Application Details")
            print("=" * 100)
            print(f"App Name: {app.name}")
            print(f"App UID: {app.uid}")
            print(f"Records Shared: {app.records}")
            print(f"Folders Shared: {app.folders}")
            print(f"Client Devices: {app.count}")
            
            if app.client_devices:
                print(f"\nClient Devices ({len(app.client_devices)}):")
                print("-" * 100)
                print(f"{'Name':<25} {'Short ID':<15} {'Created':<20} {'Last Access':<20} {'IP Address':<20}")
                print("-" * 100)
                
                for client in app.client_devices:
                    name = client.name[:24] if client.name else 'N/A'
                    short_id = client.short_id[:14] if client.short_id else 'N/A'
                    created = client.created_on.strftime('%Y-%m-%d %H:%M') if client.created_on else 'N/A'
                    last_access = client.last_access.strftime('%Y-%m-%d %H:%M') if client.last_access else 'Never'
                    ip_address = client.ip_address[:19] if client.ip_address else 'N/A'
                    
                    print(f"{name:<25} {short_id:<15} {created:<20} {last_access:<20} {ip_address:<20}")
            
            if app.shared_secrets:
                print(f"\nShared Secrets ({len(app.shared_secrets)}):")
                print("-" * 100)
                print(f"{'Type':<15} {'Name':<45} {'UID':<40}")
                print("-" * 100)
                
                for secret in app.shared_secrets[:20]:
                    secret_type = secret.type[:14] if secret.type else 'N/A'
                    secret_name = secret.name[:44] if secret.name else 'N/A'
                    secret_uid = secret.uid[:39] if secret.uid else 'N/A'
                    
                    print(f"{secret_type:<15} {secret_name:<45} {secret_uid:<40}")
                
                if len(app.shared_secrets) > 20:
                    print(f"  ... and {len(app.shared_secrets) - 20} more")
            
            print("=" * 100)
        
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error getting application details: {e}")
    
    vault.close()
    keeper_auth_context.close()

