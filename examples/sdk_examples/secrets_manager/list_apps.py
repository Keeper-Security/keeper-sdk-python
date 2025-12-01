import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, ksm_management
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
    
    try:
        apps = ksm_management.list_secrets_manager_apps(vault)
        
        if not apps:
            print("\nNo Secrets Manager applications found")
        else:
            print(f"\nSecrets Manager Applications ({len(apps)})")
            print("=" * 120)
            print(f"{'App Name':<30} {'App UID':<40} {'Records':<10} {'Folders':<10} {'Clients':<10} {'Last Access':<20}")
            print("-" * 120)
            
            for app in apps:
                app_name = app.name[:29] if app.name else '(Unnamed)'
                app_uid = app.uid[:39]
                records = app.records
                folders = app.folders
                clients = app.count
                last_access = app.last_access.strftime('%Y-%m-%d %H:%M') if app.last_access else 'Never'
                
                print(f"{app_name:<30} {app_uid:<40} {records:<10} {folders:<10} {clients:<10} {last_access:<20}")
            
            print("-" * 120)
            print(f"Total applications: {len(apps)}")
        
        print("=" * 120)
        
    except Exception as e:
        print(f"Error listing Secrets Manager applications: {e}")
    
    vault.close()
    keeper_auth_context.close()

