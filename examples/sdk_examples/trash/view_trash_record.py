import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, trash_management
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
        record_uid = input('Enter record UID to view: ').strip()
        
        if not record_uid:
            print("Record UID cannot be empty")
        else:
            record, is_shared = trash_management.get_trash_record(vault, record_uid)
            
            if not record:
                print(f"Record '{record_uid}' not found in trash")
            else:
                print("\nDeleted Record Details")
                print("=" * 100)
                
                title = record.get('title', '(Untitled)')
                print(f"Title: {title}")
                print(f"Record UID: {record_uid}")
                print(f"Type: {'Orphaned/Shared' if is_shared else 'Deleted'}")
                
                if 'version' in record:
                    print(f"Version: {record['version']}")
                
                if 'revision' in record:
                    print(f"Revision: {record['revision']}")
                
                if 'client_modified_time' in record:
                    from datetime import datetime
                    modified_time = record['client_modified_time']
                    modified_str = datetime.fromtimestamp(modified_time / 1000).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"Last Modified: {modified_str}")
                
                if 'record_type' in record:
                    print(f"Record Type: {record['record_type']}")
                
                if is_shared:
                    print("\n⚠️  This is an orphaned record (no access)")
                    print("   Restoration may require special permissions")
                else:
                    print("\n✓ This record can be restored")
                
                print("=" * 100)
        
    except Exception as e:
        print(f"Error viewing trash record: {e}")
    
    vault.close()
    keeper_auth_context.close()

