import getpass
import sqlite3
from datetime import datetime

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
        trash_management.TrashManagement._ensure_deleted_records_loaded(vault)
        
        deleted_records = trash_management.TrashManagement.get_deleted_records()
        orphaned_records = trash_management.TrashManagement.get_orphaned_records()
        deleted_shared_folders = trash_management.TrashManagement.get_shared_folders()
        
        total_items = len(deleted_records) + len(orphaned_records) + len(deleted_shared_folders)
        
        if total_items == 0:
            print("\nTrash is empty")
            print("No deleted records or folders found.")
        else:
            print(f"\nDeleted Items in Trash ({total_items} total)")
            print("=" * 120)
            
            if deleted_records:
                print(f"\nDeleted Records ({len(deleted_records)})")
                print("-" * 120)
                print(f"{'Title':<40} {'Record UID':<40} {'Deleted On':<30}")
                print("-" * 120)
                
                for record_uid, record in list(deleted_records.items())[:20]:
                    title = record.get('title', '(Untitled)')[:39]
                    uid = record_uid[:39]
                    
                    deleted_time = record.get('client_modified_time', 0)
                    deleted_str = datetime.fromtimestamp(deleted_time / 1000).strftime('%Y-%m-%d %H:%M:%S') if deleted_time else 'N/A'
                    
                    print(f"{title:<40} {uid:<40} {deleted_str:<30}")
                
                if len(deleted_records) > 20:
                    print(f"  ... and {len(deleted_records) - 20} more")
            
            if orphaned_records:
                print(f"\nOrphaned Records ({len(orphaned_records)})")
                print("-" * 120)
                print(f"{'Title':<40} {'Record UID':<40} {'Status':<30}")
                print("-" * 120)
                
                for record_uid, record in list(orphaned_records.items())[:10]:
                    title = record.get('title', '(Untitled)')[:39]
                    uid = record_uid[:39]
                    status = 'No Access'
                    
                    print(f"{title:<40} {uid:<40} {status:<30}")
                
                if len(orphaned_records) > 10:
                    print(f"  ... and {len(orphaned_records) - 10} more")
            
            if deleted_shared_folders:
                print(f"\nDeleted Shared Folders ({len(deleted_shared_folders)})")
                print("-" * 120)
                print(f"{'Folder Name':<40} {'Folder UID':<40} {'Records':<20}")
                print("-" * 120)
                
                for folder_uid, folder in list(deleted_shared_folders.items())[:10]:
                    folder_name = folder.get('name', '(Unnamed)')[:39]
                    uid = folder_uid[:39]
                    records_count = len(folder.get('records', []))
                    
                    print(f"{folder_name:<40} {uid:<40} {records_count:<20}")
                
                if len(deleted_shared_folders) > 10:
                    print(f"  ... and {len(deleted_shared_folders) - 10} more")
            
            print("=" * 120)
            print(f"\nSummary:")
            print(f"  Deleted Records: {len(deleted_records)}")
            print(f"  Orphaned Records: {len(orphaned_records)}")
            print(f"  Deleted Shared Folders: {len(deleted_shared_folders)}")
            print(f"\nUse restore operations to recover items from trash.")
        
    except Exception as e:
        print(f"Error listing trash: {e}")
    
    vault.close()
    keeper_auth_context.close()

