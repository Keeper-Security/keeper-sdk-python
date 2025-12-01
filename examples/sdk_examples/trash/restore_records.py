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
        record_search = input('Enter record UID or pattern to restore (or "all" for all): ').strip()
        
        if not record_search:
            print("Record identifier cannot be empty")
        else:
            trash_management.TrashManagement._ensure_deleted_records_loaded(vault)
            
            deleted_records = trash_management.TrashManagement.get_deleted_records()
            orphaned_records = trash_management.TrashManagement.get_orphaned_records()
            
            if len(deleted_records) == 0 and len(orphaned_records) == 0:
                print("\nTrash is empty - no records to restore")
            else:
                records_to_restore = []
                
                if record_search.lower() == 'all':
                    records_to_restore = list(deleted_records.keys()) + list(orphaned_records.keys())
                else:
                    if record_search in deleted_records or record_search in orphaned_records:
                        records_to_restore.append(record_search)
                    else:
                        pattern = record_search.lower()
                        for uid, record in deleted_records.items():
                            title = record.get('title', '').lower()
                            if pattern in title or pattern in uid:
                                records_to_restore.append(uid)
                        
                        for uid, record in orphaned_records.items():
                            title = record.get('title', '').lower()
                            if pattern in title or pattern in uid:
                                records_to_restore.append(uid)
                
                if not records_to_restore:
                    print(f"No records found matching: '{record_search}'")
                else:
                    print(f"\nFound {len(records_to_restore)} record(s) to restore")
                    
                    if len(records_to_restore) <= 5:
                        for uid in records_to_restore:
                            record = deleted_records.get(uid) or orphaned_records.get(uid)
                            title = record.get('title', '(Untitled)') if record else 'Unknown'
                            print(f"  - {title} ({uid})")
                    
                    confirm = input(f"\nRestore {len(records_to_restore)} record(s)? (yes/no): ").strip().lower()
                    
                    if confirm == 'yes':
                        print("\nRestoring records...")
                        trash_management.restore_trash_records(vault, records_to_restore)
                        
                        print(f"\n✓ Successfully restored {len(records_to_restore)} record(s)")
                        print("Records have been moved back to your vault.")
                        
                        vault.sync_down()
                    else:
                        print("Restore cancelled")
        
    except Exception as e:
        print(f"Error restoring records: {e}")
    
    vault.close()
    keeper_auth_context.close()

