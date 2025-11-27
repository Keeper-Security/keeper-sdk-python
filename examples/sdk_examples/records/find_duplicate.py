import getpass
import sqlite3
from typing import Dict, List

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record

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
    vault.sync_down()

    print("Finding Duplicate Records")
    print("-" * 50)
    
    print("\nDuplicate detection options:")
    print("1. By title")
    print("2. By title and username")
    print("3. By title and URL")
    print("4. By all fields (title, username, URL)")
    
    choice = input("\nSelect option (1-4, default=1): ").strip() or "1"
    
    match_title = True
    match_login = choice in ["2", "4"]
    match_url = choice in ["3", "4"]
    
    print(f"\nSearching for duplicates...")
    print(f"Matching by: Title={match_title}, Username={match_login}, URL={match_url}")
    print("-" * 50)
    
    duplicates_map: Dict[str, List[vault_record.RecordInfo]] = {}
    
    for record_info in vault.vault_data.records():
        try:
            record = vault.vault_data.load_record(record_info.record_uid)
            
            key_parts = []
            
            if match_title:
                title = record.title.lower().strip() if record.title else ""
                key_parts.append(f"title:{title}")
            
            if match_login and isinstance(record, vault_record.PasswordRecord):
                login = record.login.lower().strip() if record.login else ""
                key_parts.append(f"login:{login}")
            
            if match_url:
                url = ""
                if isinstance(record, vault_record.PasswordRecord):
                    url = record.link.lower().strip() if record.link else ""
                key_parts.append(f"url:{url}")
            
            if key_parts:
                key = "|".join(key_parts)
                
                if key not in duplicates_map:
                    duplicates_map[key] = []
                duplicates_map[key].append(record_info)
        
        except Exception as e:
            print(f"Warning: Error processing record {record_info.record_uid}: {str(e)}")
            continue
    
    duplicate_groups = {k: v for k, v in duplicates_map.items() if len(v) > 1}
    
    if duplicate_groups:
        print(f"\nFound {len(duplicate_groups)} duplicate group(s):")
        print("=" * 50)
        
        total_duplicates = 0
        for i, (key, records) in enumerate(duplicate_groups.items(), 1):
            total_duplicates += len(records)
            print(f"\nDuplicate Group {i} ({len(records)} records):")
            print("-" * 50)
            
            first_record = vault.vault_data.load_record(records[0].record_uid)
            print(f"Common attributes:")
            if match_title:
                print(f"  Title: {first_record.title}")
            if match_login and isinstance(first_record, vault_record.PasswordRecord):
                print(f"  Username: {first_record.login or '(empty)'}")
            if match_url and isinstance(first_record, vault_record.PasswordRecord):
                print(f"  URL: {first_record.link or '(empty)'}")
            
            print(f"\nDuplicate records:")
            for record_info in records:
                record = vault.vault_data.load_record(record_info.record_uid)
                print(f"  - {record.title}")
                print(f"    UID: {record_info.record_uid}")
                print(f"    Type: {record_info.record_type}")
                if isinstance(record, vault_record.PasswordRecord):
                    print(f"    Username: {record.login or '(empty)'}")
                    print(f"    URL: {record.link or '(empty)'}")
                print()
        
        print("=" * 50)
        print(f"\nSummary:")
        print(f"  Total duplicate groups: {len(duplicate_groups)}")
        print(f"  Total duplicate records: {total_duplicates}")
        print(f"  Potential records to remove: {total_duplicates - len(duplicate_groups)}")
        print("\nNote: Review duplicates carefully before deletion.")
        print("Use delete_record.py to remove unwanted duplicates.")
    else:
        print("\nNo duplicate records found!")
        print("Your vault is clean.")
    
    print("-" * 50)
    
    vault.close()
    keeper_auth_context.close()
