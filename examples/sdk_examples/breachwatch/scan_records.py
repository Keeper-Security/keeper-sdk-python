import getpass
import sqlite3

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
    
    if not vault.breach_watch_plugin():
        print("BreachWatch is not enabled for this account.")
        print("Please contact your administrator to enable BreachWatch.")
    else:
        breach_watch = vault.breach_watch_plugin().breach_watch
        
        if not breach_watch:
            print("Unable to initialize BreachWatch scanner.")
        else:
            record_search = input('Enter record title or UID to scan (or "all" for all records): ').strip()
            
            records_to_scan = []
            
            if record_search.lower() == 'all':
                for record_info in vault.vault_data.records():
                    if record_info.version in (2, 3):
                        records_to_scan.append(record_info)
            else:
                for record_info in vault.vault_data.records():
                    if (record_search.lower() in record_info.title.lower() or 
                        record_search == record_info.record_uid):
                        records_to_scan.append(record_info)
            
            if not records_to_scan:
                print(f"No records found matching: '{record_search}'")
            else:
                print(f"\nScanning {len(records_to_scan)} record(s) for breached passwords...")
                print("=" * 120)
                
                scan_results = []
                
                for record_info in records_to_scan:
                    record = vault.vault_data.load_record(record_info.record_uid)
                    
                    passwords = []
                    if isinstance(record, vault_record.PasswordRecord):
                        if record.password:
                            passwords.append(record.password)
                    elif isinstance(record, vault_record.TypedRecord):
                        for field in record.fields:
                            if field.field_type == 'password' and field.value:
                                pwd = field.value[0] if isinstance(field.value, list) else field.value
                                if pwd:
                                    passwords.append(pwd)
                    
                    if passwords:
                        for password in passwords:
                            for pwd, status in breach_watch.scan_passwords([password]):
                                is_breached = status and hasattr(status, 'breachDetected') and status.breachDetected
                                scan_results.append({
                                    'record_uid': record_info.record_uid,
                                    'title': record_info.title,
                                    'breached': is_breached,
                                    'status': status
                                })
                                break
                
                if scan_results:
                    print(f"{'Title':<40} {'Record UID':<40} {'Status':<20}")
                    print("-" * 120)
                    
                    for result in scan_results:
                        title = result['title'][:39] if result['title'] else '(Untitled)'
                        uid = result['record_uid'][:39]
                        status_text = "BREACHED" if result['breached'] else "SECURE"
                        
                        print(f"{title:<40} {uid:<40} {status_text:<20}")
                    
                    print("-" * 120)
                    breached_count = sum(1 for r in scan_results if r['breached'])
                    secure_count = len(scan_results) - breached_count
                    
                    print(f"\nSummary: {len(scan_results)} records scanned")
                    print(f"  - {breached_count} with breached passwords")
                    print(f"  - {secure_count} with secure passwords")
                    
                    if breached_count > 0:
                        print("\nRecommendation: Update breached passwords immediately to secure your accounts.")
                else:
                    print("\nNo passwords found in selected records.")
    
    vault.close()
    keeper_auth_context.close()

