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
        breached_records = []
        
        for record_info in vault.vault_data.records():
            if record_info.version not in (2, 3):
                continue
            
            bw_record = vault.vault_data.storage.breach_watch_records.get_entity(record_info.record_uid)
            if bw_record:
                record = vault.vault_data.load_record(record_info.record_uid)
                
                password = None
                if isinstance(record, vault_record.PasswordRecord):
                    password = record.password
                elif isinstance(record, vault_record.TypedRecord):
                    for field in record.fields:
                        if field.field_type == 'password' and field.value:
                            password = field.value[0] if isinstance(field.value, list) else field.value
                            break
                
                if password:
                    breached_records.append({
                        'uid': record_info.record_uid,
                        'title': record_info.title,
                        'record': record
                    })
        
        if not breached_records:
            print("\nNo breached passwords found in your vault!")
            print("Your passwords are secure.")
        else:
            print("\nBreached Passwords Detected")
            print("=" * 100)
            print(f"Found {len(breached_records)} record(s) with breached passwords")
            print("=" * 100)
            print(f"{'#':<5} {'Title':<40} {'Record UID':<40}")
            print("-" * 100)
            
            for idx, br in enumerate(breached_records, 1):
                title = br['title'][:39] if br['title'] else '(Untitled)'
                uid = br['uid']
                print(f"{idx:<5} {title:<40} {uid:<40}")
            
            print("-" * 100)
            print(f"\nTotal breached records: {len(breached_records)}")
            print("\nRecommendation: Update these passwords immediately to secure your accounts.")
    
    vault.close()
    keeper_auth_context.close()

