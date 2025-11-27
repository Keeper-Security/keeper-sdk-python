import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online

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
    
    print("\nBreachWatch Status")
    print("=" * 100)
    
    if not vault.breach_watch_plugin():
        print("Status: DISABLED")
        print("\nBreachWatch is not enabled for this account.")
        print("Contact your administrator to enable BreachWatch.")
    else:
        print("Status: ENABLED")
        
        breach_watch = vault.breach_watch_plugin().breach_watch
        if not breach_watch:
            print("Scanner: UNAVAILABLE")
            print("\nUnable to initialize BreachWatch scanner.")
        else:
            print("Scanner: READY")
        
        total_records = 0
        breached_records = 0
        secure_records = 0
        
        for record_info in vault.vault_data.records():
            if record_info.version not in (2, 3):
                continue
            
            total_records += 1
            
            bw_record = vault.vault_data.storage.breach_watch_records.get_entity(record_info.record_uid)
            if bw_record:
                breached_records += 1
            else:
                secure_records += 1
        
        print(f"\nVault Statistics:")
        print(f"  Total Records: {total_records}")
        print(f"  Breached Records: {breached_records}")
        print(f"  Secure Records: {secure_records}")
        
        if total_records > 0:
            breach_percentage = (breached_records / total_records) * 100
            print(f"  Breach Percentage: {breach_percentage:.1f}%")
            
            if breached_records > 0:
                print(f"\n⚠️  WARNING: {breached_records} record(s) with breached passwords detected!")
                print("   Run 'list_breaches.py' to see details and update affected passwords.")
            else:
                print("\n✓  All passwords are secure! No breaches detected.")
        else:
            print("\n  No records found in vault.")
    
    print("=" * 100)
    
    vault.close()
    keeper_auth_context.close()

