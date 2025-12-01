import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record
from keepersdk import utils
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
    vault.sync_down()
    
    record_search = input('Enter record title or UID to get TOTP code: ').strip()
    
    if not record_search:
        print("Record identifier cannot be empty")
    else:
        record_found = None
        
        for record_info in vault.vault_data.records():
            if (record_search.lower() in record_info.title.lower() or 
                record_search == record_info.record_uid):
                record_found = record_info
                break
        
        if not record_found:
            print(f"Record '{record_search}' not found")
        else:
            record = vault.vault_data.load_record(record_found.record_uid)
            
            totp_url = None
            
            if isinstance(record, vault_record.PasswordRecord):
                if hasattr(record, 'totp') and record.totp:
                    totp_url = record.totp
            elif isinstance(record, vault_record.TypedRecord):
                for field in record.fields:
                    if field.field_type == 'oneTimeCode' and field.value:
                        totp_url = field.value[0] if isinstance(field.value, list) else field.value
                        break
            
            if not totp_url:
                print(f"\nNo TOTP configured for record: {record_found.title}")
                print("This record does not have two-factor authentication set up.")
            else:
                try:
                    totp_code = utils.get_totp_code(totp_url)
                    
                    print(f"\nRecord: {record_found.title}")
                    print("=" * 60)
                    print(f"TOTP Code: {totp_code}")
                    print("=" * 60)
                    print("\nNote: TOTP codes expire every 30 seconds.")
                    print("Enter this code in your authentication prompt.")
                    
                except Exception as e:
                    print(f"Error generating TOTP code: {e}")
    
    vault.close()
    keeper_auth_context.close()

