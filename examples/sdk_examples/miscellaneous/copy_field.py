import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record
from keepersdk import utils

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
    
    record_search = input('Enter record title or UID: ').strip()
    
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
            
            print(f"\nRecord: {record_found.title}")
            print("=" * 80)
            
            print("\nWhat would you like to copy?")
            print("1. Password")
            print("2. Login/Username")
            print("3. URL")
            print("4. TOTP Code")
            print("5. Record UID")
            
            choice = input("\nEnter choice (1-5): ").strip()
            
            output_value = None
            output_label = None
            
            if choice == '1':
                if isinstance(record, vault_record.PasswordRecord):
                    output_value = record.password
                    output_label = "Password"
                elif isinstance(record, vault_record.TypedRecord):
                    for field in record.fields:
                        if field.field_type == 'password' and field.value:
                            output_value = field.value[0] if isinstance(field.value, list) else field.value
                            output_label = "Password"
                            break
            
            elif choice == '2':
                if isinstance(record, vault_record.PasswordRecord):
                    output_value = record.login
                    output_label = "Login"
                elif isinstance(record, vault_record.TypedRecord):
                    for field in record.fields:
                        if field.field_type == 'login' and field.value:
                            output_value = field.value[0] if isinstance(field.value, list) else field.value
                            output_label = "Login"
                            break
            
            elif choice == '3':
                if isinstance(record, vault_record.PasswordRecord):
                    output_value = record.link
                    output_label = "URL"
                elif isinstance(record, vault_record.TypedRecord):
                    for field in record.fields:
                        if field.field_type == 'url' and field.value:
                            output_value = field.value[0] if isinstance(field.value, list) else field.value
                            output_label = "URL"
                            break
            
            elif choice == '4':
                totp_url = None
                if isinstance(record, vault_record.PasswordRecord):
                    if hasattr(record, 'totp') and record.totp:
                        totp_url = record.totp
                elif isinstance(record, vault_record.TypedRecord):
                    for field in record.fields:
                        if field.field_type == 'oneTimeCode' and field.value:
                            totp_url = field.value[0] if isinstance(field.value, list) else field.value
                            break
                
                if totp_url:
                    try:
                        output_value = utils.get_totp_code(totp_url)
                        output_label = "TOTP Code"
                    except Exception as e:
                        print(f"Error generating TOTP: {e}")
                else:
                    print("No TOTP configured for this record")
            
            elif choice == '5':
                output_value = record_found.record_uid
                output_label = "Record UID"
            
            else:
                print("Invalid choice")
            
            if output_value and output_label:
                print(f"\n{output_label}:")
                print("=" * 80)
                print(output_value)
                print("=" * 80)
                print(f"\n✓ {output_label} displayed above")
                print("Note: Copy the value manually or use pyperclip library for clipboard integration")
            elif choice in ['1', '2', '3', '4']:
                print(f"\n{output_label if output_label else 'Field'} not found in this record")
    
    vault.close()
    keeper_auth_context.close()

