import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record
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

    print("Get Record Details")
    print("-" * 50)
    
    search_input = input('Enter record UID or title: ').strip()
    
    if not search_input:
        print('No input provided. Showing first record as example...')
        for record_info in vault.vault_data.records():
            search_input = record_info.record_uid
            break
    
    if search_input:
        try:
            record_info = vault.vault_data.get_record(search_input)
            
            if not record_info:
                for rec_info in vault.vault_data.records():
                    if rec_info.title.lower() == search_input.lower():
                        record_info = rec_info
                        break
            
            if record_info:
                record = vault.vault_data.load_record(record_info.record_uid)
                
                print("\n" + "=" * 50)
                print(f"Record Details: {record_info.title}")
                print("=" * 50)
                print(f'Record UID: {record_info.record_uid}')
                print(f'Record Type: {record_info.record_type}')
                print(f'Record Version: {record_info.version}')
                print("-" * 50)
                
                if isinstance(record, vault_record.PasswordRecord):
                    print('Type: Password Record (Legacy)')
                    print(f'Title: {record.title}')
                    print(f'Username: {record.login or "(empty)"}')
                    print(f'Password: {"*" * len(record.password) if record.password else "(empty)"}')
                    print(f'URL: {record.link or "(empty)"}')
                    
                    if record.notes:
                        notes_preview = record.notes[:100] + '...' if len(record.notes) > 100 else record.notes
                        print(f'Notes: {notes_preview}')
                    else:
                        print('Notes: (empty)')
                    
                    if record.custom:
                        print('\nCustom Fields:')
                        for custom_field in record.custom:
                            print(f'  - {custom_field.name}: {custom_field.value}')
                    
                    if record.attachments:
                        print('\nAttachments:')
                        for atta in record.attachments:
                            print(f'  - {atta.title or atta.name} ({atta.size} bytes)')
                    
                elif isinstance(record, vault_record.TypedRecord):
                    print('Type: Typed Record (Modern)')
                    print(f'Title: {record.title}')
                    print(f'Record Type: {record.record_type}')
                    
                    if record.notes:
                        notes_preview = record.notes[:100] + '...' if len(record.notes) > 100 else record.notes
                        print(f'Notes: {notes_preview}')
                    else:
                        print('Notes: (empty)')
                    
                    if record.fields:
                        print('\nFields:')
                        for field in record.fields:
                            field_type = field.type if hasattr(field, 'type') else 'unknown'
                            field_label = field.label if hasattr(field, 'label') else ''
                            field_value = field.value if hasattr(field, 'value') else ''
                            
                            if isinstance(field_value, list):
                                if field_value:
                                    field_value = ', '.join(str(v) for v in field_value)
                                else:
                                    field_value = '(empty)'
                            
                            if field_type in ['password', 'secret']:
                                field_value = '*' * 10 if field_value else '(empty)'
                            
                            label_text = f' ({field_label})' if field_label else ''
                            print(f'  - {field_type}{label_text}: {field_value}')
                    
                    if record.custom:
                        print('\nCustom Fields:')
                        for custom_field in record.custom:
                            field_type = custom_field.type if hasattr(custom_field, 'type') else 'unknown'
                            field_label = custom_field.label if hasattr(custom_field, 'label') else ''
                            field_value = custom_field.value if hasattr(custom_field, 'value') else ''
                            
                            if isinstance(field_value, list):
                                if field_value:
                                    field_value = ', '.join(str(v) for v in field_value)
                                else:
                                    field_value = '(empty)'
                            
                            label_text = f' ({field_label})' if field_label else ''
                            print(f'  - {field_type}{label_text}: {field_value}')
                    
                    from keepersdk.vault.record_facades import FileRefRecordFacade
                    facade = FileRefRecordFacade()
                    facade.record = record
                    if isinstance(facade.file_ref, list) and facade.file_ref:
                        print('\nFile References:')
                        for file_uid in facade.file_ref:
                            file_record = vault.vault_data.load_record(file_uid)
                            if isinstance(file_record, vault_record.FileRecord):
                                print(f'  - {file_record.title} (UID: {file_uid})')
                
                else:
                    print(f'Record Type: {type(record).__name__}')
                    print(f'Title: {record.title if hasattr(record, "title") else "N/A"}')
                
                print("=" * 50)
                
            else:
                print(f'Record not found: "{search_input}"')
                print('\nAvailable records:')
                for i, rec_info in enumerate(vault.vault_data.records(), 1):
                    if i > 10:
                        print(f'... and more')
                        break
                    print(f'  - {rec_info.title} ({rec_info.record_uid})')
                
        except Exception as e:
            print(f'Error getting record details: {str(e)}')
            import traceback
            traceback.print_exc()
    else:
        print('No records found in vault')
    
    vault.close()
    keeper_auth_context.close()
