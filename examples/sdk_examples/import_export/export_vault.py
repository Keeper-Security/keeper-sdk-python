import getpass
import sqlite3
import json

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
    
    output_file = input('Enter output filename (default: vault_export.json): ').strip() or 'vault_export.json'
    
    try:
        export_data = {
            'records': [],
            'folders': [],
            'metadata': {
                'version': '1.0',
                'export_type': 'keeper_sdk',
                'record_count': 0,
                'folder_count': 0
            }
        }
        
        print("\nExporting vault data...")
        
        for record_info in vault.vault_data.records():
            if record_info.version not in (2, 3):
                continue
            
            record = vault.vault_data.load_record(record_info.record_uid)
            
            record_data = {
                'uid': record_info.record_uid,
                'title': record_info.title,
                'type': record_info.record_type if hasattr(record_info, 'record_type') else 'login',
                'version': record_info.version
            }
            
            if isinstance(record, vault_record.PasswordRecord):
                record_data['fields'] = {
                    'login': record.login,
                    'password': record.password,
                    'url': record.link,
                    'notes': record.notes
                }
                record_data['custom_fields'] = record.custom
            elif isinstance(record, vault_record.TypedRecord):
                record_data['fields'] = []
                for field in record.fields:
                    record_data['fields'].append({
                        'type': field.field_type,
                        'label': field.label if hasattr(field, 'label') else '',
                        'value': field.value
                    })
            
            export_data['records'].append(record_data)
        
        for folder in vault.vault_data.folders():
            folder_data = {
                'uid': folder.folder_uid,
                'name': folder.name,
                'type': folder.folder_type,
                'parent_uid': folder.parent_uid
            }
            export_data['folders'].append(folder_data)
        
        export_data['metadata']['record_count'] = len(export_data['records'])
        export_data['metadata']['folder_count'] = len(export_data['folders'])
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n✓ Export completed successfully!")
        print(f"Output file: {output_file}")
        print(f"Records exported: {export_data['metadata']['record_count']}")
        print(f"Folders exported: {export_data['metadata']['folder_count']}")
        print(f"\nNote: Passwords are included in the export. Keep this file secure!")
        
    except Exception as e:
        print(f"Error exporting vault data: {e}")
    
    vault.close()
    keeper_auth_context.close()

