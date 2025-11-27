import getpass
import sqlite3
import os

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, attachment

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

    print("Downloading attachments from record...")
    print("-" * 50)
    
    record_uid = input('Enter record UID (or leave empty to search): ').strip()
    
    if not record_uid:
        print('\nSearching for records with attachments...')
        for record_info in vault.vault_data.records():
            record = vault.vault_data.load_record(record_info.record_uid)
            has_attachments = False
            
            if hasattr(record, 'attachments') and record.attachments:
                has_attachments = True
            elif hasattr(record, 'file_ref') and record.file_ref:
                has_attachments = True
            
            if has_attachments:
                print(f'  - {record_info.title} ({record_info.record_uid})')
                record_uid = record_info.record_uid
                break
        
        if not record_uid:
            print('No records with attachments found')
    
    if record_uid:
        try:
            output_dir = input('Enter output directory (or leave empty for current dir): ').strip() or '.'
            
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                print(f'Created directory: {output_dir}')
            
            attachment_name = None
            
            attachments_to_download = list(attachment.prepare_attachment_download(
                vault, 
                record_uid, 
                attachment_name
            ))
            
            if attachments_to_download:
                print(f'\nFound {len(attachments_to_download)} attachment(s) to download')
                print("-" * 50)
                
                for atta in attachments_to_download:
                    file_name = atta.title
                    file_path = os.path.join(output_dir, file_name)
                    
                    if os.path.isfile(file_path):
                        base_name, ext = os.path.splitext(file_name)
                        file_path = os.path.join(output_dir, f'{base_name}_{atta.file_id}{ext}')
                    
                    print(f'Downloading: {file_name}')
                    atta.download_to_file(file_path)
                    print(f'Saved to: {file_path}')
                    print("-" * 50)
                
                print(f'\nSuccessfully downloaded {len(attachments_to_download)} attachment(s)!')
            else:
                print(f'No attachments found for record: {record_uid}')
                
        except Exception as e:
            print(f'Error downloading attachments: {str(e)}')
            import traceback
            traceback.print_exc()
    
    vault.close()
    keeper_auth_context.close()
